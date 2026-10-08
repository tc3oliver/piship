import {
  type InlineExtension,
  type ToolDefinition,
  VERSION,
} from "@earendil-works/pi-coding-agent";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
  PiShipError,
  plainHttpOrigins,
  type PolicyAction,
  principalId,
  principalKey,
  samePrincipal,
} from "@piship/contracts";
import {
  configuredModel,
  describeYolo,
  eventDetail,
  type GovernedLock,
  governedLock,
  openSandboxCredential,
} from "@piship/core";
import { BUILTIN_DEFAULT_RULE, type ModelEvidence } from "@piship/policy";
import { resolveTemplate } from "@piship/schema";
import {
  askUserTool,
  governanceHooks,
  workflowExtension,
} from "../builtins.js";
import type { ModelPolicy, VirtualModelRule } from "../governance.js";
import {
  type GovernanceOptions,
  GovernanceSession,
} from "../governance-session.js";
import type { ToolExposureTable } from "../governance/exposure.js";
import { governedTools } from "../governed-tools.js";
import type { LaunchContext, PreparedAccess } from "./context.js";

/**
 * The MCP plain-HTTP fetch: it admits plain HTTP only to the origins of the
 * resolved urls of servers not set to `httpTransport: https` that are on a
 * private or internal host. A url that does not resolve admits nothing; the
 * server then fails to start on its own.
 */
function mcpPlainHttp(
  ctx: LaunchContext,
  servers: GovernedLock["governance"]["manifest"]["mcp"]["servers"],
  network: NetworkPolicy,
): Pick<GovernanceOptions, "mcpPlainHttpFetch"> {
  const urls = servers
    .filter(
      (server) =>
        server.httpTransport !== "https" && server.credential !== "runtime",
    )
    .map((server) => {
      try {
        return resolveTemplate(
          `mcp.servers.${server.id}.url`,
          server.url ?? "",
          ctx.metadata.access?.variables ?? [],
          process.env,
        );
      } catch {
        return undefined;
      }
    });
  const plainHttp = plainHttpOrigins(urls);
  return plainHttp
    ? {
        mcpPlainHttpFetch: createManagedFetch(network, "governance", {
          plainHttp,
        }),
      }
    : {};
}

export function governanceOptions(
  ctx: LaunchContext,
  lock: GovernedLock,
  prepared: PreparedAccess | null,
  interactive: boolean,
): GovernanceOptions {
  const { access, activated, metrics } = prepared ?? {};
  const sandbox = lock.governance.manifest.sandbox;
  // The principal the sandbox credential is checked against: the one this
  // launch activated, or nobody for a distribution without access. Without
  // either (an offline report), no sandbox credential is offered.
  const principal = activated?.identity
    ? principalKey(activated.identity)
    : null;
  const known = !ctx.metadata.access || !!activated;
  const onSandboxCredentialEvent = prepared?.events.listener;
  const servers = lock.governance.manifest.mcp.servers;
  const network = access?.network ?? DEFAULT_NETWORK_POLICY;
  return {
    lock,
    ...(metrics ? { metrics } : {}),
    distributionDir: ctx.distributionDir,
    stateDir: ctx.stateDir,
    cwd: process.cwd(),
    piVersion: VERSION,
    interactive,
    ...(ctx.yolo ? { yolo: true } : {}),
    ...(ctx.subagent ? { subagent: true } : {}),
    ...(ctx.endProviderAutoApprove
      ? { onYoloEnd: ctx.endProviderAutoApprove }
      : {}),
    fetch: createManagedFetch(network, "governance"),
    plainHttpFetch: (plainHttp) =>
      createManagedFetch(network, "governance", { plainHttp }),
    // Plain HTTP beyond loopback only for MCP servers not set to
    // httpTransport: https and without the runtime credential, to the
    // origins of their resolved urls on a private or internal host, and only
    // on this fetch. Each server's
    // transport requests only its own url. Private-only network policy
    // still applies.
    ...mcpPlainHttp(ctx, servers, network),
    // MCP identity headers: the claims of the identity this launch
    // activated, held in memory. Each request only checks, without the
    // secret store or the identity provider, that the identity metadata
    // still names the launch's principal: after a logout or a user switch
    // the header is not sent, and the next launch uses the new user's claims.
    ...(access &&
    principal &&
    activated?.identity &&
    servers.some((server) => server.headers !== undefined)
      ? {
          identityClaims: async () => {
            const stored = access.readIdentityMetadata();
            if (!stored)
              throw new PiShipError(
                "IDENTITY_REQUIRED",
                "You signed out since launch",
                { component: "identity" },
              );
            if (!samePrincipal(principalKey(stored), principal))
              throw new PiShipError(
                "IDENTITY_REQUIRED",
                "Another identity signed in since launch",
                { component: "identity" },
              );
            return activated.identity?.claims ?? {};
          },
        }
      : {}),
    resolveTemplate: (key, template) =>
      resolveTemplate(
        key,
        template,
        ctx.metadata.access?.variables ?? [],
        process.env,
      ),
    user: activated?.identity
      ? principalId(principalKey(activated.identity))
      : null,
    model: selectedModelEvidence(ctx, prepared),
    ...(onSandboxCredentialEvent ? { onSandboxCredentialEvent } : {}),
    ...(known && sandbox.credential === "stored" && sandbox.provider
      ? {
          sandboxCredential: async (targets: readonly string[]) => {
            const signedIn = await access?.signedInGuard(principal);
            return openSandboxCredential({
              distributionId: lock.app.id,
              command: lock.app.command,
              stateDir: ctx.stateDir,
              provider: sandbox.provider as NonNullable<
                typeof sandbox.provider
              >,
              ...(ctx.metadata.access
                ? { storage: ctx.metadata.access.credential.storage }
                : {}),
              ...(access?.store ? { secretStore: access.store } : {}),
              principal,
              ...(signedIn ? { signedIn } : {}),
              targets,
              ...(onSandboxCredentialEvent
                ? { onEvent: onSandboxCredentialEvent }
                : {}),
            }).access();
          },
        }
      : {}),
    ...(known
      ? {
          sandboxIdentity: {
            principal,
            // A renewed session of the same principal, never another's.
            current: async () =>
              access && principal
                ? access.currentIdentity({ required: true })
                : null,
          },
        }
      : {}),
    ...(access && activated?.runtime.requiresCredential
      ? {
          credential: async () =>
            (await access.requestSecret({ force: false }))?.reveal(),
          // The runtime credential is issued for the inference gateway only.
          credentialOrigins: activated.runtime.baseUrl
            ? [activated.runtime.baseUrl]
            : [],
        }
      : {}),
  };
}

/**
 * The model capability requirements are checked against: the one launch
 * selected, or, for offline reports, the one it would select.
 */
function selectedModelEvidence(
  ctx: LaunchContext,
  prepared: PreparedAccess | null,
): ModelEvidence {
  const activated = prepared?.activated;
  if (!activated)
    try {
      return configuredModel({
        app: ctx.metadata.app,
        access: ctx.metadata.access,
        stateDir: ctx.stateDir,
      });
    } catch (error) {
      // Unreadable user preferences: this read leaves them in place (launch
      // moves them aside). The report then knows no model and says why
      // instead of failing.
      if (!(error instanceof PiShipError) || error.code !== "CONFIG_INVALID")
        throw error;
      return { id: `(unknown: ${error.message})` };
    }
  const selected = activated.selectedModel;
  const metadata = selected
    ? activated.models.find((model) => model.id === selected)
    : undefined;
  return {
    id:
      selected === undefined
        ? "(selected by Pi)"
        : activated.runtime.kind === "pi-native"
          ? selected
          : `${ctx.metadata.app.id}/${selected}`,
    ...(metadata ? { metadata } : {}),
  };
}

export async function openGovernance(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  interactive: boolean,
): Promise<GovernanceSession | null> {
  const lock = governedLock(ctx);
  if (!lock) return null;
  const gov = await GovernanceSession.open(
    governanceOptions(ctx, lock, prepared, interactive),
  );
  // Before Pi's screen opens, and in a headless run where nothing else shows it.
  if (gov.yolo) ctx.err(`Notice: ${describeYolo(ctx.mode)}`);
  const { access } = prepared;
  // Only lifecycle changes are recorded: reusing a stored credential is not
  // an acquisition. Later refreshes during the session are forwarded live.
  // Sandbox credential events name their purpose instead of the mode.
  prepared.events.forward((event) =>
    gov.emit(event.event, {
      detail: eventDetail(access?.credentialMode ?? "pi-native", event.detail),
    }),
  );
  return gov;
}

/** The settings of the built-in workflow when this session runs it. */
export function activeWorkflow(
  gov: GovernanceSession,
): Readonly<Record<string, string>> | undefined {
  const workflow = gov.manifest.capabilities.find(
    (item) => item.name === "workflow",
  );
  return workflow &&
    gov.loader.builtin.has("piship-workflow") &&
    gov.effective("workflow") &&
    (workflow.provider?.id ?? "builtin/workflow") === "builtin/workflow"
    ? workflow.settings
    : undefined;
}

/**
 * PiShip's inline extensions for a governed session. `ask_user` is an SDK
 * custom tool (`governedCustomTools`), not an extension tool, so a file
 * extension of the same name cannot shadow it.
 */
export function governanceExtensions(
  gov: GovernanceSession,
): InlineExtension[] {
  const extensions = [governanceHooks(gov)];
  const workflow = activeWorkflow(gov);
  if (workflow) extensions.push(workflowExtension(gov, workflow));
  return extensions;
}

/** Governed built-in tools plus `ask_user` when the builtin is loaded. */
export function governedCustomTools(
  gov: GovernanceSession,
  cwd: string,
  table: ToolExposureTable | null = gov.exposure,
): ToolDefinition[] {
  return [
    ...governedTools(gov, cwd, table),
    ...(gov.loader.builtin.has("piship-ask-user") &&
    table?.get("ask_user") !== "hidden"
      ? [
          {
            ...askUserTool(gov),
            exposure: table?.get("ask_user") ?? "direct",
          } as ToolDefinition,
        ]
      : []),
  ];
}

/**
 * model.select and model.dispatch from the distribution policy. `ask` is
 * resolved before the session starts for the model it starts with and, when
 * that model is virtual, for each of its declared routes; other models that
 * need approval are not offered for switching or routing mid-session.
 *
 * Deny wins: a dispatch also needs model.select unless a rule that names
 * model.dispatch itself decides it (the router-only case), from a layer at
 * least as authoritative as every model.select deny or ask that matches.
 * Without such a rule (none matched, the deciding rule is a `*` or `model.*`
 * wildcard, or a stricter layer restricts selection: an enforced, team,
 * project, or user rule over a default or user allow) model.select decides
 * (§18.3), so neither a v0.8 `model.use` deny nor a model.select deny can be
 * routed around.
 */
export async function modelPolicy(
  gov: GovernanceSession,
  selected: string | undefined,
  virtual: readonly VirtualModelRule[] = [],
): Promise<ModelPolicy> {
  const approved = new Set<string>();
  const approvedDispatch = new Set<string>();
  /** model.select asks approved at start only so that a route may dispatch. */
  const approvedRoute = new Set<string>();
  /**
   * The model.dispatch decision, the model.select one, and whether a rule
   * naming model.dispatch decides dispatch on its own: a rule that also
   * matches model.select names a wildcard, and a model.select deny or ask
   * from a more authoritative layer still applies.
   */
  const dispatchDecision = (key: string) => {
    const decision = gov.engine.evaluate({
      action: "model.dispatch",
      resource: key,
    });
    const select = gov.engine.explain({
      action: "model.select",
      resource: key,
    });
    const named =
      decision.ruleId !== BUILTIN_DEFAULT_RULE &&
      !select.matches.some(
        (match) =>
          match.layer === decision.layer && match.ruleId === decision.ruleId,
      ) &&
      select.matches.every(
        (match) =>
          !match.first ||
          match.effect === "allow" ||
          (decision.layer === "distribution-enforced" ? 3 : 1) >=
            authority(match.layer),
      );
    return { decision, select: select.decision, named };
  };
  const startup = async (action: PolicyAction, key: string) =>
    (
      await gov.decide(action, key, gov.startupChannel(), {
        denied: "model.denied",
      })
    ).outcome === "allow";
  if (selected) {
    const decision = await gov.decide(
      "model.select",
      selected,
      gov.startupChannel(),
      { denied: "model.denied" },
    );
    if (decision.outcome !== "allow")
      throw new PiShipError(
        "MODEL_DENIED",
        `Model ${selected} is not allowed by ${decision.policyId} rule ${decision.ruleId}`,
        { component: "policy" },
      );
    approved.add(selected);
    const rule = virtual.find((item) => key(item) === selected);
    const targets = rule ? rule.routes.map(key) : [selected];
    for (const target of targets) {
      const { decision: dispatch, select, named } = dispatchDecision(target);
      if (dispatch.ruleId !== BUILTIN_DEFAULT_RULE) {
        if (dispatch.effect === "deny") continue;
        if (dispatch.effect === "ask") {
          if (!(await startup("model.dispatch", target))) continue;
          approvedDispatch.add(target);
          // One wildcard ask decides both: its approval is asked once.
          if (
            select.effect === "ask" &&
            select.layer === dispatch.layer &&
            select.ruleId === dispatch.ruleId
          ) {
            approvedRoute.add(target);
            continue;
          }
        }
        if (named) continue;
      }
      if (
        !approved.has(target) &&
        gov.engine.evaluate({ action: "model.select", resource: target })
          .effect === "ask" &&
        (await startup("model.select", target))
      )
        approvedRoute.add(target);
    }
    // A virtual model needs one route it may dispatch to.
    if (!targets.some((target) => dispatches(target)))
      throw new PiShipError(
        "MODEL_DENIED",
        rule
          ? `No route of virtual model ${selected} (${targets.join(", ")}) may receive a request`
          : `Model ${selected} may not receive a request (model.dispatch)`,
        { component: "policy" },
      );
  }
  function selectEffect(key: string, routes: boolean): boolean {
    const effect = gov.engine.evaluate({
      action: "model.select",
      resource: key,
    }).effect;
    return (
      effect === "allow" ||
      (effect === "ask" &&
        (approved.has(key) || (routes && approvedRoute.has(key))))
    );
  }
  function selects(key: string): boolean {
    return selectEffect(key, false);
  }
  function dispatches(key: string): boolean {
    const { decision, named } = dispatchDecision(key);
    if (decision.ruleId === BUILTIN_DEFAULT_RULE)
      return selectEffect(key, true);
    const allowed =
      decision.effect === "allow" ||
      (decision.effect === "ask" && approvedDispatch.has(key));
    return allowed && (named || selectEffect(key, true));
  }
  return {
    selects: (provider, id) => selects(`${provider}/${id}`),
    dispatches: (provider, id) => dispatches(`${provider}/${id}`),
    denied: (action, provider, id, detail) =>
      gov.emit("model.denied", {
        resource: `${provider}/${id}`,
        decision: "denied",
        enforcement: "control-plane",
        detail: { action, ...detail },
      }),
    dispatched: (dispatch) =>
      gov.emit("model.dispatch", {
        resource: dispatch.dispatched,
        decision: "allowed",
        enforcement: "control-plane",
        detail: { ...dispatch },
      }),
    available: () => {
      gov.assertAuditAvailable();
      gov.assertRuntimeIntact();
    },
  };
}

/**
 * How authoritative a model.select deny or ask is against a model.dispatch
 * allow: an enforced one yields to an enforced allow only, a narrowing one
 * (team, project, a user's own restriction) too, since no allow comes from
 * those layers; a default one also to a default or user allow.
 */
function authority(layer: string): number {
  if (layer === "distribution-enforced") return 3;
  if (layer === "team-project" || layer === "user-preference") return 2;
  return 1;
}

const key = (model: { provider: string; id: string }) =>
  `${model.provider}/${model.id}`;
