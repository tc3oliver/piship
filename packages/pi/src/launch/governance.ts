import {
  type InlineExtension,
  type ToolDefinition,
  VERSION,
} from "@earendil-works/pi-coding-agent";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  PiShipError,
  type PolicyAction,
  principalId,
  principalKey,
} from "@piship/contracts";
import {
  configuredModel,
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
  return {
    lock,
    ...(metrics ? { metrics } : {}),
    distributionDir: ctx.distributionDir,
    stateDir: ctx.stateDir,
    cwd: process.cwd(),
    piVersion: VERSION,
    interactive,
    fetch: createManagedFetch(
      access?.network ?? DEFAULT_NETWORK_POLICY,
      "governance",
    ),
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
      // Unreadable user preferences: launch refuses them too. The report then
      // knows no model and says why instead of failing.
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
 * Without a model.dispatch rule for a physical model, model.select decides
 * it (§18.3), so a v0.8 `model.use` deny cannot be routed around.
 */
export async function modelPolicy(
  gov: GovernanceSession,
  selected: string | undefined,
  virtual: readonly VirtualModelRule[] = [],
): Promise<ModelPolicy> {
  const approved = new Set<string>();
  const approvedDispatch = new Set<string>();
  /** The rule that decides a dispatch: model.dispatch, else model.select. */
  const dispatchAction = (key: string): PolicyAction =>
    gov.engine.evaluate({ action: "model.dispatch", resource: key }).ruleId ===
    BUILTIN_DEFAULT_RULE
      ? "model.select"
      : "model.dispatch";
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
      const action = dispatchAction(target);
      if (action === "model.select" && approved.has(target)) {
        approvedDispatch.add(target);
        continue;
      }
      if (
        gov.engine.evaluate({ action, resource: target }).effect === "ask" &&
        (await startup(action, target))
      )
        approvedDispatch.add(target);
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
  function selects(key: string): boolean {
    const effect = gov.engine.evaluate({
      action: "model.select",
      resource: key,
    }).effect;
    return effect === "allow" || (effect === "ask" && approved.has(key));
  }
  function dispatches(key: string): boolean {
    const action = dispatchAction(key);
    const effect = gov.engine.evaluate({ action, resource: key }).effect;
    return (
      effect === "allow" ||
      (effect === "ask" &&
        (approvedDispatch.has(key) ||
          (action === "model.select" && approved.has(key))))
    );
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

const key = (model: { provider: string; id: string }) =>
  `${model.provider}/${model.id}`;
