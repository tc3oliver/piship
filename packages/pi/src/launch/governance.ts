import { type InlineExtension, VERSION } from "@earendil-works/pi-coding-agent";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  PiShipError,
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
import type { ModelEvidence } from "@piship/policy";
import { resolveTemplate } from "@piship/schema";
import {
  askUserExtension,
  governanceHooks,
  workflowExtension,
} from "../builtins.js";
import type { ModelPolicy } from "../governance.js";
import {
  type GovernanceOptions,
  GovernanceSession,
} from "../governance-session.js";
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

/** PiShip's inline extensions for a governed session. */
export function governanceExtensions(
  gov: GovernanceSession,
): InlineExtension[] {
  const extensions = [governanceHooks(gov)];
  if (gov.loader.builtin.has("piship-ask-user"))
    extensions.push(askUserExtension(gov));
  const workflow = gov.manifest.capabilities.find(
    (item) => item.name === "workflow",
  );
  if (
    workflow &&
    gov.loader.builtin.has("piship-workflow") &&
    gov.effective("workflow") &&
    (workflow.provider?.id ?? "builtin/workflow") === "builtin/workflow"
  )
    extensions.push(workflowExtension(gov, workflow.settings));
  return extensions;
}

/**
 * model.use from the distribution policy. `ask` is resolved before the
 * session starts for the model it starts with; other models that need
 * approval are not offered for switching mid-session.
 */
export async function modelPolicy(
  gov: GovernanceSession,
  selected: string | undefined,
): Promise<ModelPolicy> {
  const approved = new Set<string>();
  if (selected) {
    const decision = await gov.decide(
      "model.use",
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
  }
  return {
    allows: (provider, id) => {
      const key = `${provider}/${id}`;
      const effect = gov.engine.evaluate({
        action: "model.use",
        resource: key,
      }).effect;
      return effect === "allow" || (effect === "ask" && approved.has(key));
    },
    denied: (provider, id) =>
      gov.emit("model.denied", { resource: `${provider}/${id}` }),
    available: () => gov.assertAuditAvailable(),
  };
}
