import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  createAgentSession,
  createAgentSessionRuntime,
  DefaultResourceLoader,
  type SessionManager,
  SettingsManager,
  type AgentSessionServices,
  type CreateAgentSessionRuntimeFactory,
  type InlineExtension,
} from "@earendil-works/pi-coding-agent";
import {
  ENTERPRISE_CONTEXT_SYMBOL,
  type EnterpriseContext,
  formatError,
  PiShipError,
  startupMark,
} from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import {
  type GovernedRuntime,
  isCredentialRejection,
  isModelDenial,
} from "../governance.js";
import {
  activateExposure,
  buildExposureTable,
  exposureConfigOf,
  exposureFactories,
  extensionToolsOf,
} from "../governance/exposure.js";
import type { GovernanceSession } from "../governance-session.js";
import { saveMetrics } from "../launch-metrics.js";
import type { LaunchContext, PreparedAccess } from "./context.js";
import {
  activeWorkflow,
  governanceExtensions,
  governedCustomTools,
  modelPolicy,
} from "./governance.js";
import { piSettings } from "./pi-defaults.js";
import { sessionProjectTrust } from "./project-trust.js";
import {
  createModelRuntime,
  launchVirtualModels,
  type Model,
} from "./model-runtime.js";
import { providerErrorRedaction } from "./redaction.js";
import { governVirtualModels } from "./virtual-models.js";
import {
  cacheWarmingSetting,
  enforcedRuntime,
  governCacheWarming,
  inlineExtensionOrder,
  runtimeIntegrityExtension,
} from "./runtime-integrity.js";
import {
  openSession,
  resumeRefusal,
  type SessionOwnership,
} from "./session-file.js";

function verifyBuiltResources(ctx: LaunchContext): void {
  const resourceDir = join(ctx.distributionDir, "resources");
  for (const resource of ctx.metadata.resources) {
    if (
      resource.path.startsWith("/") ||
      resource.path.split("/").includes("..")
    )
      throw new Error("Unsafe built resource path");
    const path = join(resourceDir, resource.path);
    if (!lstatSync(path).isFile())
      throw new Error(`Built resource is not a regular file: ${resource.path}`);
    const digest = createHash("sha256")
      .update(readFileSync(path))
      .digest("hex");
    if (digest !== resource.sha256)
      throw new Error(`Built resource integrity mismatch: ${resource.path}`);
  }
}

function resourcePaths(
  ctx: LaunchContext,
  kind: keyof DistributionLock["declared"],
): string[] {
  const resourceDir = join(ctx.distributionDir, "resources");
  return ctx.metadata.declared[kind].map((path) => {
    const segments = path.slice(2).split("/");
    if (
      !path.startsWith("./") ||
      segments.some(
        (segment) => !segment || segment === "." || segment === "..",
      )
    )
      throw new Error(`Unsafe built resource declaration: ${path}`);
    return join(resourceDir, ...segments);
  });
}

export function publishContext(context: EnterpriseContext | null): void {
  const holder = globalThis as unknown as Record<symbol, unknown>;
  if (context) holder[ENTERPRISE_CONTEXT_SYMBOL] = context;
  else delete holder[ENTERPRISE_CONTEXT_SYMBOL];
}

/**
 * Keeps the owner record on the session file the runtime writes, and refuses
 * a `/resume` of a session another live process owns.
 */
function sessionOwnerExtension(
  ownership: SessionOwnership,
  command: string,
): InlineExtension {
  return {
    name: "piship-session-owner",
    factory: (pi) => {
      pi.on("session_before_switch", (event, extension) => {
        if (event.reason !== "resume" || !event.targetSessionFile)
          return undefined;
        const refusal = resumeRefusal(
          ownership,
          event.targetSessionFile,
          command,
        );
        if (!refusal) return undefined;
        extension.ui.notify(refusal, "warning");
        return { cancel: true };
      });
    },
  };
}

export interface SessionOptions {
  readonly sessionDir: string;
  /** Start a new session instead of resuming the most recent one. */
  readonly newSession: boolean;
  /** A session that holds no user work: a damaged one is replaced, not refused. */
  readonly disposable?: boolean;
}

async function startRuntime(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  sessionManager: SessionManager,
  gov: GovernanceSession | null,
  ownership: SessionOwnership,
) {
  verifyBuiltResources(ctx);
  startupMark("resources_verified");
  const instructions = gov
    ? gov.loader.instructions
    : resourcePaths(ctx, "instructions").map((path) => ({
        path,
        content: readFileSync(path, "utf8"),
      }));
  const { activated, access } = prepared;
  const selectedKey =
    activated?.selectedModel && activated.runtime.kind === "managed-endpoint"
      ? `${activated.runtime.providerId}/${activated.selectedModel}`
      : activated?.selectedModel;
  const virtual = launchVirtualModels(ctx, prepared);
  const policy = gov ? await modelPolicy(gov, selectedKey, virtual) : undefined;
  const builtinExtensions = gov ? governanceExtensions(gov) : [];
  const exposureConfig = gov ? exposureConfigOf(gov) : null;
  const exposureExtensionFactories =
    gov && exposureConfig ? exposureFactories(gov, exposureConfig) : [];
  const integrity = gov
    ? runtimeIntegrityExtension(gov, enforcedRuntime(gov, activeWorkflow(gov)))
    : null;
  const cacheWarming = cacheWarmingSetting(gov);
  const theme = activated?.config.values.theme ?? ctx.metadata.app.theme;
  const thinkingLevel = activated?.config.values.thinkingLevel;
  const context =
    activated && access ? access.enterpriseContext(activated) : null;
  publishContext(context);
  let governedRef: GovernedRuntime | null = null;
  const governanceExtension: InlineExtension = {
    name: "piship-governance",
    factory: (pi) => {
      pi.on("message_end", async (event) => {
        // Pi shows the failed request's error text in the TUI; a failure on
        // the managed credential also gets the PiShip action.
        const withAction = governedRef?.withAccessAction(event.message);
        const replaced = withAction
          ? { message: withAction as typeof event.message }
          : undefined;
        // A message that reads as both ("403 invalid api key") is a rejected
        // credential first.
        if (isCredentialRejection(event.message)) {
          governedRef?.markCredentialRejected();
          await access?.markCredentialRejected();
          return replaced;
        }
        if (replaced) return replaced;
        if (!isModelDenial(event.message)) return;
        // The gateway refused the model with 403: what the credential is
        // entitled to may have changed, so re-read it once. The rejected
        // request is not replayed, and the new entitlement applies from the
        // next launch.
        await access
          ?.refreshEntitlement()
          .catch((error: Error) =>
            ctx.err(
              `Notice: the model entitlement could not be re-read: ${formatError(error)}`,
            ),
          );
      });
      pi.on("model_select", (event) => {
        if (activated && access)
          publishContext(
            access.enterpriseContext(
              activated,
              `${event.model.provider}/${event.model.id}`,
            ),
          );
      });
    },
  };
  const ownerExtension = sessionOwnerExtension(
    ownership,
    ctx.metadata.app.command,
  );
  const createRuntime: CreateAgentSessionRuntimeFactory = async ({
    cwd,
    sessionManager,
  }) => {
    // A `/new`, `/resume`, or fork moves the owner record to the new file.
    const sessionFile = sessionManager.getSessionFile();
    // `session_before_switch` already refused a session another process owns;
    // losing the race after that must not leave two writers on one file.
    if (sessionFile && !ownership.claim(sessionFile))
      throw new PiShipError(
        "CONFIG_UNAVAILABLE",
        `Another ${ctx.metadata.app.command} process opened the session ${sessionFile} first, so it is not used here.`,
        {
          userAction: `Start ${ctx.metadata.app.command} again to continue, or run it with --new-session.`,
          component: "session",
        },
      );
    // Pi's project-trust flag is PiShip's decision, not the in-memory default.
    const settingsManager = SettingsManager.inMemory(
      piSettings(cacheWarming.mode),
      { projectTrusted: sessionProjectTrust(gov, cwd, ctx.agentDir) },
    );
    governCacheWarming(settingsManager, cacheWarming, gov);
    const { modelRuntime, governed } = await createModelRuntime(
      ctx,
      prepared,
      policy,
      virtual,
    );
    governedRef = governed;
    // Discovery uses the built distribution, never the user's cwd or personal ~/.pi.
    const resourceLoader = new DefaultResourceLoader({
      cwd: ctx.distributionDir,
      agentDir: ctx.agentDir,
      settingsManager,
      additionalExtensionPaths: gov
        ? gov.loader.extensions
        : resourcePaths(ctx, "extensions"),
      additionalSkillPaths: gov
        ? gov.loader.skills
        : resourcePaths(ctx, "skills"),
      additionalPromptTemplatePaths: gov
        ? gov.loader.prompts
        : resourcePaths(ctx, "prompts"),
      additionalThemePaths: gov
        ? gov.loader.themes
        : resourcePaths(ctx, "themes"),
      extensionFactories: inlineExtensionOrder(
        [
          ownerExtension,
          ...(ctx.metadata.access ? [governanceExtension] : []),
          ...builtinExtensions,
          ...exposureExtensionFactories,
        ],
        integrity,
        providerErrorRedaction,
      ),
      noExtensions: true,
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
      agentsFilesOverride: () => ({ agentsFiles: instructions }),
    });
    await resourceLoader.reload();
    startupMark("resources_loaded");
    const extensionErrors = resourceLoader.getExtensions().errors;
    const themeDiagnostics = resourceLoader.getThemes().diagnostics;
    // Counted before the launch fails; Pi reports these without a PiShip code.
    const loadFailures = extensionErrors.length + themeDiagnostics.length;
    for (let index = 0; index < loadFailures; index += 1)
      prepared.metrics?.recordLoadFailure("resource", "UNKNOWN");
    if (extensionErrors.length)
      throw new Error(
        `Pi extension load failed: ${extensionErrors.map((item) => item.error).join("; ")}`,
      );
    if (themeDiagnostics.length)
      throw new Error(
        `Pi theme load failed: ${themeDiagnostics.map((item) => item.message).join("; ")}`,
      );
    // Virtual models are registered here, before the launch model and a
    // resumed session's model are looked up, and again after each /reload;
    // Pi would register them later and drop a refusal unheard.
    if (governed) {
      governVirtualModels(resourceLoader, governed, modelRuntime, virtual);
      for (const rule of virtual)
        if (!modelRuntime.getModel(rule.provider, rule.id))
          ctx.err(
            `Notice: virtual model ${rule.provider}/${rule.id} is declared, but its router ${rule.router} did not register it.`,
          );
    }
    // Hidden and denied tools, and Pi's ungoverned base tools, are excluded
    // from the session; an extension tool wider than the manifest allows
    // fails the launch.
    const table =
      gov && exposureConfig
        ? buildExposureTable(
            gov,
            exposureConfig,
            extensionToolsOf(resourceLoader),
          )
        : null;
    if (gov) {
      gov.exposure = table;
      gov.piExtensions = () => resourceLoader.getExtensions().extensions;
    }
    if (
      theme &&
      !["dark", "light"].includes(theme) &&
      !resourceLoader.getThemes().themes.some((item) => item.name === theme)
    )
      throw new Error(`Declared theme is unavailable: ${theme}`);
    let model: Model | undefined;
    if (activated?.selectedModel) {
      const [provider, ...rest] =
        activated.runtime.kind === "managed-endpoint"
          ? [activated.runtime.providerId, activated.selectedModel]
          : activated.selectedModel.split("/");
      model = modelRuntime.getModel(provider ?? "", rest.join("/"));
      if (!model) {
        const command = ctx.metadata.app.command;
        const flag =
          activated.runtime.kind === "managed-endpoint"
            ? "--model <model>"
            : "--model <provider/model>";
        const fromPreference =
          activated.config.values.model === activated.selectedModel &&
          activated.config.entries.find((entry) => entry.key === "model")
            ?.source === "user-preference";
        throw new PiShipError(
          "MODEL_UNAVAILABLE",
          `Model ${activated.selectedModel} is not available in the Pi runtime`,
          {
            userAction: fromPreference
              ? `Run ${command} config unset model to remove the model preference, or start ${command} ${flag}`
              : `Start ${command} ${flag} with a model Pi offers`,
          },
        );
      }
    }
    startupMark("agent_session_start");
    const result = await createAgentSession({
      cwd,
      agentDir: ctx.agentDir,
      settingsManager,
      modelRuntime,
      resourceLoader,
      sessionManager,
      ...(model ? { model } : {}),
      ...(thinkingLevel ? { thinkingLevel: thinkingLevel as never } : {}),
      // Governed sessions replace Pi's built-in tools with governed ones of
      // the same names; SDK custom tools also win over extension tools.
      ...(gov
        ? {
            noTools: "builtin" as const,
            customTools: governedCustomTools(gov, cwd, table),
            excludeTools: table?.excluded() ?? [],
          }
        : {}),
    });
    if (table) activateExposure(result.session, table);
    const current = result.session.model;
    if (
      governed &&
      current &&
      !governed.isSelectable(current.provider, current.id)
    ) {
      if (!model)
        throw new PiShipError(
          "MODEL_DENIED",
          `The resumed session uses ${current.provider}/${current.id}, which is not allowed`,
        );
      await result.session.setModel(model);
      ctx.err(
        `Notice: the resumed session used ${current.provider}/${current.id}, which is no longer allowed; switched to ${model.provider}/${model.id}.`,
      );
    }
    const services: AgentSessionServices = {
      cwd,
      agentDir: ctx.agentDir,
      settingsManager,
      modelRuntime,
      resourceLoader,
      diagnostics: [],
    };
    return { ...result, services, diagnostics: [] };
  };
  const runtime = await createAgentSessionRuntime(createRuntime, {
    cwd: process.cwd(),
    agentDir: ctx.agentDir,
    sessionManager,
  });
  return { runtime, theme, context, governed: () => governedRef };
}

/**
 * Starts the Pi runtime on the session `openSession` chose. The returned
 * ownership is released when the session ends (or, at the latest, when the
 * process exits).
 */
export async function startGoverned(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  session: SessionOptions,
  gov: GovernanceSession | null,
) {
  let ownership: SessionOwnership | undefined;
  try {
    const opened = openSession(process.cwd(), session.sessionDir, {
      newSession: session.newSession,
      command: ctx.metadata.app.command,
      ...(session.disposable ? { disposable: true } : {}),
    });
    ownership = opened.ownership;
    if (opened.notice) ctx.err(`Notice: ${opened.notice}`);
    const started = await startRuntime(
      ctx,
      prepared,
      opened.sessionManager,
      gov,
      opened.ownership,
    );
    return { ...started, ownership: opened.ownership };
  } catch (error) {
    ownership?.release();
    // The start error stays the command's error; a close that lost audit
    // events is reported next to it instead of replacing it. Both are counted
    // in the local startup failures, as an open failure is.
    const count = (failure: unknown) =>
      prepared.metrics?.recordStartupFailure(
        failure instanceof PiShipError ? failure.code : "CONFIG_UNAVAILABLE",
      );
    count(error);
    try {
      await gov?.close();
    } catch (closeError) {
      count(closeError);
      ctx.err(`Error: ${formatError(closeError)}`);
    }
    saveMetrics(prepared.metrics);
    throw error;
  }
}
