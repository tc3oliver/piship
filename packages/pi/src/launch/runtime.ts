import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join, sep } from "node:path";
import {
  createAgentSession,
  createAgentSessionRuntime,
  DefaultResourceLoader,
  SessionManager,
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
  boundedByAllowlist,
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
import { entitlementNotice } from "./entitlement-notice.js";
import {
  assertPrivateDirectory,
  childToolOptions,
  type SubagentChild,
} from "./subagent-child.js";
import { publishSubagentOwner } from "./subagent-owner.js";
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
  SessionOwnership,
} from "./session-file.js";

/**
 * Each resource the launch loads is still the regular file the lock lists.
 * Hashing every one at every start is per-file work the installed payload
 * was already verified for (at install or update, and by `doctor`), so it is
 * done only for a distribution that declares `runtime.verifyAtLaunch: true`.
 */
export function verifyBuiltResources(
  ctx: Pick<LaunchContext, "distributionDir"> & {
    readonly metadata: Pick<LaunchContext["metadata"], "resources" | "app"> & {
      readonly verifyAtLaunch?: boolean;
    };
  },
): void {
  const resourceDir = join(ctx.distributionDir, "resources");
  const hash = ctx.metadata.verifyAtLaunch === true;
  const damaged = (path: string, reason: string) =>
    new PiShipError(
      "INTEGRITY_FAILED",
      `Built resource ${path} in ${ctx.distributionDir} ${reason}`,
      {
        component: "payload",
        userAction: builtResourceRepair(ctx.metadata.app.id),
      },
    );
  for (const resource of ctx.metadata.resources) {
    if (
      resource.path.startsWith("/") ||
      resource.path.split("/").includes("..")
    )
      throw new Error("Unsafe built resource path");
    const path = join(resourceDir, resource.path);
    let file: boolean;
    try {
      file = lstatSync(path).isFile();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      throw damaged(
        resource.path,
        code === "ENOENT" ? "is missing" : `cannot be read (${code})`,
      );
    }
    if (!file) throw damaged(resource.path, "is not a regular file");
    if (!hash) continue;
    const digest = createHash("sha256")
      .update(readFileSync(path))
      .digest("hex");
    if (digest !== resource.sha256)
      throw damaged(resource.path, "does not match the lock (modified)");
  }
}

/** The same recovery core's payload checks name: restore from a trusted release, never edit in place. */
function builtResourceRepair(id: string): string {
  return `Do not run it. Restore it from a trusted release of the same version: piship repair ${id} <release archive> (without the PiShip CLI: node <extracted release>/payload/piship.mjs repair ${id} <extracted release>), or reinstall the distribution. A distribution that is not installed must be rebuilt with piship build`;
}

/**
 * Pi's load errors, each naming its extension: a factory that throws reports
 * only its message, so the path is added the way Pi's own CLI does.
 */
export function extensionLoadErrors(
  errors: readonly { readonly path: string; readonly error: string }[],
  distributionDir: string,
): string {
  return sourcePaths(
    errors
      .map((item) => {
        const conflict = toolConflict(item, distributionDir);
        if (conflict)
          return `Tool "${conflict.tool}" is registered by both ${extensionLabel(conflict.owner, distributionDir)} and ${extensionLabel(item.path, distributionDir)}`;
        return item.error.includes(item.path)
          ? item.error
          : `Failed to load extension "${item.path}": ${item.error}`;
      })
      .join("; "),
    distributionDir,
  );
}

/**
 * Pi's "Tool X conflicts with <path>" for two extensions of which at least
 * one is a vendored package's, whose built copy no one can fix.
 */
function toolConflict(
  item: { readonly path: string; readonly error: string },
  distributionDir: string,
) {
  const match = /^Tool "(.+)" conflicts with (.+)$/s.exec(item.error);
  if (!match?.[1] || !match[2]) return;
  const owner = match[2];
  const excluded =
    packageFile(item.path, distributionDir) ??
    packageFile(owner, distributionDir);
  return excluded ? { tool: match[1], owner, excluded } : undefined;
}

/**
 * A vendored package's file: its id and its path inside the package, which is
 * what that package's resource filters match.
 */
export function packageFile(
  path: string,
  distributionDir: string,
): { readonly id: string; readonly file: string } | undefined {
  const root = `${distributionDir.replaceAll("\\", "/")}/pi-packages/`;
  const slashed = path.replaceAll("\\", "/");
  if (!slashed.startsWith(root)) return;
  const [id, top, ...rest] = slashed.slice(root.length).split("/");
  if (!id || !top) return;
  // pi-packages/<id>/package/... (git, local) or node_modules/<name>/... (npm)
  if (top === "node_modules") rest.splice(0, rest[0]?.startsWith("@") ? 2 : 1);
  return { id, file: rest.join("/") };
}

/** An extension named as its author knows it: package and file, or the declared path. */
export function extensionLabel(path: string, distributionDir: string): string {
  const inPackage = packageFile(path, distributionDir);
  return inPackage
    ? `package ${inPackage.id} (${inPackage.file})`
    : sourcePaths(path, distributionDir);
}

/**
 * What to do about an extension or theme Pi could not load: its author fixes
 * the source and rebuilds; a managed user cannot, so the administrator does.
 */
export function resourceLoadAction(
  mode: LaunchContext["mode"],
  errors: readonly { readonly path: string; readonly error: string }[] = [],
  distributionDir = "",
): string {
  if (mode === "managed")
    return "Contact your administrator: the distribution ships a resource that does not load";
  const conflict = errors
    .map((item) => toolConflict(item, distributionDir))
    .find(Boolean);
  if (conflict)
    return `Keep one of the two tools: exclude the other extension with its package's extensions filter in piship.yaml (for example extensions: ["!${conflict.excluded.file}"] on package ${conflict.excluded.id}), then run piship lock and build again`;
  return "Fix the source file named above, run piship build, then install the rebuilt distribution again";
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

/**
 * Rewrites paths into the payload's resources folder as the manifest-relative
 * paths the author wrote (`./resources/extensions/bad.ts`), so a load error
 * points at the source file rather than its build copy.
 */
export function sourcePaths(text: string, distributionDir: string): string {
  const root = join(distributionDir, "resources");
  let output = text;
  for (const prefix of new Set([
    `${root}${sep}`,
    `${root.replaceAll("\\", "/")}/`,
  ]))
    output = output.replaceAll(prefix, "./");
  return output;
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
  /** `--session <id>`: resume this session of the project, or refuse. */
  readonly resume?: string;
  /** A session that holds no user work: a damaged one is replaced, not refused. */
  readonly disposable?: boolean;
  /** A subagent child: no resume, and its options only narrow the session. */
  readonly child?: SubagentChild;
}

/** The child's session: in memory, or the background run's own directory. */
function openChildSession(cwd: string, child: SubagentChild) {
  const ownership = new SessionOwnership();
  if (!child.session)
    return { sessionManager: SessionManager.inMemory(cwd), ownership };
  const { id, dir } = child.session;
  // Checked where it is used: a link, another user's, or an open directory
  // swapped in since the arguments were read is not pi-code's session.
  assertPrivateDirectory(dir, "session directory");
  const existing = SessionManager.findById(cwd, id, dir);
  const sessionManager = existing
    ? SessionManager.open(existing, dir, cwd)
    : SessionManager.create(cwd, dir, { id });
  return { sessionManager, ownership };
}

/** Why a launch has no allowed model, for the refusal's cause and next step. */
export interface NoModelCause {
  /** The session being resumed, or false for a new session. */
  readonly resumed: boolean;
  /** The user's own models.allowed preference narrowed the allowlist. */
  readonly userNarrowed: boolean;
  readonly mode: "managed" | "personal";
}

/**
 * The model a session switches to when the one Pi picked (a resumed
 * session's last model, or Pi's default) is not allowed: the one the launch
 * chose, or else the first the distribution still allows. Only a launch with
 * no allowed model at all fails.
 */
export function replacementModel<T>(
  chosen: T | undefined,
  allowed: readonly T[],
  previous: string,
  command: string,
  cause: NoModelCause,
): T {
  const replacement = chosen ?? allowed[0];
  // Pi names a session with no model unknown/unknown; that is not a model to report.
  if (replacement === undefined)
    throw new PiShipError(
      "MODEL_DENIED",
      `${cause.resumed && previous !== "unknown/unknown" ? `The resumed session uses ${previous}, which is not allowed, and no` : "No"} allowed model is available: ${cause.userNarrowed ? "no model Pi offers matches your models.allowed preference" : "the distribution allows no model Pi offers"}`,
      {
        userAction: cause.userNarrowed
          ? `Run ${command} config unset models.allowed, or set it to a model ${command} models lists, then start ${command} again`
          : cause.mode === "personal"
            ? `Set models.allowed in piship.yaml to a model ${command} models lists, then start ${command} again`
            : `Ask your administrator to allow a model Pi offers, then start ${command} again`,
        component: "inference",
      },
    );
  return replacement;
}

/**
 * The theme a launch uses. A theme the person chose with `config set` and
 * mistyped, or one a later release no longer ships, must not stop every
 * launch: the distribution's theme (or Pi's) is used, with a notice that says
 * how to fix it. A theme the distribution itself declares that is not
 * available still fails the launch.
 */
export function launchTheme(input: {
  readonly theme: string | undefined;
  readonly preferred: boolean;
  readonly distributionTheme: string | undefined;
  readonly loaded: readonly (string | undefined)[];
  readonly command: string;
  /** A theme failed to load, so a declared theme may be missing because of it. */
  readonly loadFailed?: boolean;
}): { readonly theme: string | undefined; readonly notice?: string } {
  const names = ["dark", "light", ...input.loaded.filter((name) => !!name)];
  const available = (name: string | undefined) => !name || names.includes(name);
  if (!available(input.theme) && input.preferred) {
    const fallback = available(input.distributionTheme)
      ? input.distributionTheme
      : undefined;
    return {
      theme: fallback,
      notice: `Notice: theme ${input.theme} (your preference) is not available, so ${fallback ?? "Pi's default theme"} is used. Choose one of ${names.join(", ")} with ${input.command} config set theme <name>, or run ${input.command} config unset theme.`,
    };
  }
  if (!available(input.theme) && input.loadFailed)
    return {
      theme: undefined,
      notice: `Notice: theme ${input.theme} did not load, so Pi's default theme is used.`,
    };
  if (!available(input.theme))
    throw new Error(`Declared theme is unavailable: ${input.theme}`);
  return { theme: input.theme };
}

/**
 * What to do when the selected model is not one Pi offers, by where the
 * selection came from: a user preference, the manifest, or a --model flag.
 */
export function unavailableModelAction(
  command: string,
  flag: string,
  source: string | undefined,
): string {
  if (source === "user-preference")
    return `Run ${command} config unset model to remove the model preference, or start ${command} ${flag}`;
  if (source === "distribution-default" || source === "distribution-enforced")
    return `The distribution's models.default is not a model Pi offers: set models.default (and models.allowed, if it lists models) in piship.yaml to one ${command} models lists, or start ${command} ${flag}`;
  return `Start ${command} ${flag} with a model Pi offers`;
}

async function startRuntime(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  sessionManager: SessionManager,
  gov: GovernanceSession | null,
  ownership: SessionOwnership,
  child?: SubagentChild,
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
  const policy = gov
    ? await modelPolicy(gov, selectedKey, virtual, ctx.metadata.app.command)
    : undefined;
  const builtinExtensions = gov ? governanceExtensions(gov) : [];
  const exposureConfig = gov ? exposureConfigOf(gov) : null;
  const exposureExtensionFactories =
    gov && exposureConfig ? exposureFactories(gov, exposureConfig) : [];
  const integrity = gov
    ? runtimeIntegrityExtension(gov, enforcedRuntime(gov, activeWorkflow(gov)))
    : null;
  const cacheWarming = cacheWarmingSetting(gov);
  let theme = activated?.config.values.theme ?? ctx.metadata.app.theme;
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
        // next launch: the session says so when it differs from this one's.
        let reread = false;
        await access
          ?.refreshEntitlement()
          .then(() => {
            reread = true;
          })
          .catch((error: Error) =>
            ctx.err(
              `Notice: the model entitlement could not be re-read: ${formatError(error)}`,
            ),
          );
        if (!access || !reread) return;
        const refused = (event.message as { model?: string }).model;
        const notice = entitlementNotice({
          before: activated?.credential.ref?.models,
          after: (await access.credentialManager()).readMetadata()?.models,
          refused,
          command: ctx.metadata.app.command,
        });
        if (gov) gov.notice(notice);
        else ctx.err(`Notice: ${notice}`);
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
      // A subagent's own prompt replaces Pi's base prompt only: the
      // distribution's instructions below still apply.
      ...(child?.systemPrompt !== undefined
        ? { systemPromptOverride: () => child.systemPrompt }
        : {}),
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
      throw new PiShipError(
        "CONFIG_INVALID",
        `Pi extension load failed: ${extensionLoadErrors(
          extensionErrors,
          ctx.distributionDir,
        )}`,
        {
          component: "extensions",
          userAction: resourceLoadAction(
            ctx.mode,
            extensionErrors,
            ctx.distributionDir,
          ),
        },
      );
    if (themeDiagnostics.length)
      // A broken theme is cosmetic: skip it and launch with the default.
      ctx.err(
        `Warning: skipped a Pi theme that failed to load (${themeDiagnostics.map((item) => item.message).join("; ")}). ${resourceLoadAction(ctx.mode)}`,
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
    const built =
      gov && exposureConfig
        ? buildExposureTable(
            gov,
            exposureConfig,
            extensionToolsOf(resourceLoader),
          )
        : null;
    // A child's `--tools` is a bound: Codemode and tool search would reach
    // tools it leaves out, so they stay inactive in such a child.
    const table = built && child?.tools ? boundedByAllowlist(built) : built;
    if (gov) {
      gov.exposure = table;
      gov.piExtensions = () => resourceLoader.getExtensions().extensions;
    }
    const chosen = launchTheme({
      theme,
      preferred:
        activated?.config.entries.some(
          (entry) =>
            entry.key === "theme" && entry.source === "user-preference",
        ) ?? false,
      distributionTheme: ctx.metadata.app.theme,
      loaded: resourceLoader.getThemes().themes.map((item) => item.name),
      command: ctx.metadata.app.command,
      loadFailed: themeDiagnostics.length > 0,
    });
    if (chosen.notice) ctx.err(chosen.notice);
    theme = chosen.theme;
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
        const source =
          activated.config.values.model === activated.selectedModel
            ? activated.config.entries.find((entry) => entry.key === "model")
                ?.source
            : undefined;
        throw new PiShipError(
          "MODEL_UNAVAILABLE",
          `Model ${activated.selectedModel} is not available in the Pi runtime`,
          { userAction: unavailableModelAction(command, flag, source) },
        );
      }
    }
    // Pi restores the model of a session that already has messages, unless
    // one is passed: only --model overrides it, and a model the session ended
    // on that is no longer allowed is replaced below.
    const resumed = sessionManager.buildSessionContext().messages.length > 0;
    // A pi-native model is not checked against capabilities with model
    // requirements by Pi, so such a launch keeps the model it verified.
    // An explicit choice wins over the session's model: --model, or a model
    // preference the user set, which the launch resolved to.
    const preferredModel =
      activated?.config.values.model === activated?.selectedModel &&
      (activated?.config.entries.some(
        (entry) => entry.key === "model" && entry.source === "user-preference",
      ) ??
        false);
    const keepSessionModel =
      resumed &&
      !prepared.requestedModel &&
      !preferredModel &&
      !(
        activated?.runtime.kind === "pi-native" &&
        (ctx.metadata.governance?.manifest.capabilities ?? []).some(
          (item) => item.enabled && item.requirements,
        )
      );
    startupMark("agent_session_start");
    const result = await createAgentSession({
      cwd,
      agentDir: ctx.agentDir,
      settingsManager,
      modelRuntime,
      resourceLoader,
      sessionManager,
      ...(model && !keepSessionModel ? { model } : {}),
      ...(thinkingLevel ? { thinkingLevel: thinkingLevel as never } : {}),
      // Governed sessions replace Pi's built-in tools with governed ones of
      // the same names; SDK custom tools also win over extension tools.
      ...(gov
        ? {
            noTools: "builtin" as const,
            customTools: governedCustomTools(gov, cwd, table),
          }
        : {}),
      // Pi bounds the session's tools by `tools`, after exposure: it can only
      // remove tools, never add one the exclusions remove. The integrity
      // extension re-activates the tools the distribution requires, so they
      // stay in the list (and a child may not exclude them).
      ...childToolOptions(
        child,
        gov ? (table?.excluded() ?? []) : undefined,
        child && gov ? enforcedRuntime(gov, undefined).mandatoryTools : [],
      ),
    });
    if (child?.thinking) result.session.setThinkingLevel(child.thinking);
    if (table) activateExposure(result.session, table);
    if (
      keepSessionModel &&
      model &&
      (result.modelFallbackMessage || !result.session.model)
    ) {
      // Pi could not restore the model the session ended on, and picked
      // another: the launch's model wins. Without credentials the switch is
      // refused; Pi's own message is not shown by the session, so print it.
      try {
        await result.session.setModel(model);
        ctx.err(
          `Notice: the model the resumed session ended on could not be restored; switched to ${model.provider}/${model.id}.`,
        );
      } catch {
        if (result.modelFallbackMessage)
          ctx.err(`Notice: ${result.modelFallbackMessage}`);
      }
    }
    const current = result.session.model;
    if (
      governed &&
      current &&
      !governed.isSelectable(current.provider, current.id)
    ) {
      // The model the launch chose, or else the first one the distribution
      // still allows: a session is never refused for the model it ended on.
      const replacement = replacementModel(
        model,
        modelRuntime.getAvailableSnapshot(),
        `${current.provider}/${current.id}`,
        ctx.metadata.app.command,
        {
          resumed,
          userNarrowed: activated?.config.userNarrowedFrom !== undefined,
          mode: ctx.mode,
        },
      );
      await result.session.setModel(replacement);
      if (resumed)
        ctx.err(
          `Notice: the resumed session used ${current.provider}/${current.id}, which is no longer allowed; switched to ${replacement.provider}/${replacement.id}.`,
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
 * Lets this session's subagent tool start children (launch/subagent-owner.ts).
 * A session that cannot publish still runs; its children are refused.
 */
function publishChildren(ctx: LaunchContext, gov: GovernanceSession | null) {
  try {
    publishSubagentOwner(ctx.stateDir, {
      session: gov?.sessionId ?? "",
      workspace: realpathSync.native(process.cwd()),
      ...(gov?.manifestGrantBinding ? { grant: gov.manifestGrantBinding } : {}),
    });
  } catch (error) {
    ctx.err(
      `Notice: subagents are unavailable in this session: ${formatError(error)}`,
    );
  }
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
    if (!session.child) publishChildren(ctx, gov);
    const opened = session.child
      ? { ...openChildSession(process.cwd(), session.child), notice: undefined }
      : openSession(process.cwd(), session.sessionDir, {
          newSession: session.newSession,
          command: ctx.metadata.app.command,
          ...(session.resume !== undefined ? { resume: session.resume } : {}),
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
      session.child,
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
