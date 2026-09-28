/** The only Pi package integration boundary. All imports use the public package entrypoint. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import {
  createAgentSession,
  createAgentSessionRuntime,
  createReadTool,
  DefaultResourceLoader,
  InteractiveMode,
  ModelRuntime,
  SessionManager,
  SettingsManager,
  VERSION,
  type AgentSessionServices,
  type CreateAgentSessionRuntimeFactory,
  type InlineExtension,
} from "@earendil-works/pi-coding-agent";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  ENTERPRISE_CONTEXT_SYMBOL,
  type EnterpriseContext,
  PiShipError,
  type PolicyAction,
  POLICY_ACTIONS,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  type AuditEventType,
  formatError,
  redact,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import {
  type ActivatedAccess,
  DistributionAccess,
  type DistributionLock,
  accessStatePaths,
  explainConfiguration,
  formatExplanation,
  formatMigrationReport,
  lifecycleStatus,
  readInstallReceipt,
  rollbackDistribution,
  runtimeStateDirectory,
  setPreference,
  updateDistribution,
} from "@piship/core";
import { AuditLog, describeAuditStatus, LocalMetrics } from "@piship/audit";
import {
  decisionToJSON,
  formatCapabilities,
  formatDecision,
} from "@piship/policy";
import { resolveTemplate } from "@piship/schema";
import {
  askUserExtension,
  governanceHooks,
  workflowExtension,
} from "./builtins.js";
import {
  governModelRuntime,
  isCredentialRejection,
  type GovernedRuntime,
  type ModelPolicy,
} from "./governance.js";
import {
  type GovernanceOptions,
  GovernanceSession,
  inspectGovernance,
} from "./governance-session.js";
import { governedTools } from "./governed-tools.js";

export {
  governModelRuntime,
  isCredentialRejection,
  type ModelGovernance,
  type ModelPolicy,
  type GovernedRuntime,
} from "./governance.js";
export {
  GovernanceSession,
  inspectGovernance,
  type GovernanceInspection,
  type GovernanceOptions,
} from "./governance-session.js";

export const PINNED_PI_VERSION = "0.87.1" as const;
export type PiVersion = typeof PINNED_PI_VERSION;
export type PiSessionFactory = typeof createAgentSession;
export interface LaunchOptions {
  readonly distributionDir: string;
  readonly metadata: DistributionLock;
  readonly args: readonly string[];
}

/** Sent as the bearer only for `credential.provider: none`; it is not a secret. */
export const NO_CREDENTIAL_PLACEHOLDER = "piship-no-credential";
const SMOKE_PROMPT = "PiShip acceptance request: reply with a short greeting.";

type Model = NonNullable<ReturnType<ModelRuntime["getModel"]>>;

interface LaunchContext {
  readonly metadata: DistributionLock;
  readonly distributionDir: string;
  readonly stateDir: string;
  readonly agentDir: string;
  readonly mode: "personal" | "managed";
  readonly out: (message: string) => void;
  readonly err: (message: string) => void;
}

function openAccess(ctx: LaunchContext): DistributionAccess {
  return DistributionAccess.open({
    app: ctx.metadata.app,
    mode: ctx.mode,
    access: ctx.metadata.access,
    stateDir: ctx.stateDir,
    distributionDir: ctx.distributionDir,
  });
}

function openBrowser(url: string): void {
  if (process.env.PISHIP_NO_BROWSER === "1") return;
  try {
    const child =
      process.platform === "darwin"
        ? spawn("open", [url], { stdio: "ignore", detached: true })
        : process.platform === "win32"
          ? spawn("rundll32", ["url.dll,FileProtocolHandler", url], {
              stdio: "ignore",
              detached: true,
            })
          : spawn("xdg-open", [url], { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    // The URL is always printed; opening a browser is a convenience.
  }
}

async function readSecretInput(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    let data = "";
    for await (const chunk of process.stdin) data += chunk;
    return data.split(/\r?\n/)[0] ?? "";
  }
  process.stderr.write(`${prompt}: `);
  const rl = createInterface({
    input: process.stdin,
    output: undefined,
    terminal: true,
  });
  const answer = await new Promise<string>((resolveAnswer) =>
    rl.question("", resolveAnswer),
  );
  rl.close();
  process.stderr.write("\n");
  return answer;
}

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

function toPiModels(activated: ActivatedAccess) {
  return activated.runtime.models.map((model) => ({
    id: model.id,
    name: model.name,
    reasoning: model.capabilities.reasoning ?? false,
    input: (model.capabilities.input ?? ["text"]).filter(
      (item): item is "text" | "image" => item === "text" || item === "image",
    ),
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: model.capabilities.contextWindow ?? 128_000,
    maxTokens: model.capabilities.maxOutputTokens ?? 8192,
  }));
}

/** An in-memory Pi credential store: managed runtimes never read ~/.pi or auth.json. */
function isolatedCredentialStore() {
  const values = new Map<string, unknown>();
  return {
    async read(id: string) {
      return values.get(id) as never;
    },
    async list() {
      return [];
    },
    async modify(id: string, fn: (current: never) => Promise<unknown>) {
      const next = await fn(values.get(id) as never);
      if (next !== undefined) values.set(id, next);
      return values.get(id) as never;
    },
    async delete(id: string) {
      values.delete(id);
    },
  };
}

interface PreparedAccess {
  readonly access: DistributionAccess | null;
  readonly activated: ActivatedAccess | null;
  readonly removedEnvironment: readonly string[];
}

async function prepareAccess(
  ctx: LaunchContext,
  requestedModel: string | undefined,
): Promise<PreparedAccess> {
  if (!ctx.metadata.access) {
    if (requestedModel && !/^[^/]+\/.+$/.test(requestedModel))
      throw new PiShipError(
        "MODEL_DENIED",
        "Use --model provider/model for Pi-native distributions",
      );
    return { access: null, activated: null, removedEnvironment: [] };
  }
  // Refuse before sanitizing: silently dropping a disabled-TLS setting would hide it.
  assertTlsVerificationEnabled();
  const access = openAccess(ctx);
  let removedEnvironment: string[] = [];
  if (ctx.mode === "managed")
    removedEnvironment = sanitizeManagedEnvironment(
      process.env,
      access.network,
      ctx.metadata.access.variables,
    );
  applyProcessNetworkPolicy(access.network);
  const activated = await access.activate(
    requestedModel ? { requestedModel } : {},
  );
  return { access, activated, removedEnvironment };
}

async function createModelRuntime(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  policy?: ModelPolicy,
): Promise<{ modelRuntime: ModelRuntime; governed: GovernedRuntime | null }> {
  const { activated, access } = prepared;
  if (!activated || !access || activated.runtime.kind === "pi-native") {
    const modelRuntime = await ModelRuntime.create({
      authPath: join(ctx.agentDir, "auth.json"),
      modelsPath: join(ctx.agentDir, "models.json"),
    });
    // The effective allowlist includes an enforced model and user narrowing,
    // not only the manifest's list.
    const effective = activated?.config;
    const governed =
      ctx.metadata.access || policy
        ? governModelRuntime(
            modelRuntime,
            {
              kind: "pi-native",
              allowedModelKeys: effective
                ? effective.allowedModels
                : (ctx.metadata.access?.models.allowed ?? []),
              restricted: effective?.modelsRestricted ?? false,
            },
            policy,
          )
        : null;
    return { modelRuntime, governed };
  }
  const modelRuntime = await ModelRuntime.create({
    credentials: isolatedCredentialStore() as never,
    modelsPath: null,
    refreshOnCreate: false,
    allowModelNetwork: false,
  });
  modelRuntime.registerProvider(activated.runtime.providerId, {
    name: ctx.metadata.app.name,
    baseUrl: activated.runtime.baseUrl ?? "",
    api: activated.runtime.api ?? "openai-completions",
    models: toPiModels(activated),
  });
  const governed = governModelRuntime(
    modelRuntime,
    {
      kind: "managed-endpoint",
      providerId: activated.runtime.providerId,
      allowedModelIds: activated.runtime.models
        .map((model) => model.id)
        .filter((id) => activated.config.allowedModels.includes(id)),
      apiKey: async ({ force }) => {
        if (!activated.runtime.requiresCredential)
          return NO_CREDENTIAL_PLACEHOLDER;
        const secret = await access.requestSecret({ force });
        if (!secret)
          throw new PiShipError(
            "CREDENTIAL_REQUIRED",
            "No runtime credential is available",
            {
              userAction: `Run ${ctx.metadata.app.command} login`,
            },
          );
        return secret.reveal();
      },
    },
    policy,
  );
  return { modelRuntime, governed };
}

function publishContext(context: EnterpriseContext | null): void {
  const holder = globalThis as unknown as Record<symbol, unknown>;
  if (context) holder[ENTERPRISE_CONTEXT_SYMBOL] = context;
  else delete holder[ENTERPRISE_CONTEXT_SYMBOL];
}

type GovernedLock = GovernanceOptions["lock"];

function governedLock(ctx: LaunchContext): GovernedLock | null {
  return ctx.metadata.governance ? (ctx.metadata as GovernedLock) : null;
}

function governanceOptions(
  ctx: LaunchContext,
  lock: GovernedLock,
  prepared: PreparedAccess | null,
  interactive: boolean,
): GovernanceOptions {
  const { access, activated } = prepared ?? {};
  return {
    lock,
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
    user: activated?.identity?.subject ?? null,
    ...(access && activated?.runtime.requiresCredential
      ? {
          credential: async () =>
            (await access.requestSecret({ force: false }))?.reveal(),
        }
      : {}),
  };
}

async function openGovernance(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  interactive: boolean,
): Promise<GovernanceSession | null> {
  const lock = governedLock(ctx);
  if (!lock) return null;
  const gov = await GovernanceSession.open(
    governanceOptions(ctx, lock, prepared, interactive),
  );
  const { access, activated } = prepared;
  if (access && activated?.credential.ref)
    gov.emit("credential.acquire", {
      detail: {
        mode: access.credentialMode,
        renewed: activated.notices.some((notice) =>
          notice.includes("new credential"),
        ),
      },
    });
  return gov;
}

/**
 * Identity lifecycle events outside a session. Best effort: signing out must
 * work while the company sink is down, so a failure is reported, not fatal.
 */
async function auditAccess(
  ctx: LaunchContext,
  access: DistributionAccess,
  user: string | null,
  events: readonly AuditEventType[],
): Promise<void> {
  const lock = governedLock(ctx);
  if (!lock) return;
  try {
    const log = await AuditLog.open({
      config: lock.governance.manifest.audit,
      distribution: lock.app.id,
      stateDir: ctx.stateDir,
      fetch: createManagedFetch(access.network, "audit"),
      resolveUrl: (template) =>
        resolveTemplate(
          "audit.sinks.url",
          template,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
    });
    for (const event of events)
      log.emit({
        event,
        user,
        session: null,
        detail: { mode: access.credentialMode },
      });
    await log.close();
  } catch (error) {
    ctx.err(`Warning: audit events were not recorded: ${formatError(error)}`);
  }
}

/** PiShip's inline extensions for a governed session. */
function governanceExtensions(gov: GovernanceSession): InlineExtension[] {
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
async function modelPolicy(
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
  };
}

async function startRuntime(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  sessionDir: string,
  gov: GovernanceSession | null = null,
) {
  verifyBuiltResources(ctx);
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
  const policy = gov ? await modelPolicy(gov, selectedKey) : undefined;
  const builtinExtensions = gov ? governanceExtensions(gov) : [];
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
        if (!isCredentialRejection(event.message)) return;
        governedRef?.markCredentialRejected();
        await access?.markCredentialRejected();
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
  const createRuntime: CreateAgentSessionRuntimeFactory = async ({
    cwd,
    sessionManager,
  }) => {
    const settingsManager = SettingsManager.inMemory();
    const { modelRuntime, governed } = await createModelRuntime(
      ctx,
      prepared,
      policy,
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
      ...(ctx.metadata.access || builtinExtensions.length
        ? {
            extensionFactories: [
              ...(ctx.metadata.access ? [governanceExtension] : []),
              ...builtinExtensions,
            ],
          }
        : {}),
      noExtensions: true,
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
      agentsFilesOverride: () => ({ agentsFiles: instructions }),
    });
    await resourceLoader.reload();
    const extensionErrors = resourceLoader.getExtensions().errors;
    if (extensionErrors.length)
      throw new Error(
        `Pi extension load failed: ${extensionErrors.map((item) => item.error).join("; ")}`,
      );
    const themeDiagnostics = resourceLoader.getThemes().diagnostics;
    if (themeDiagnostics.length)
      throw new Error(
        `Pi theme load failed: ${themeDiagnostics.map((item) => item.message).join("; ")}`,
      );
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
      if (!model)
        throw new PiShipError(
          "MODEL_UNAVAILABLE",
          `Model ${activated.selectedModel} is not available in the Pi runtime`,
        );
    }
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
        ? { noTools: "builtin" as const, customTools: governedTools(gov, cwd) }
        : {}),
    });
    const current = result.session.model;
    if (
      governed &&
      current &&
      !governed.isAllowed(current.provider, current.id)
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
    sessionManager: SessionManager.continueRecent(process.cwd(), sessionDir),
  });
  return { runtime, theme, context, governed: () => governedRef };
}

function accessSummary(
  prepared: PreparedAccess,
  ctx: LaunchContext,
  selected?: string,
) {
  if (!prepared.activated || !prepared.access) return undefined;
  const { activated, access } = prepared;
  return {
    mode: ctx.mode,
    identity: activated.identity
      ? {
          subject: activated.identity.subject,
          issuer: activated.identity.issuer,
        }
      : null,
    credential: {
      mode: access.credentialMode,
      credentialId: activated.credential.ref?.credentialId ?? null,
      expiresAt: activated.credential.ref?.expiresAt?.toISOString() ?? null,
    },
    inference: activated.runtime.kind,
    selectedModel: selected ?? activated.selectedModel ?? null,
    allowedModels: activated.config.allowedModels,
    models: activated.models.map((model) => ({
      id: model.id,
      available: model.availability.available,
      ...(model.availability.reason
        ? { reason: model.availability.reason }
        : {}),
    })),
    removedEnvironment: prepared.removedEnvironment,
    notices: activated.notices,
  };
}

async function runSmoke(
  ctx: LaunchContext,
  requestedModel: string | undefined,
  withModelRequest: boolean,
): Promise<void> {
  const cacheDir = join(ctx.stateDir, "cache");
  const logsDir = join(ctx.stateDir, "logs");
  const dataDir = join(ctx.stateDir, "data");
  const sessionDir = join(ctx.stateDir, "sessions", "acceptance");
  for (const path of [cacheDir, logsDir, dataDir, sessionDir])
    mkdirSync(path, { recursive: true, mode: 0o700 });
  const prepared = await prepareAccess(ctx, requestedModel);
  const gov = await openGovernance(ctx, prepared, false);
  const { runtime } = await startGoverned(ctx, prepared, sessionDir, gov);
  try {
    const { resourceLoader } = runtime.services;
    const sessionManager = runtime.session.sessionManager;
    const resumed =
      !!sessionManager.getSessionFile() &&
      existsSync(sessionManager.getSessionFile() ?? "");
    const toolResult = await createReadTool(ctx.distributionDir).execute(
      "piship-smoke",
      { path: "piship.yaml" },
    );
    const toolText = toolResult.content.find((item) => item.type === "text");
    if (toolText?.type !== "text" || !toolText.text.includes("schema: piship/"))
      throw new Error("Pi safe read tool failed on the packaged manifest");
    let modelRequest: Record<string, unknown> | undefined;
    if (withModelRequest) {
      if (!runtime.session.model)
        throw new PiShipError(
          "MODEL_UNAVAILABLE",
          "No model is selected for the acceptance request",
        );
      await runtime.session.prompt(SMOKE_PROMPT);
      const messages = runtime.session.messages;
      const last = messages.at(-1) as
        | { role?: string; stopReason?: string; errorMessage?: string }
        | undefined;
      modelRequest = {
        model: `${runtime.session.model.provider}/${runtime.session.model.id}`,
        text: runtime.session.getLastAssistantText() ?? "",
        stopReason: last?.stopReason ?? null,
        ...(last?.errorMessage ? { error: redact(last.errorMessage) } : {}),
        toolResults: messages.filter(
          (message) => (message as { role?: string }).role === "toolResult",
        ).length,
      };
    } else if (!resumed)
      sessionManager.appendMessage({
        role: "assistant",
        content: [
          {
            type: "text",
            text: "PiShip local acceptance session; no model call.",
          },
        ],
        api: "piship-local-smoke",
        provider: "piship",
        model: "none",
        usage: {
          input: 0,
          output: 0,
          cacheRead: 0,
          cacheWrite: 0,
          totalTokens: 0,
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
        },
        stopReason: "stop",
        timestamp: Date.now(),
      });
    const access = accessSummary(
      prepared,
      ctx,
      runtime.session.model
        ? `${runtime.session.model.provider}/${runtime.session.model.id}`
        : undefined,
    );
    ctx.out(
      JSON.stringify({
        initialized: true,
        piVersion: VERSION,
        sessionId: sessionManager.getSessionId(),
        resumed,
        safeTool: "read",
        agentDir: ctx.agentDir,
        cacheDir,
        logsDir,
        dataDir,
        sessionDir,
        instructions: resourceLoader
          .getAgentsFiles()
          .agentsFiles.map((item) => item.path),
        skills: resourceLoader.getSkills().skills.map((item) => item.name),
        extensions: resourceLoader
          .getExtensions()
          .extensions.filter((item) => !item.path.startsWith("<inline")).length,
        extensionPaths: resourceLoader
          .getExtensions()
          .extensions.map((item) => item.path)
          .filter((path) => !path.startsWith("<inline")),
        prompts: resourceLoader.getPrompts().prompts.map((item) => item.name),
        themes: resourceLoader.getThemes().themes.map((item) => item.name),
        ...(access ? { access } : {}),
        ...(gov ? { governance: governanceSummary(gov) } : {}),
        ...(modelRequest ? { modelRequest } : {}),
      }),
    );
    if (
      modelRequest &&
      (modelRequest.stopReason === "error" ||
        modelRequest.stopReason === "aborted")
    )
      throw new PiShipError(
        "GATEWAY_PROTOCOL_ERROR",
        `The acceptance model request failed: ${String(modelRequest.error ?? modelRequest.stopReason)}`,
      );
  } finally {
    await runtime.dispose();
    await gov?.close();
    publishContext(null);
  }
}

async function startGoverned(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  sessionDir: string,
  gov: GovernanceSession | null,
) {
  try {
    return await startRuntime(ctx, prepared, sessionDir, gov);
  } catch (error) {
    await gov?.close();
    throw error;
  }
}

function governanceSummary(gov: GovernanceSession) {
  return {
    policy: gov.policyId,
    project: { origin: gov.project.origin },
    sandbox: {
      level: gov.sandbox.report.level,
      adapter: gov.sandbox.report.adapter,
      planes: gov.sandbox.report.planes,
      network: gov.sandbox.report.network,
    },
    workflowMode: gov.workflowMode,
    capabilities: gov.capabilities.map((state) => ({
      name: state.name,
      effective: state.axes.effective.value,
      ...(state.axes.effective.value === "no"
        ? { reason: state.axes.effective.reason }
        : {}),
    })),
    resources: gov.resources.map((item) => ({
      kind: item.kind,
      class: item.class,
      path: item.path,
      loaded: item.loaded,
      ...(item.loaded ? {} : { reason: item.reason }),
    })),
    mcp: gov.mcpReports.map((report) => ({
      id: report.id,
      state: report.state,
      tools: report.tools,
      ...(report.reason ? { reason: report.reason } : {}),
    })),
    audit: gov.audit.status().state,
  };
}

async function runInteractive(
  ctx: LaunchContext,
  requestedModel: string | undefined,
): Promise<void> {
  const sessionDir = join(ctx.stateDir, "sessions", "user");
  for (const name of ["cache", "logs", "data"])
    mkdirSync(join(ctx.stateDir, name), { recursive: true, mode: 0o700 });
  mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  const prepared = await prepareAccess(ctx, requestedModel);
  for (const notice of prepared.activated?.notices ?? [])
    ctx.err(`Notice: ${notice}`);
  const gov = await openGovernance(
    ctx,
    prepared,
    !!process.stdin.isTTY && !!process.stderr.isTTY,
  );
  const { runtime, theme } = await startGoverned(
    ctx,
    prepared,
    sessionDir,
    gov,
  );
  try {
    await new InteractiveMode(
      runtime,
      theme ? { initialThemeSetting: theme } : {},
    ).run();
  } finally {
    await runtime.dispose();
    await gov?.close();
    publishContext(null);
  }
}

async function runLogin(ctx: LaunchContext): Promise<void> {
  if (
    !ctx.metadata.access ||
    ctx.metadata.access.credential.provider === "pi-native"
  )
    throw new PiShipError(
      "POLICY_DENIED",
      "This distribution delegates authentication to Pi; start it and use Pi's /login inside the session",
    );
  assertTlsVerificationEnabled();
  const access = openAccess(ctx);
  if (ctx.mode === "managed")
    sanitizeManagedEnvironment(
      process.env,
      access.network,
      ctx.metadata.access.variables,
    );
  applyProcessNetworkPolicy(access.network);
  const result = await access.login({
    openUrl: (url) => {
      ctx.err(`Open this URL in your browser to sign in:\n${url}`);
      openBrowser(url);
    },
    readSecret: readSecretInput,
  });
  await auditAccess(ctx, access, result.identity?.subject ?? null, [
    ...(result.identity ? (["identity.login"] as const) : []),
    ...(result.credential.state === "delegated"
      ? []
      : (["credential.acquire"] as const)),
  ]);
  const identity = result.identity
    ? `Signed in as ${result.identity.displayName ?? result.identity.subject} (${result.identity.issuer}).`
    : "No identity provider is configured.";
  const credential =
    result.credential.state === "delegated"
      ? `Credential: ${access.credentialMode} (no stored secret).`
      : `Credential: ${access.credentialMode} stored in ${access.store?.description ?? "no store"}${result.credential.metadata?.expires_at ? `; expires ${result.credential.metadata.expires_at}` : ""}.`;
  ctx.out(`${identity}\n${credential}`);
  for (const notice of result.notices) ctx.err(`Notice: ${notice}`);
  if (access.store?.kind === "file")
    ctx.err(
      "Warning: credentials use the explicitly enabled plaintext file fallback, not platform secure storage.",
    );
}

async function runLogout(ctx: LaunchContext): Promise<void> {
  if (
    !ctx.metadata.access ||
    ctx.metadata.access.credential.provider === "pi-native"
  )
    throw new PiShipError(
      "POLICY_DENIED",
      "This distribution delegates authentication to Pi; use Pi's /logout inside the session",
    );
  assertTlsVerificationEnabled();
  const access = openAccess(ctx);
  if (ctx.mode === "managed")
    sanitizeManagedEnvironment(
      process.env,
      access.network,
      ctx.metadata.access.variables,
    );
  applyProcessNetworkPolicy(access.network);
  const signedIn = (await access.status().catch(() => undefined))?.identity;
  const problems = await access.logout();
  await auditAccess(ctx, access, signedIn?.subject ?? null, [
    "identity.logout",
    "credential.revoke",
  ]);
  ctx.out(
    `Signed out of ${ctx.metadata.app.name}. Local runtime and identity credentials were cleared; sessions were preserved.`,
  );
  for (const problem of problems) ctx.err(`Warning: ${problem}`);
}

/** Governance settings as `config explain` rows; all distribution-enforced. */
function governanceRows(ctx: LaunchContext) {
  const lock = governedLock(ctx);
  if (!lock) return [];
  const { policy, mcp, sandbox, audit } = lock.governance.manifest;
  const row = (key: string, value: unknown, note?: string) => ({
    key,
    value,
    source: "distribution-enforced" as const,
    overridable: false,
    ...(note ? { note } : {}),
  });
  return [
    row(
      "policy",
      `${policy.id}@${policy.version}`,
      `default ${policy.default}; ${policy.enforced.length} enforced and ${policy.defaults.length} default rule(s); user rules in config/policy.json may only relax defaults`,
    ),
    row("mcp.mode", mcp.mode, `${mcp.servers.length} server(s)`),
    row(
      "sandbox.required",
      sandbox.required,
      "run doctor for the effective containment level",
    ),
    row("sandbox.network", sandbox.network.mode),
    row(
      "audit.sinks",
      audit.enabled
        ? audit.sinks.map(
            (sink) =>
              `${sink.id} (${sink.type}${sink.required ? ", required" : ""})`,
          )
        : [],
      audit.enabled
        ? "metadata only unless content capture is opted in"
        : "disabled",
    ),
  ];
}

async function runConfig(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  const [action, key, ...rest] = args;
  const paths = accessStatePaths(ctx.stateDir);
  if (action === "explain") {
    const rows = [
      ...(await explainConfiguration({
        app: ctx.metadata.app,
        mode: ctx.mode,
        access: ctx.metadata.access,
        stateDir: ctx.stateDir,
        distributionDir: ctx.distributionDir,
      })),
      ...governanceRows(ctx),
    ];
    if (key === "--json") ctx.out(redact(JSON.stringify(rows, null, 2)));
    else ctx.out(formatExplanation(ctx.metadata.app.name, rows));
    return;
  }
  if (
    (action === "set" && key && rest.length === 1) ||
    (action === "unset" && key && rest.length === 0)
  ) {
    setPreference(
      paths.preferences,
      ctx.metadata.access,
      ctx.metadata.app.theme,
      key,
      action === "set" ? rest[0] : undefined,
    );
    ctx.out(
      action === "set"
        ? `Set ${key} (user preference).`
        : `Removed ${key} (user preference).`,
    );
    return;
  }
  throw new PiShipError(
    "CONFIG_INVALID",
    `Usage: ${ctx.metadata.app.command} config explain [--json] | config set <key> <value> | config unset <key>`,
  );
}

async function runModels(ctx: LaunchContext): Promise<void> {
  const prepared = await prepareAccess(ctx, undefined);
  if (!prepared.activated || prepared.activated.runtime.kind === "pi-native") {
    ctx.out(
      "Pi-native inference: use /model inside the session to choose from Pi's configured providers.",
    );
    const allowed = ctx.metadata.access?.models.allowed ?? [];
    if (allowed.length) ctx.out(`Owner allowlist: ${allowed.join(", ")}`);
    return;
  }
  const { activated } = prepared;
  for (const model of activated.models) {
    const allowed = activated.config.allowedModels.includes(model.id);
    const marker = model.id === activated.selectedModel ? "*" : " ";
    ctx.out(
      `${marker} ${model.id.padEnd(28)} ${model.name.padEnd(24)} ${allowed && model.availability.available ? "available" : `unavailable (${model.availability.reason ?? "excluded"})`}  ctx=${model.capabilities.contextWindow ?? "?"} tools=${model.capabilities.tools ? "yes" : "no"} tags=${model.policyTags.join(",") || "-"}`,
    );
  }
}

function requireGovernedLock(
  ctx: LaunchContext,
  command: string,
): GovernedLock {
  const lock = governedLock(ctx);
  if (!lock)
    throw new PiShipError(
      "CONFIG_INVALID",
      `${ctx.metadata.app.command} ${command} needs a piship/v1alpha3 distribution`,
    );
  return lock;
}

async function runPolicy(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  const json = args.includes("--json");
  const words = args.filter((arg) => arg !== "--json");
  if (words[0] !== "explain" || words.length !== 3)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Usage: ${ctx.metadata.app.command} policy explain <action> <resource> [--json]`,
    );
  const [, requested, target] = words as [string, string, string];
  if (!(POLICY_ACTIONS as readonly string[]).includes(requested))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Unknown policy action ${requested}. Actions: ${POLICY_ACTIONS.join(", ")}`,
    );
  const lock = requireGovernedLock(ctx, "policy explain");
  const inspection = await inspectGovernance(
    governanceOptions(ctx, lock, null, false),
  );
  // Paths are explained as tools see them: `~` is the home directory and
  // relative paths are resolved against the working directory.
  const resource = requested.startsWith("filesystem.")
    ? target === "~" || target.startsWith("~/")
      ? join(homedir(), target.slice(2))
      : resolve(target)
    : target;
  const explanation = inspection.engine.explain({
    action: requested as PolicyAction,
    resource,
  });
  ctx.out(
    json
      ? redact(JSON.stringify(decisionToJSON(explanation), null, 2))
      : redact(formatDecision(explanation)),
  );
}

async function runCapabilities(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  if (args.some((arg) => arg !== "--json"))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Usage: ${ctx.metadata.app.command} capabilities [--json]`,
    );
  const lock = requireGovernedLock(ctx, "capabilities");
  const inspection = await inspectGovernance(
    governanceOptions(ctx, lock, null, false),
  );
  ctx.out(
    args.includes("--json")
      ? JSON.stringify(inspection.capabilities, null, 2)
      : formatCapabilities(inspection.capabilities),
  );
}

type DoctorLine = (label: string, value: string) => void;

async function governanceDoctor(
  ctx: LaunchContext,
  lines: string[],
  ok: DoctorLine,
  bad: DoctorLine,
  warn: DoctorLine,
): Promise<void> {
  const lock = governedLock(ctx);
  if (!lock) return;
  const manifest = lock.governance.manifest;
  const options = governanceOptions(ctx, lock, null, false);
  let inspection: Awaited<ReturnType<typeof inspectGovernance>> | undefined;
  lines.push("", "Policy");
  try {
    inspection = await inspectGovernance(options);
    const policy = manifest.policy;
    ok("policy", `${inspection.engine.id}; default ${policy.default}`);
    ok(
      "rules",
      `${policy.enforced.length} enforced, ${policy.defaults.length} defaults${policy.adapter ? ", team adapter" : ""}`,
    );
    for (const diagnostic of inspection.engine.diagnostics)
      warn(diagnostic.source, diagnostic.message);
  } catch (error) {
    bad("policy", formatError(error));
  }
  if (!inspection) return;
  lines.push("", "Project");
  ok("origin", `${inspection.project.origin} (${inspection.project.root})`);
  for (const candidate of inspection.candidates) {
    if (candidate.dimension === "restrictions") continue;
    const line = `${candidate.path}: ${candidate.effect} (${candidate.reason})`;
    if (candidate.effect === "deny") warn(candidate.kind, line);
    else ok(candidate.kind, line);
  }
  lines.push("", "Resources");
  for (const item of inspection.resources) {
    const label = `${item.class} ${item.kind}`;
    const detail = `${item.path}${item.integrity === "verified" ? " (integrity verified)" : ""}`;
    if (item.loaded) ok(label, detail);
    else if (item.class === "certified" && item.integrity !== "verified")
      bad(label, `${detail}: ${item.reason}`);
    else warn(label, `${detail}: not loaded, ${item.reason}`);
  }
  lines.push("", "Capabilities");
  for (const state of inspection.capabilities) {
    const effective = state.axes.effective;
    const provider = state.provider ? ` via ${state.provider}` : "";
    if (effective.value === "yes") ok(state.name, `effective${provider}`);
    else if (state.axes.enabled.value === "no")
      ok(state.name, `disabled${provider}`);
    else bad(state.name, `not effective${provider}: ${effective.reason ?? ""}`);
  }
  lines.push("", "Sandbox");
  const report = inspection.sandbox;
  const containment = `${report.level} (${report.adapter}${report.planes.length ? `: ${report.planes.join(", ")}` : ""})`;
  if (report.level === "enforced") ok("containment", containment);
  else if (report.required)
    bad("containment", `${containment}: ${report.reason ?? "required"}`);
  else
    warn(
      "containment",
      `${containment}${report.reason ? `: ${report.reason}` : ""}`,
    );
  ok("network", report.network);
  ok(
    "scope",
    "tool subprocesses and MCP stdio servers; Pi and in-process extensions are not contained",
  );
  for (const warning of report.warnings) warn("sandbox", warning);
  lines.push("", "MCP and audit");
  let session: GovernanceSession | undefined;
  try {
    session = await GovernanceSession.open(options);
    for (const server of session.mcpReports) {
      const label = `mcp ${server.id}`;
      const detail = `${server.state} (${server.transport}${server.tools.length ? `; ${server.tools.length} tool(s)` : ""})${server.reason ? `: ${server.reason}` : ""}`;
      if (server.state === "healthy") ok(label, detail);
      else if (server.state === "denied") warn(label, detail);
      else if (server.required) bad(label, detail);
      else warn(label, detail);
    }
    if (!manifest.mcp.servers.length) ok("mcp", "no servers declared");
    await session.audit.flush();
    const status = session.audit.status();
    for (const line of describeAuditStatus(status))
      if (status.state === "failed") bad("audit", line);
      else if (status.state === "degraded") warn("audit", line);
      else ok("audit", line);
  } catch (error) {
    bad("launch controls", formatError(error));
  } finally {
    await session?.close();
  }
  const metrics = LocalMetrics.load(ctx.stateDir).snapshot();
  const denials = Object.values(metrics.policyDenials).reduce(
    (sum, count) => sum + count,
    0,
  );
  const failures = Object.entries(metrics.startupFailures);
  ok(
    "local metrics",
    `${denials} policy denial(s)${failures.length ? `; startup failures ${failures.map(([code, count]) => `${code}=${count}`).join(", ")}` : ""}`,
  );
}

/** The installed receipt when this payload is the active installed release. */
function installedHere(ctx: LaunchContext) {
  try {
    const receipt = readInstallReceipt(ctx.metadata.app.id);
    // Compare real paths: on macOS the install home may sit behind /var.
    return realpathSync(receipt.payload) === realpathSync(ctx.distributionDir)
      ? receipt
      : null;
  } catch {
    return null;
  }
}

function requireInstalled(ctx: LaunchContext, command: string): void {
  if (!installedHere(ctx))
    throw new PiShipError(
      "CONFIG_INVALID",
      `${command} works on an installed distribution; this ${ctx.metadata.app.name} runs from ${ctx.distributionDir}. Install it with piship install first`,
    );
}

/** Deletes secret-store entries for credentials a target release cannot read. */
function secretDeleter(ctx: LaunchContext) {
  if (!ctx.metadata.access) return undefined;
  try {
    const store = openAccess(ctx).store;
    return store ? (ref: string) => store.delete(ref) : undefined;
  } catch {
    return undefined;
  }
}

/** runtime.update and runtime.rollback at their activation boundary; best effort. */
async function auditLifecycle(
  ctx: LaunchContext,
  event: "runtime.update" | "runtime.rollback",
  decision: "allowed" | "denied",
  detail: Record<string, string>,
): Promise<void> {
  const lock = governedLock(ctx);
  if (!lock) return;
  try {
    let network = DEFAULT_NETWORK_POLICY;
    try {
      if (ctx.metadata.access) network = openAccess(ctx).network;
    } catch {
      // The default policy still applies to an HTTP sink.
    }
    const log = await AuditLog.open({
      config: lock.governance.manifest.audit,
      distribution: lock.app.id,
      stateDir: ctx.stateDir,
      fetch: createManagedFetch(network, "audit"),
      resolveUrl: (template) =>
        resolveTemplate(
          "audit.sinks.url",
          template,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
    });
    log.emit({
      event,
      user: null,
      session: null,
      resource: ctx.metadata.app.id,
      decision,
      detail,
    });
    await log.close();
  } catch (error) {
    ctx.err(`Warning: audit events were not recorded: ${formatError(error)}`);
  }
}

function recordLifecycleMetric(
  ctx: LaunchContext,
  kind: "update" | "check" | "rollback",
  outcome: string,
): void {
  try {
    const metrics = LocalMetrics.load(ctx.stateDir);
    metrics.recordLifecycle(kind, outcome);
    metrics.save();
  } catch {
    // Local metrics never block a lifecycle operation.
  }
}

/** Host of the declared update source, when it resolves to a URL. */
function updateSourceHost(ctx: LaunchContext): string | null {
  const template = ctx.metadata.updates?.source;
  if (!template) return null;
  try {
    const source = resolveTemplate(
      "updates.source",
      template,
      ctx.metadata.access?.variables ?? [],
      process.env,
    );
    return /^https?:\/\//.test(source) ? new URL(source).hostname : null;
  } catch {
    return null;
  }
}

async function runUpdate(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  const { app } = ctx.metadata;
  const usage = `Usage: ${app.command} update [--channel <name>] [--from <dir|url>] [--check] [--accept-review]`;
  const options: { channel?: string; source?: string } = {};
  const flags = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];
    if ((arg === "--channel" || arg === "--from") && value !== undefined) {
      if (arg === "--channel") options.channel = value;
      else options.source = value;
      index += 1;
    } else if (arg === "--check" || arg === "--accept-review") flags.add(arg);
    else throw new PiShipError("CONFIG_INVALID", usage);
  }
  requireInstalled(ctx, `${app.command} update`);
  const check = flags.has("--check");
  const deleteSecret = secretDeleter(ctx);
  let network = DEFAULT_NETWORK_POLICY;
  try {
    if (ctx.metadata.access) network = openAccess(ctx).network;
  } catch {
    // Proxy and CA settings default when access cannot be resolved.
  }
  // Proxy, CA, and TLS policy apply. Only the update host the distribution
  // declares is added to the allowed hosts; a --from URL gets no exception.
  const declaredHost = updateSourceHost(ctx);
  const fetcher = createManagedFetch(
    {
      ...network,
      allowHosts: declaredHost
        ? [...network.allowHosts, declaredHost]
        : network.allowHosts,
    },
    "update",
  ) as typeof fetch;
  let result: Awaited<ReturnType<typeof updateDistribution>>;
  try {
    result = await updateDistribution(app.id, {
      ...options,
      check,
      acceptReview: flags.has("--accept-review"),
      fetcher,
      ...(deleteSecret ? { deleteSecret } : {}),
    });
  } catch (error) {
    const code = error instanceof PiShipError ? error.code : "UPDATE_FAILED";
    recordLifecycleMetric(ctx, check ? "check" : "update", code);
    if (!check)
      await auditLifecycle(ctx, "runtime.update", "denied", {
        from: app.version,
        code,
      });
    throw error;
  }
  recordLifecycleMetric(ctx, check ? "check" : "update", "ok");
  for (const notice of result.notices) ctx.err(`Notice: ${notice}`);
  if (result.status === "up-to-date") {
    ctx.out(
      `${app.name} ${result.from} is up to date on the ${result.channel} channel.`,
    );
    return;
  }
  if (result.migration) ctx.out(formatMigrationReport(result.migration));
  if (result.status === "available") {
    ctx.out(
      `${app.name} ${result.to} is available on the ${result.channel} channel (signed by ${result.keyId}); run ${app.command} update to install it.`,
    );
    return;
  }
  await auditLifecycle(ctx, "runtime.update", "allowed", {
    from: result.from,
    to: result.to ?? "",
    channel: result.channel,
    key: result.keyId ?? "",
  });
  ctx.out(
    `Updated ${app.name} ${result.from} -> ${result.to} (${result.channel}, signed by ${result.keyId}). ${result.from} is kept for ${app.command} rollback; sessions and settings were preserved.`,
  );
}

async function runRollback(ctx: LaunchContext): Promise<void> {
  const { app } = ctx.metadata;
  requireInstalled(ctx, `${app.command} rollback`);
  const deleteSecret = secretDeleter(ctx);
  let result: Awaited<ReturnType<typeof rollbackDistribution>>;
  try {
    result = await rollbackDistribution(app.id, {
      ...(deleteSecret ? { deleteSecret } : {}),
    });
  } catch (error) {
    const code = error instanceof PiShipError ? error.code : "ROLLBACK_FAILED";
    recordLifecycleMetric(ctx, "rollback", code);
    await auditLifecycle(ctx, "runtime.rollback", "denied", {
      from: app.version,
      code,
    });
    throw error;
  }
  recordLifecycleMetric(ctx, "rollback", "ok");
  await auditLifecycle(ctx, "runtime.rollback", "allowed", {
    from: result.from,
    to: result.to,
  });
  for (const notice of result.notices) ctx.err(`Notice: ${notice}`);
  ctx.out(
    `Rolled back ${app.name} ${result.from} -> ${result.to}. Sessions and settings were preserved; credentials were not restored.`,
  );
}

/** Supply chain and update sections of doctor. */
function lifecycleDoctor(
  ctx: LaunchContext,
  lines: string[],
  ok: DoctorLine,
  warn: DoctorLine,
): void {
  const { metadata } = ctx;
  lines.push("", "Supply Chain");
  ok("manifest", `verified (${metadata.manifest.schema})`);
  ok("lockfile", `verified (${metadata.schema})`);
  ok("integrity", "payload inventory verified at launch");
  const status = lifecycleStatus(metadata.app.id, metadata);
  const here = installedHere(ctx);
  const active = here?.releases.find((item) => item.version === here.active);
  if (active?.release)
    ok(
      "release",
      `verified ${active.release.target} artifact (${active.release.channel})`,
    );
  else if (here)
    warn("release", "installed from a payload directory, not a release");
  lines.push("", "Update");
  if (!here) {
    warn("installation", "not installed; running from a build directory");
    return;
  }
  if (!status.tracked) {
    warn(
      "installation",
      "installed without release tracking; reinstall to enable update and rollback",
    );
    return;
  }
  ok("active", status.active ?? metadata.app.version);
  if (!metadata.updates) {
    warn("updates", `not configured (${metadata.manifest.schema})`);
  } else {
    ok(
      "channel",
      `${status.channel} (allowed: ${(status.channels ?? []).join(", ")})`,
    );
    if (status.source) ok("source", status.source);
    else warn("source", "none declared; update needs --from");
    if (status.trustedKeys) ok("trusted keys", String(status.trustedKeys));
    else warn("trusted keys", "none; updates cannot be verified");
  }
  if (status.previous) ok("rollback", `${status.previous} retained`);
  else ok("rollback", "no retained release");
  if (status.lastCheck)
    ok("last check", `${status.lastCheck.result} (${status.lastCheck.time})`);
  if (status.leftovers.length)
    warn(
      "interrupted",
      `${status.leftovers.length} leftover item(s); cleaned by the next update or rollback`,
    );
  const counts = LocalMetrics.load(ctx.stateDir).snapshot().lifecycle ?? {};
  if (Object.keys(counts).length)
    ok(
      "lifecycle metrics",
      Object.entries(counts)
        .map(([key, count]) => `${key}=${count}`)
        .join(", "),
    );
}

async function runDoctor(ctx: LaunchContext): Promise<void> {
  const lines: string[] = [];
  let failed = false;
  const ok = (label: string, value: string) =>
    lines.push(`  ✓ ${label.padEnd(20)} ${value}`);
  const bad = (label: string, value: string) => {
    failed = true;
    lines.push(`  ✗ ${label.padEnd(20)} ${redact(value)}`);
  };
  const warn = (label: string, value: string) =>
    lines.push(`  ! ${label.padEnd(20)} ${redact(value)}`);
  const { app } = ctx.metadata;
  lines.push(`${app.name} Doctor`, "", "Distribution");
  ok(app.name, `${app.version} (${ctx.mode})`);
  ok("PiShip", ctx.metadata.runtime.pishipVersion);
  ok("Pi", VERSION);
  lifecycleDoctor(ctx, lines, ok, warn);
  if (!ctx.metadata.access) {
    lines.push("", "Access");
    ok("mode", "personal Pi-native (no identity; Pi auth in isolated state)");
    await governanceDoctor(ctx, lines, ok, bad, warn);
    ctx.out(lines.join("\n"));
    if (failed)
      throw new PiShipError(
        "CONFIG_UNAVAILABLE",
        `${app.name} doctor found problems`,
      );
    return;
  }
  const access = ctx.metadata.access;
  // Checked before the managed environment is sanitized, which removes the
  // variable; a real launch refuses in this state, so doctor must too.
  let tlsError: unknown;
  try {
    assertTlsVerificationEnabled();
  } catch (error) {
    tlsError = error;
  }
  let opened: DistributionAccess | undefined;
  try {
    opened = openAccess(ctx);
    if (ctx.mode === "managed")
      sanitizeManagedEnvironment(process.env, opened.network, access.variables);
  } catch (error) {
    bad("configuration", formatError(error));
  }
  lines.push("", "Identity");
  if (access.identity.mode === "none") ok("mode", "none");
  let activated: ActivatedAccess | undefined;
  if (opened) {
    const status = await opened.status().catch(() => undefined);
    if (access.identity.mode !== "none") {
      if (status?.identity) {
        ok(
          "authenticated",
          status.identity.displayName ?? status.identity.subject,
        );
        ok("issuer", status.identity.issuer);
      } else bad("authenticated", `not signed in; run ${app.command} login`);
    }
    lines.push("Credential");
    ok("provider", access.credential.provider);
    if (opened.store) {
      if (opened.store.kind === "file")
        warn("secret store", opened.store.description);
      else ok("secret store", opened.store.description);
    }
    if (status?.credential.state === "valid")
      ok(
        "valid",
        status.credential.remainingSeconds === undefined
          ? "no expiry"
          : `${Math.floor(status.credential.remainingSeconds / 60)}m remaining`,
      );
    else if (status?.credential.state === "expiring")
      warn(
        "valid",
        `expiring in ${status.credential.remainingSeconds ?? 0}s; refresh on next use`,
      );
    else if (status?.credential.state === "delegated")
      ok("state", "delegated (no PiShip secret)");
    else if (status?.credential.state === "rejected")
      warn("state", "rejected by the gateway; renewed on next use");
    else
      bad(
        "state",
        `${status?.credential.state ?? "unknown"}; run ${app.command} login`,
      );
    lines.push("", "Inference");
    if (tlsError) bad("activation", formatError(tlsError));
    else
      try {
        applyProcessNetworkPolicy(opened.network);
        activated = await opened.activate();
        ok("provider", access.inference.provider);
        if (activated.runtime.kind === "managed-endpoint") {
          const inference = opened.inferenceProvider() as {
            probe?: () => Promise<string[]>;
          };
          if (inference.probe)
            try {
              const listed = await inference.probe();
              ok("gateway", `reachable (${listed.length} listed)`);
            } catch (error) {
              bad("gateway", formatError(error));
            }
        }
        ok(
          "models",
          `${activated.config.allowedModels.length} allowed; default ${activated.selectedModel ?? "Pi default"}`,
        );
      } catch (error) {
        bad("activation", formatError(error));
      }
  }
  lines.push("", "Security");
  if (tlsError) bad("TLS verification", "DISABLED in environment");
  else ok("TLS verification", "on");
  ok(
    "public fallback",
    access.network.publicFallback === "deny"
      ? "denied"
      : "allowed (personal owner policy)",
  );
  ok(
    "private-only",
    access.network.privateOnly
      ? `on (${opened?.network.allowHosts.join(", ") ?? ""})`
      : "off",
  );
  ok(
    "proxy environment",
    access.network.proxy.inheritEnvironment ? "inherited" : "ignored",
  );
  ok("enterprise CA", `${access.network.tls.additionalCA.length} bundle(s)`);
  if (ctx.mode === "managed")
    ok("ambient credentials", "removed from the managed runtime environment");
  await governanceDoctor(ctx, lines, ok, bad, warn);
  ctx.out(lines.join("\n"));
  if (failed)
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `${app.name} doctor found problems`,
    );
}

/** Starts Pi's real SDK/runtime and the branded management commands. */
export async function launchPiDistribution(
  options: LaunchOptions,
): Promise<void> {
  const { metadata } = options;
  if (
    metadata.runtime.package !== "@earendil-works/pi-coding-agent" ||
    metadata.runtime.version !== PINNED_PI_VERSION ||
    VERSION !== PINNED_PI_VERSION
  )
    throw new Error(
      "Built Pi metadata does not match the pinned upstream runtime",
    );
  let args = [...options.args];
  let requestedModel: string | undefined;
  if (args[0] === "--model") {
    requestedModel = args[1];
    if (!requestedModel)
      throw new PiShipError("CONFIG_INVALID", "--model needs a model id");
    args = args.slice(2);
  }
  const stateDir = runtimeStateDirectory({ value: metadata.app.id });
  const agentDir = join(stateDir, "agent");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(agentDir, { recursive: true, mode: 0o700 });
  const ctx: LaunchContext = {
    metadata,
    distributionDir: resolve(options.distributionDir),
    stateDir,
    agentDir,
    mode: metadata.deployment.mode,
    out: (message) => console.log(message),
    err: (message) => console.error(message),
  };
  const [command, ...rest] = args;
  if (
    !requestedModel &&
    args.length === 1 &&
    (command === "--version" || command === "version")
  ) {
    ctx.out(
      `${metadata.app.name} ${metadata.app.version}\nPiShip ${metadata.runtime.pishipVersion}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  if (!requestedModel && args.length === 1 && command === "--help") {
    const governanceHelp = metadata.governance
      ? "\n  policy explain <action> <resource> [--json] | capabilities [--json]"
      : "";
    const managedHelp = metadata.access
      ? `\n\nCommands:\n  login | logout | doctor | models | version\n  update [--channel <name>] [--from <dir|url>] [--check] | rollback\n  config explain [--json] | config set <key> <value> | config unset <key>${governanceHelp}\n  [--model <id>] [--smoke | --smoke-model]`
      : metadata.governance
        ? `\n\nCommands:\n  doctor | version | update [--check] | rollback${governanceHelp}\n  [--smoke]`
        : "\n\nCommands:\n  doctor | version";
    ctx.out(
      `${metadata.app.banner ?? metadata.app.name}\n\n${metadata.app.command} [--help|--version|--smoke]${managedHelp}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  if (!requestedModel) {
    if (args.length === 1 && command === "login") return runLogin(ctx);
    if (args.length === 1 && command === "logout") return runLogout(ctx);
    if (args.length === 1 && command === "doctor") return runDoctor(ctx);
    if (args.length === 1 && command === "models") return runModels(ctx);
    if (command === "update") return runUpdate(ctx, rest);
    if (args.length === 1 && command === "rollback") return runRollback(ctx);
    if (command === "config") return runConfig(ctx, rest);
    if (command === "policy") return runPolicy(ctx, rest);
    if (command === "capabilities") return runCapabilities(ctx, rest);
  }
  if (
    args.length === 1 &&
    (command === "--smoke" || command === "--smoke-model")
  )
    return runSmoke(ctx, requestedModel, command === "--smoke-model");
  if (args.length > 0)
    throw new Error(`Unknown branded command option: ${args.join(" ")}`);
  return runInteractive(ctx, requestedModel);
}
