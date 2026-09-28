/** The only Pi package integration boundary. All imports use the public package entrypoint. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync } from "node:fs";
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
  ENTERPRISE_CONTEXT_SYMBOL,
  type EnterpriseContext,
  PiShipError,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
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
  runtimeStateDirectory,
  setPreference,
} from "@piship/core";
import {
  governModelRuntime,
  isCredentialRejection,
  type GovernedRuntime,
} from "./governance.js";

export {
  governModelRuntime,
  isCredentialRejection,
  type ModelGovernance,
  type GovernedRuntime,
} from "./governance.js";

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
    input: model.capabilities.input.filter(
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
): Promise<{ modelRuntime: ModelRuntime; governed: GovernedRuntime | null }> {
  const { activated, access } = prepared;
  if (!activated || !access || activated.runtime.kind === "pi-native") {
    const modelRuntime = await ModelRuntime.create({
      authPath: join(ctx.agentDir, "auth.json"),
      modelsPath: join(ctx.agentDir, "models.json"),
    });
    const allowed = ctx.metadata.access?.models.allowed ?? [];
    const governed = ctx.metadata.access
      ? governModelRuntime(modelRuntime, {
          kind: "pi-native",
          allowedModelKeys: allowed,
        })
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
  const governed = governModelRuntime(modelRuntime, {
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
  });
  return { modelRuntime, governed };
}

function publishContext(context: EnterpriseContext | null): void {
  const holder = globalThis as unknown as Record<symbol, unknown>;
  if (context) holder[ENTERPRISE_CONTEXT_SYMBOL] = context;
  else delete holder[ENTERPRISE_CONTEXT_SYMBOL];
}

async function startRuntime(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  sessionDir: string,
) {
  verifyBuiltResources(ctx);
  const instructions = resourcePaths(ctx, "instructions").map((path) => ({
    path,
    content: readFileSync(path, "utf8"),
  }));
  const { activated, access } = prepared;
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
    const { modelRuntime, governed } = await createModelRuntime(ctx, prepared);
    governedRef = governed;
    // Discovery uses the built distribution, never the user's cwd or personal ~/.pi.
    const resourceLoader = new DefaultResourceLoader({
      cwd: ctx.distributionDir,
      agentDir: ctx.agentDir,
      settingsManager,
      additionalExtensionPaths: resourcePaths(ctx, "extensions"),
      additionalSkillPaths: resourcePaths(ctx, "skills"),
      additionalPromptTemplatePaths: resourcePaths(ctx, "prompts"),
      additionalThemePaths: resourcePaths(ctx, "themes"),
      ...(ctx.metadata.access
        ? { extensionFactories: [governanceExtension] }
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
  const { runtime } = await startRuntime(ctx, prepared, sessionDir);
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
    publishContext(null);
  }
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
  const { runtime, theme } = await startRuntime(ctx, prepared, sessionDir);
  try {
    await new InteractiveMode(
      runtime,
      theme ? { initialThemeSetting: theme } : {},
    ).run();
  } finally {
    await runtime.dispose();
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
  const problems = await access.logout();
  ctx.out(
    `Signed out of ${ctx.metadata.app.name}. Local runtime and identity credentials were cleared; sessions were preserved.`,
  );
  for (const problem of problems) ctx.err(`Warning: ${problem}`);
}

async function runConfig(
  ctx: LaunchContext,
  args: readonly string[],
): Promise<void> {
  const [action, key, ...rest] = args;
  const paths = accessStatePaths(ctx.stateDir);
  if (action === "explain") {
    const rows = await explainConfiguration({
      app: ctx.metadata.app,
      mode: ctx.mode,
      access: ctx.metadata.access,
      stateDir: ctx.stateDir,
      distributionDir: ctx.distributionDir,
    });
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
  if (!ctx.metadata.access) {
    lines.push("", "Access");
    ok("mode", "personal Pi-native (no identity; Pi auth in isolated state)");
    ctx.out(lines.join("\n"));
    return;
  }
  const access = ctx.metadata.access;
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
  ok(
    "TLS verification",
    process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0"
      ? "DISABLED in environment"
      : "on",
  );
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") failed = true;
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
    const managedHelp = metadata.access
      ? "\n\nCommands:\n  login | logout | doctor | models | version\n  config explain [--json] | config set <key> <value> | config unset <key>\n  [--model <id>] [--smoke | --smoke-model]"
      : "";
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
    if (command === "config") return runConfig(ctx, rest);
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
