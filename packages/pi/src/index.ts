/** The only Pi package integration boundary. All imports use the public package entrypoint. */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
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
} from "@earendil-works/pi-coding-agent";
import { runtimeStateDirectory, type DistributionLock } from "@piship/core";

export const PINNED_PI_VERSION = "0.87.1" as const;
export type PiVersion = typeof PINNED_PI_VERSION;
export type PiSessionFactory = typeof createAgentSession;
export interface LaunchOptions {
  readonly distributionDir: string;
  readonly metadata: DistributionLock;
  readonly args: readonly string[];
}

/** Starts Pi's real SDK/runtime. --smoke verifies initialization without a model call. */
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
  if (options.args.length === 1 && options.args[0] === "--version") {
    console.log(
      `${metadata.app.name} ${metadata.app.version}\nPiShip ${metadata.runtime.pishipVersion}\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  if (options.args.length === 1 && options.args[0] === "--help") {
    console.log(
      `${metadata.app.banner ?? metadata.app.name}\n\n${metadata.app.command} [--help|--version|--smoke]\nPi ${VERSION} by Earendil Works`,
    );
    return;
  }
  const stateDir = runtimeStateDirectory({ value: metadata.app.id });
  const agentDir = join(stateDir, "agent");
  const cacheDir = join(stateDir, "cache");
  const logsDir = join(stateDir, "logs");
  const dataDir = join(stateDir, "data");
  const smoke = options.args.length === 1 && options.args[0] === "--smoke";
  const sessionDir = join(stateDir, "sessions", smoke ? "acceptance" : "user");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  for (const path of [agentDir, cacheDir, logsDir, dataDir, sessionDir])
    mkdirSync(path, { recursive: true, mode: 0o700 });
  const distributionDir = resolve(options.distributionDir);
  const resourceDir = join(distributionDir, "resources");
  for (const resource of metadata.resources) {
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
  const resourcePaths = (kind: keyof DistributionLock["declared"]) =>
    metadata.declared[kind].map((path) => {
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
  const instructions = resourcePaths("instructions").map((path) => ({
    path,
    content: readFileSync(path, "utf8"),
  }));
  const createRuntime: CreateAgentSessionRuntimeFactory = async ({
    cwd,
    sessionManager,
  }) => {
    const settingsManager = SettingsManager.inMemory();
    const modelRuntime = await ModelRuntime.create({
      authPath: join(agentDir, "auth.json"),
      modelsPath: join(agentDir, "models.json"),
    });
    // Discovery uses the built distribution, never the user's cwd or personal ~/.pi.
    const resourceLoader = new DefaultResourceLoader({
      cwd: distributionDir,
      agentDir,
      settingsManager,
      additionalExtensionPaths: resourcePaths("extensions"),
      additionalSkillPaths: resourcePaths("skills"),
      additionalPromptTemplatePaths: resourcePaths("prompts"),
      additionalThemePaths: resourcePaths("themes"),
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
      metadata.app.theme &&
      !["dark", "light"].includes(metadata.app.theme) &&
      !resourceLoader
        .getThemes()
        .themes.some((item) => item.name === metadata.app.theme)
    )
      throw new Error(`Declared theme is unavailable: ${metadata.app.theme}`);
    const result = await createAgentSession({
      cwd,
      agentDir,
      settingsManager,
      modelRuntime,
      resourceLoader,
      sessionManager,
    });
    const services: AgentSessionServices = {
      cwd,
      agentDir,
      settingsManager,
      modelRuntime,
      resourceLoader,
      diagnostics: [],
    };
    return { ...result, services, diagnostics: [] };
  };
  const runtime = await createAgentSessionRuntime(createRuntime, {
    cwd: process.cwd(),
    agentDir,
    sessionManager: SessionManager.continueRecent(process.cwd(), sessionDir),
  });
  try {
    if (smoke) {
      const { resourceLoader } = runtime.services;
      const sessionManager = runtime.session.sessionManager;
      const resumed =
        !!sessionManager.getSessionFile() &&
        existsSync(sessionManager.getSessionFile() ?? "");
      const toolResult = await createReadTool(distributionDir).execute(
        "piship-smoke",
        { path: "piship.yaml" },
      );
      const toolText = toolResult.content.find((item) => item.type === "text");
      if (
        toolText?.type !== "text" ||
        !toolText.text.includes("piship/v1alpha1")
      )
        throw new Error("Pi safe read tool failed on the packaged manifest");
      if (!resumed)
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
            cost: {
              input: 0,
              output: 0,
              cacheRead: 0,
              cacheWrite: 0,
              total: 0,
            },
          },
          stopReason: "stop",
          timestamp: Date.now(),
        });
      console.log(
        JSON.stringify({
          initialized: true,
          piVersion: VERSION,
          sessionId: sessionManager.getSessionId(),
          resumed,
          safeTool: "read",
          agentDir,
          cacheDir,
          logsDir,
          dataDir,
          sessionDir,
          instructions: resourceLoader
            .getAgentsFiles()
            .agentsFiles.map((item) => item.path),
          skills: resourceLoader.getSkills().skills.map((item) => item.name),
          extensions: resourceLoader.getExtensions().extensions.length,
          extensionPaths: resourceLoader
            .getExtensions()
            .extensions.map((item) => item.path),
          prompts: resourceLoader.getPrompts().prompts.map((item) => item.name),
          themes: resourceLoader.getThemes().themes.map((item) => item.name),
        }),
      );
      return;
    }
    if (options.args.length > 0)
      throw new Error(
        `Unknown branded command option: ${options.args.join(" ")}`,
      );
    await new InteractiveMode(
      runtime,
      metadata.app.theme ? { initialThemeSetting: metadata.app.theme } : {},
    ).run();
  } finally {
    await runtime.dispose();
  }
}
