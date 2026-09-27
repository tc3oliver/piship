/** The only Pi package integration boundary. All imports use the public package entrypoint. */
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  createAgentSession,
  createAgentSessionRuntime,
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
  const stateDir = runtimeStateDirectory({ value: metadata.app.id });
  const agentDir = join(stateDir, "agent");
  const sessionDir = join(stateDir, "sessions");
  mkdirSync(agentDir, { recursive: true });
  mkdirSync(sessionDir, { recursive: true });
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
      additionalExtensionPaths: metadata.resources
        .filter(
          (resource) =>
            resource.kind === "extensions" &&
            /\.[cm]?[jt]s$/.test(resource.path),
        )
        .map((resource) => join(resourceDir, resource.path)),
      additionalSkillPaths: resourcePaths("skills"),
      additionalPromptTemplatePaths: resourcePaths("prompts"),
      noContextFiles: true,
      agentsFilesOverride: () => ({ agentsFiles: instructions }),
    });
    await resourceLoader.reload();
    const extensionErrors = resourceLoader.getExtensions().errors;
    if (extensionErrors.length)
      throw new Error(
        `Pi extension load failed: ${extensionErrors.map((item) => item.error).join("; ")}`,
      );
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
    sessionManager: SessionManager.create(process.cwd(), sessionDir),
  });
  try {
    if (options.args.length === 1 && options.args[0] === "--smoke") {
      const { resourceLoader } = runtime.services;
      console.log(
        JSON.stringify({
          initialized: true,
          piVersion: VERSION,
          agentDir,
          sessionDir,
          instructions: resourceLoader
            .getAgentsFiles()
            .agentsFiles.map((item) => item.path),
          skills: resourceLoader.getSkills().skills.map((item) => item.name),
          extensions: resourceLoader.getExtensions().extensions.length,
          prompts: resourceLoader.getPrompts().prompts.map((item) => item.name),
        }),
      );
      return;
    }
    if (options.args.length > 0)
      throw new Error(
        `Unknown branded command option: ${options.args.join(" ")}`,
      );
    await new InteractiveMode(runtime).run();
  } finally {
    await runtime.dispose();
  }
}
