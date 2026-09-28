import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
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
  PiShipError,
} from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import { isCredentialRejection, type GovernedRuntime } from "../governance.js";
import type { GovernanceSession } from "../governance-session.js";
import { governedTools } from "../governed-tools.js";
import { saveMetrics } from "../launch-metrics.js";
import type { LaunchContext, PreparedAccess } from "./context.js";
import { governanceExtensions, modelPolicy } from "./governance.js";
import { createModelRuntime, type Model } from "./model-runtime.js";

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

export async function startGoverned(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  sessionDir: string,
  gov: GovernanceSession | null,
) {
  try {
    return await startRuntime(ctx, prepared, sessionDir, gov);
  } catch (error) {
    await gov?.close();
    saveMetrics(prepared.metrics);
    throw error;
  }
}
