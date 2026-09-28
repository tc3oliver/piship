// The Pi session commands: the interactive TUI and the `--smoke` acceptance run.
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  createReadTool,
  InteractiveMode,
  VERSION,
} from "@earendil-works/pi-coding-agent";
import { PiShipError, redact } from "@piship/contracts";
import type { GovernanceSession } from "../governance-session.js";
import { saveMetrics } from "../launch-metrics.js";
import {
  type LaunchContext,
  type PreparedAccess,
  prepareAccess,
} from "../launch/context.js";
import { openGovernance } from "../launch/governance.js";
import { publishContext, startGoverned } from "../launch/runtime.js";

const SMOKE_PROMPT = "PiShip acceptance request: reply with a short greeting.";

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

export async function runSmoke(
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
    // Credential refreshes during the session land in the same metrics.
    saveMetrics(prepared.metrics);
    publishContext(null);
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

export async function runInteractive(
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
    // Credential refreshes during the session land in the same metrics.
    saveMetrics(prepared.metrics);
    publishContext(null);
  }
}
