// The Pi session commands: the interactive TUI and the `--smoke` acceptance run.
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  createReadTool,
  InteractiveMode,
  VERSION,
} from "@earendil-works/pi-coding-agent";
import {
  formatError,
  PiShipError,
  principalDigest,
  principalKey,
  redact,
} from "@piship/contracts";
import { acceptanceFailure } from "../governance.js";
import type { GovernanceSession } from "../governance-session.js";
import { saveMetrics } from "../launch-metrics.js";
import {
  type LaunchContext,
  type PreparedAccess,
  prepareAccess,
} from "../launch/context.js";
import { openGovernance } from "../launch/governance.js";
import { publishContext, startGoverned } from "../launch/runtime.js";
import type { SessionOwnership } from "../launch/session-file.js";
import { endInsideDispose } from "./dispose-hook.js";

/**
 * Pi keeps its session history in a directory PiShip chooses. With an identity
 * session the directory is per principal, so a different user on the same OS
 * account does not resume the previous user's sessions; the same user resumes
 * across logout and login. Without an identity (a personal distribution) it is
 * the shared directory, as before.
 */
function sessionDirectory(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  kind: "user" | "acceptance",
): string {
  const identity = prepared.activated?.identity;
  const base = join(ctx.stateDir, "sessions", kind);
  const dir = identity
    ? join(base, principalDigest(principalKey(identity)))
    : base;
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

const SMOKE_PROMPT = "PiShip acceptance request: reply with a short greeting.";

/**
 * Ends a session: dispose the runtime, close the governance session (which
 * throws `AUDIT_UNAVAILABLE` when a required sink lost events), then save the
 * metrics and drop the published context. Every step runs even when an earlier
 * one failed. A failure of the session itself stays the command's error, and
 * teardown failures are then only reported; otherwise the first one is thrown.
 */
async function endSession(
  ctx: LaunchContext,
  prepared: PreparedAccess,
  runtime: { dispose(): Promise<void> },
  gov: GovernanceSession | null,
  sessionFailed: boolean,
  ownership: SessionOwnership,
): Promise<void> {
  const failures: unknown[] = [];
  try {
    await runtime.dispose();
  } catch (error) {
    failures.push(error);
  }
  // Pi has written its last entry; another launch may continue the session.
  ownership.release();
  try {
    await gov?.close();
  } catch (error) {
    failures.push(error);
  }
  // Credential refreshes during the session land in the same metrics.
  saveMetrics(prepared.metrics);
  publishContext(null);
  if (failures.length === 0) return;
  if (sessionFailed) {
    for (const error of failures) ctx.err(`Error: ${formatError(error)}`);
    return;
  }
  // Lost required audit outranks a cleanup error, as it does in close().
  const lost = failures.findIndex(
    (error) =>
      error instanceof PiShipError && error.code === "AUDIT_UNAVAILABLE",
  );
  const [first] = failures.splice(Math.max(lost, 0), 1);
  for (const error of failures) ctx.err(`Error: ${formatError(error)}`);
  throw first;
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

export async function runSmoke(
  ctx: LaunchContext,
  requestedModel: string | undefined,
  withModelRequest: boolean,
  newSession: boolean,
): Promise<void> {
  const cacheDir = join(ctx.stateDir, "cache");
  const logsDir = join(ctx.stateDir, "logs");
  const dataDir = join(ctx.stateDir, "data");
  for (const path of [cacheDir, logsDir, dataDir])
    mkdirSync(path, { recursive: true, mode: 0o700 });
  const prepared = await prepareAccess(ctx, requestedModel);
  const sessionDir = sessionDirectory(ctx, prepared, "acceptance");
  const gov = await openGovernance(ctx, prepared, false);
  const { runtime, ownership } = await startGoverned(
    ctx,
    prepared,
    { sessionDir, newSession, disposable: true },
    gov,
  );
  let sessionFailed = false;
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
      throw acceptanceFailure(runtime.session.messages.at(-1));
  } catch (error) {
    sessionFailed = true;
    throw error;
  } finally {
    await endSession(ctx, prepared, runtime, gov, sessionFailed, ownership);
  }
}

function governanceSummary(gov: GovernanceSession) {
  return {
    policy: gov.policyId,
    project: { origin: gov.project.origin },
    sandbox: {
      level: gov.sandbox.report.level,
      adapter: gov.sandbox.report.adapter,
      provider: gov.sandbox.report.provider,
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
  newSession: boolean,
): Promise<void> {
  for (const name of ["cache", "logs", "data"])
    mkdirSync(join(ctx.stateDir, name), { recursive: true, mode: 0o700 });
  const prepared = await prepareAccess(ctx, requestedModel);
  const sessionDir = sessionDirectory(ctx, prepared, "user");
  for (const notice of prepared.activated?.notices ?? [])
    ctx.err(`Notice: ${notice}`);
  const gov = await openGovernance(
    ctx,
    prepared,
    !!process.stdin.isTTY && !!process.stderr.isTTY,
  );
  const { runtime, theme, ownership } = await startGoverned(
    ctx,
    prepared,
    { sessionDir, newSession },
    gov,
  );
  let sessionFailed = false;
  // Pi's shutdown awaits runtime.dispose() and then calls process.exit(), so
  // the governance session ends inside that dispose (see dispose-hook.ts).
  const piDispose = runtime.dispose.bind(runtime);
  const end = endInsideDispose(
    runtime,
    (failed) =>
      endSession(ctx, prepared, { dispose: piDispose }, gov, failed, ownership),
    (error) => ctx.err(`Error: ${formatError(error)}`),
  );
  try {
    await new InteractiveMode(
      runtime,
      theme ? { initialThemeSetting: theme } : {},
    ).run();
  } catch (error) {
    sessionFailed = true;
    throw error;
  } finally {
    await end(sessionFailed);
  }
}
