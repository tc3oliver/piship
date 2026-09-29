// Launch-time governance for piship/v1alpha3 distributions: audit, project
// origin, sandbox, policy, resource and provider trust, capability state, and
// MCP. Every mandatory control that cannot be established fails the launch.
import { AsyncLocalStorage } from "node:async_hooks";
import { homedir } from "node:os";
import {
  AuditLog,
  type AuditStatus,
  LocalMetrics,
  requiredAuditLoss,
} from "@piship/audit";
import {
  type ApprovalChannel,
  type AuditEventType,
  type PolicyAction,
  PiShipError,
  type ResolvedDecision,
  redact,
  resolveDecision,
} from "@piship/contracts";
import type {
  McpGovernor,
  McpServerConfig,
  McpServerReport,
} from "@piship/mcp";
import type {
  CapabilityState,
  PolicyEngine,
  ProjectIdentity,
  ProjectResourceCandidate,
} from "@piship/policy";
import { type ActiveSandbox, activateSandbox } from "@piship/sandbox";
import type { BuiltinExtension, GovernanceManifest } from "@piship/schema";
import { approvalSubject, terminalApproval } from "./governance/approval.js";
import { computeCapabilities } from "./governance/capabilities.js";
import {
  buildEngine,
  discoverProject,
  gitProtection,
  sandboxConfig,
} from "./governance/engine.js";
import { startMcp } from "./governance/mcp.js";
import type {
  DecisionEvents,
  GovernanceOptions,
  ResourceEvidence,
} from "./governance/options.js";
import { resolveProject } from "./governance/project.js";
import { resolveResources } from "./governance/resources.js";
import { sandboxBackend } from "./governance/sandbox.js";

export { terminalApproval } from "./governance/approval.js";
export {
  type GovernanceInspection,
  inspectGovernance,
} from "./governance/inspection.js";
export type {
  DecisionEvents,
  GovernanceOptions,
  LoaderInputs,
  ResourceEvidence,
} from "./governance/options.js";

const STRICTNESS = { allow: 0, ask: 1, deny: 2 } as const;

export class GovernanceSession {
  readonly manifest: GovernanceManifest;
  readonly resources: ResourceEvidence[] = [];
  readonly loader: {
    instructions: { path: string; content: string }[];
    skills: string[];
    extensions: string[];
    prompts: string[];
    themes: string[];
    builtin: Set<BuiltinExtension>;
  } = {
    instructions: [],
    skills: [],
    extensions: [],
    prompts: [],
    themes: [],
    builtin: new Set(),
  };
  capabilities: CapabilityState[] = [];
  mcpReports: readonly McpServerReport[] = [];
  mcp: McpGovernor | null = null;
  #closed = false;

  private constructor(
    readonly options: GovernanceOptions,
    readonly audit: AuditLog,
    readonly metrics: LocalMetrics,
    readonly project: ProjectIdentity,
    readonly projectCandidates: readonly ProjectResourceCandidate[],
    readonly sandbox: ActiveSandbox,
    readonly engine: PolicyEngine,
    readonly sessionId: string,
  ) {
    this.manifest = options.lock.governance.manifest;
  }

  static async open(options: GovernanceOptions): Promise<GovernanceSession> {
    const started = Date.now();
    const manifest = options.lock.governance.manifest;
    const metrics = options.metrics ?? LocalMetrics.load(options.stateDir);
    const homeDir = options.homeDir ?? homedir();
    let audit: AuditLog | undefined;
    let sandbox: ActiveSandbox | undefined;
    try {
      audit = await AuditLog.open({
        config: manifest.audit,
        distribution: options.lock.app.id,
        stateDir: options.stateDir,
        fetch: options.fetch,
        resolveUrl: (template) =>
          options.resolveTemplate("audit.sinks.url", template),
      });
      const { project, candidates } = discoverProject(options, homeDir);
      // The distribution state holds sessions and credential metadata; tool
      // subprocesses never need to read it. The git files that classify the
      // project and the hooks git runs outside the sandbox stay read-only.
      const backend = await sandboxBackend(options);
      sandbox = await activateSandbox(sandboxConfig(options), {
        ...(backend ? { backend } : {}),
        workspace: project.root,
        homeDir,
        extraReadOnly: [options.distributionDir],
        protectedPaths: gitProtection(project.root),
      });
      metrics.recordSandbox(sandbox.report.level, sandbox.report.adapter);
      const engine = await buildEngine(
        options,
        project,
        candidates,
        sandbox.report,
        sandbox.profile.tmpDir,
        homeDir,
      );
      const session = new GovernanceSession(
        options,
        audit,
        metrics,
        project,
        candidates,
        sandbox,
        engine,
        `${Date.now().toString(36)}-${process.pid}`,
      );
      session.emit("session.start", {
        detail: {
          project: project.origin,
          sandbox: sandbox.report.level,
        },
      });
      session.emit("policy.loaded", {
        policy: engine.id,
        detail: { diagnostics: engine.diagnostics.length },
      });
      // A team, project, or managed user file that tries to widen the policy
      // is recorded.
      for (const diagnostic of engine.diagnostics)
        session.emit("policy.violation", {
          policy: engine.id,
          ...(diagnostic.ruleId ? { rule: diagnostic.ruleId } : {}),
          detail: { source: diagnostic.source },
        });
      await resolveResources(session);
      await resolveProject(session, session.#projectServers);
      await startMcp(session, session.#projectServers);
      await computeCapabilities(session);
      metrics.recordStartupLatency(Date.now() - started);
      metrics.save();
      return session;
    } catch (error) {
      const code =
        error instanceof PiShipError ? error.code : "CONFIG_UNAVAILABLE";
      metrics.recordStartupFailure(code);
      try {
        await sandbox?.dispose();
      } finally {
        // The launch fails with its own error; events a required sink did
        // not take are recorded locally, where doctor reports them.
        const status = await audit?.close(options.auditCloseDeadlineMs);
        if (status && requiredAuditLoss(status))
          metrics.recordStartupFailure("AUDIT_UNAVAILABLE");
        metrics.save();
      }
      throw error;
    }
  }

  get policyId(): string {
    return this.engine.id;
  }

  /** Throws AUDIT_UNAVAILABLE while a required audit sink has lost events. */
  assertAuditAvailable(): void {
    this.audit.assertAvailable();
  }

  emit(
    event: AuditEventType,
    fields: Omit<Parameters<AuditLog["emit"]>[0], "event"> = {},
  ): void {
    this.audit.emit({
      user: this.options.user ?? null,
      session: this.sessionId,
      ...fields,
      event,
    });
  }

  /**
   * Evaluate, resolve `ask` through the channel (headless: deny), record
   * denials, and fail closed when a required audit sink is down. Several
   * resources (a lexical and a symlink-resolved path) are decided together:
   * the strictest decision wins and at most one approval is asked.
   */
  async decide(
    action: PolicyAction,
    resource: string | readonly string[],
    channel: ApprovalChannel | undefined,
    events?: DecisionEvents,
  ): Promise<ResolvedDecision> {
    this.audit.assertAvailable();
    const resources =
      typeof resource === "string" ? [resource] : [...new Set(resource)];
    const decision = resources
      .map((item) => this.engine.evaluate({ action, resource: item }))
      .reduce((current, next) =>
        STRICTNESS[next.effect] > STRICTNESS[current.effect] ? next : current,
      );
    const resolved = await resolveDecision(decision, channel, {
      title: `${this.options.lock.app.name} policy approval`,
      message: `${action} ${approvalSubject(events?.prompt ?? events?.resource ?? decision.resource)}${decision.reason ? `\n${decision.reason}` : ""}`,
    });
    const fields = {
      resource: events?.resource ?? redact(decision.resource),
      policy: decision.policyId,
      rule: decision.ruleId,
      enforcement: decision.enforcement,
      detail: {
        action,
        ...(events?.detail ?? {}),
        ...(resolved.approval ? { approval: resolved.approval } : {}),
      },
      ...(events?.content ? { content: events.content } : {}),
    };
    if (resolved.outcome === "deny") {
      this.metrics.recordPolicyDenial(action);
      if (events) this.emit(events.denied, { ...fields, decision: "denied" });
    } else if (events?.allowed)
      this.emit(events.allowed, {
        ...fields,
        decision: resolved.approval === "approved" ? "approved" : "allowed",
      });
    return resolved;
  }

  /** Approval before the TUI starts: the terminal, or none when headless. */
  startupChannel(): ApprovalChannel | undefined {
    return (
      this.options.startupApproval ??
      (this.options.interactive ? terminalApproval() : undefined)
    );
  }

  #projectServers: McpServerConfig[] = [];

  /** The in-session UI channel, set by the governance extension. */
  toolApproval: ApprovalChannel | undefined;
  readonly #channelScope = new AsyncLocalStorage<ApprovalChannel | undefined>();

  /** Run a tool call with the approval channel of its own Pi context. */
  withChannel<T>(channel: ApprovalChannel | undefined, run: () => T): T {
    return this.#channelScope.run(channel, run);
  }

  /** Approval channel for the current tool call (headless: none). */
  currentChannel(): ApprovalChannel | undefined {
    return this.#channelScope.getStore() ?? this.toolApproval;
  }
  /** Current piship-workflow mode; null when the workflow is not active. */
  workflowMode: "plan" | "build" | null = null;

  /** Whether a capability is effective (all six axes). */
  effective(name: string): boolean {
    return (
      this.capabilities.find((state) => state.name === name)?.axes.effective
        .value === "yes"
    );
  }

  /**
   * End the session: record `session.end`, stop MCP servers, dispose the
   * sandbox, and flush audit. Audit is flushed and metrics saved even when a
   * cleanup step fails. Throws AUDIT_UNAVAILABLE, after cleanup, when a
   * required sink did not take every event of the session (that error wins
   * over a cleanup error); otherwise returns the final audit status.
   */
  async close(): Promise<AuditStatus> {
    if (this.#closed) return this.audit.status();
    this.#closed = true;
    this.emit("session.end");
    let status: AuditStatus | undefined;
    try {
      try {
        await this.mcp?.close();
      } finally {
        await this.sandbox.dispose();
      }
    } finally {
      try {
        status = await this.audit.close(this.options.auditCloseDeadlineMs);
      } finally {
        this.metrics.save();
      }
      const loss = requiredAuditLoss(status, "The session ended");
      // biome-ignore lint/correctness/noUnsafeFinally: undelivered required audit outranks a cleanup error
      if (loss) throw loss;
    }
    return status;
  }
}
