// Launch-time governance for piship/v1alpha3 distributions: audit, project
// origin, sandbox, policy, resource and provider trust, capability state, and
// MCP. Every mandatory control that cannot be established fails the launch.
import { AsyncLocalStorage } from "node:async_hooks";
import { homedir } from "node:os";
import type { Extension } from "@earendil-works/pi-coding-agent";
import {
  AuditLog,
  type AuditStatus,
  LocalMetrics,
  requiredAuditLoss,
} from "@piship/audit";
import {
  type ApprovalChannel,
  type AuditEventType,
  formatError,
  PiShipError,
  type PolicyAction,
  type PolicyDecision,
  plainHttpOrigins,
  type ResolvedDecision,
  redact,
  duringStartup,
  resolveDecision,
  startupMark,
} from "@piship/contracts";
import {
  auditRotation,
  setUserAuto,
  type UserAutoStatus,
  userAutoDenied,
  userAutoStatus,
  yoloRefusal,
} from "@piship/core";
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
import {
  type ActiveSandbox,
  activateSandbox,
  describeWorkspace,
  type WorkspaceReport,
} from "@piship/sandbox";
import type { BuiltinExtension, GovernanceManifest } from "@piship/schema";
import { approvalSubject, terminalApproval } from "./governance/approval.js";
import { computeCapabilities } from "./governance/capabilities.js";
import {
  buildEngine,
  discoverProject,
  projectProtection,
  sandboxConfig,
} from "./governance/engine.js";
import type { ToolExposureTable } from "./governance/exposure.js";
import { startMcp } from "./governance/mcp.js";
import type {
  DecisionEvents,
  GovernanceOptions,
  ProjectTrustResult,
  ResourceEvidence,
} from "./governance/options.js";
import { resolveProject } from "./governance/project.js";
import { resolveResources } from "./governance/resources.js";
import { sandboxBackend } from "./governance/sandbox.js";
import { SessionOutputStore } from "./shell-output.js";

export { terminalApproval } from "./governance/approval.js";
export {
  type GovernanceInspection,
  inspectGovernance,
} from "./governance/inspection.js";
export type {
  DecisionEvents,
  GovernanceOptions,
  LoaderInputs,
  ProjectTrustResult,
  ResourceEvidence,
} from "./governance/options.js";

const STRICTNESS = { allow: 0, ask: 1, deny: 2 } as const;

/** The exact action and targets an approval was given for. */
function sessionAllowKey(
  action: PolicyAction,
  resources: readonly string[],
): string {
  return JSON.stringify([action, [...resources].sort()]);
}
const WORKSPACE_STRENGTH = { snapshot: 0, synchronized: 1, shared: 2 } as const;

/**
 * Local metrics are operational telemetry: a record or save that fails (a
 * full, read-only, or unreachable state directory) is dropped, so it never
 * decides whether a governed session starts or closes, and never replaces
 * the error a failing launch reports.
 */
function bestEffort(record: () => void): void {
  try {
    record();
  } catch {
    // Local metrics never block a governed session.
  }
}

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
  /** Set by `resolveProject`; what Pi's `isProjectTrusted()` reports. */
  projectTrust: ProjectTrustResult = {
    trusted: false,
    surfaces: 0,
    reason: "project trust was not resolved",
  };
  capabilities: CapabilityState[] = [];
  mcpReports: readonly McpServerReport[] = [];
  mcp: McpGovernor | null = null;
  /** Full shell output of this session; removed at close(). */
  outputStore = new SessionOutputStore();
  #closed = false;
  #userAuto: UserAutoStatus;
  /** `--yolo`: approves asks for this session only; stored nowhere. */
  #yolo: boolean;

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
    // Read once: the switch the session starts with is the one it audits.
    this.#userAuto = userAutoStatus(
      options.stateDir,
      this.manifest.policy,
      options.lock.deployment.mode,
    );
    this.#yolo = options.yolo === true;
  }

  /**
   * Opens the session. The paths it resolves while it sets up (the sandbox
   * profile, the project's git protection, the policy engine) are resolved
   * once, not once per caller: `duringStartup`.
   */
  static open(options: GovernanceOptions): Promise<GovernanceSession> {
    return duringStartup(() => GovernanceSession.#open(options));
  }

  static async #open(options: GovernanceOptions): Promise<GovernanceSession> {
    // The launch refuses this first; a session opened by other means must too.
    const refusal = options.yolo ? yoloRefusal(options.lock) : undefined;
    if (refusal) throw refusal;
    const started = Date.now();
    const manifest = options.lock.governance.manifest;
    const metrics = options.metrics ?? LocalMetrics.load(options.stateDir);
    const homeDir = options.homeDir ?? homedir();
    let audit: AuditLog | undefined;
    let sandbox: ActiveSandbox | undefined;
    // Output left by PiShip processes that died before closing their session.
    SessionOutputStore.sweep();
    try {
      audit = await AuditLog.open({
        config: manifest.audit,
        distribution: options.lock.app.id,
        stateDir: options.stateDir,
        rotation: auditRotation(options.lock),
        fetch: options.fetch,
        // A sink with httpTransport: http-allowed: plain HTTP to its own
        // origin only.
        plainHttpFetch: (url) => {
          const plainHttp = plainHttpOrigins([url]);
          return plainHttp && options.plainHttpFetch
            ? options.plainHttpFetch(plainHttp)
            : options.fetch;
        },
        resolveUrl: (template) =>
          options.resolveTemplate("audit.sinks.url", template),
      });
      startupMark("governance_audit_open");
      const { project, candidates } = discoverProject(options, homeDir);
      startupMark("governance_project_discovered");
      // The distribution state holds sessions and credential metadata; tool
      // subprocesses never need to read it. The git files that classify the
      // project and the hooks git runs outside the sandbox stay read-only.
      const backend = await sandboxBackend(options);
      sandbox = await activateSandbox(sandboxConfig(options), {
        ...(backend ? { backend } : {}),
        workspace: project.root,
        homeDir,
        extraReadOnly: [options.distributionDir],
        protectedPaths: projectProtection(options, project, homeDir),
        // A backend's working-tree sentinel directory is used only in a
        // company-origin project; any other origin keeps the check in .git.
        projectOrigin: project.origin,
      });
      startupMark("governance_sandbox_active");
      const { level, adapter, networkDenial } = sandbox.report;
      bestEffort(() =>
        metrics.recordSandbox(level, adapter, networkDenial?.evidence),
      );
      const engine = await buildEngine(
        options,
        project,
        candidates,
        sandbox.report,
        sandbox.profile.tmpDir,
        homeDir,
      );
      startupMark("governance_engine_built");
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
      sandbox.onWorkspaceReport((report) => session.#workspaceReport(report));
      // Lower than declared: the backend named a network probe, and it did
      // not prove denial. The sentence is fixed text; never an address.
      if (
        networkDenial?.evidence === "attested" &&
        networkDenial.probe &&
        networkDenial.reason
      )
        session.#notice(
          `Network denial in the sandbox is attested by the ${adapter} backend, not verified: ${networkDenial.reason}.`,
        );
      const workspace = sandbox.report.workspace;
      session.emit("session.start", {
        detail: {
          project: project.origin,
          sandbox: sandbox.report.level,
          ...(workspace ? { workspace: workspace.declared } : {}),
        },
      });
      session.emit("policy.loaded", {
        policy: engine.id,
        detail: {
          diagnostics: engine.diagnostics.length,
          ...(session.userAuto.active ? { userAuto: true } : {}),
          ...(session.yolo ? { yolo: true } : {}),
        },
      });
      // The stored switch is audited when it is switched; a session that
      // starts with it on records that too, so a switch turned on without
      // an event (auto.json edited by hand) still leaves one. Metadata only.
      if (session.userAuto.active)
        session.emit("policy.auto_enabled", {
          policy: engine.id,
          detail: { source: "state" },
        });
      // `--yolo` is recorded the same way: it is the one switch this session
      // was started with, and nothing of it is stored.
      if (session.yolo)
        session.emit("policy.auto_enabled", {
          policy: engine.id,
          detail: {
            source: "yolo",
            ...(options.onYoloEnd ? { providerAutoApprove: true } : {}),
          },
        });
      // A team, project, or managed user file that tries to widen the policy
      // is recorded; a rule it names is what tried.
      for (const diagnostic of engine.diagnostics)
        if (diagnostic.ruleId !== undefined)
          session.emit("policy.violation", {
            policy: engine.id,
            rule: diagnostic.ruleId,
            detail: { source: diagnostic.source },
          });
      await resolveResources(session);
      await resolveProject(session, session.#projectServers);
      startupMark("governance_resources_resolved");
      await startMcp(session, session.#projectServers);
      startupMark("governance_mcp_started");
      await computeCapabilities(session);
      bestEffort(() => metrics.recordStartupLatency(Date.now() - started));
      bestEffort(() => metrics.save());
      return session;
    } catch (error) {
      const code =
        error instanceof PiShipError ? error.code : "CONFIG_UNAVAILABLE";
      bestEffort(() => metrics.recordStartupFailure(code));
      try {
        await sandbox?.dispose();
      } finally {
        // The launch fails with its own error; events a required sink did
        // not take are recorded locally, where doctor reports them.
        const status = await audit?.close(options.auditCloseDeadlineMs);
        if (status && requiredAuditLoss(status))
          bestEffort(() => metrics.recordStartupFailure("AUDIT_UNAVAILABLE"));
        bestEffort(() => metrics.save());
      }
      throw error;
    }
  }

  get policyId(): string {
    return this.engine.id;
  }

  /**
   * The actions whose `ask` this session resolves through `decide`, where
   * the user's auto mode applies. Others are never auto-approved: a
   * mid-session `model.select` switch accepts only a model approved at start,
   * and `network.connect`, `web.request`, `browser.execute`, `memory.*`, and
   * `agent.invoke` have no runtime hook (audit-only, or the sandbox).
   * `policy explain` reports AUTO-APPROVED only for these.
   */
  static readonly AUTO_RESOLVED_ACTIONS: ReadonlySet<PolicyAction> =
    new Set<PolicyAction>([
      "tool.execute",
      "shell.execute",
      "filesystem.read",
      "filesystem.write",
      "resource.load",
      "extension.load",
      "skill.load",
      "instruction.load",
      "provider.load",
      "mcp.server.start",
      "mcp.tool.call",
    ]);

  /** The user's auto mode as this session applies it. */
  get userAuto(): UserAutoStatus {
    return this.#userAuto;
  }

  /** Whether `--yolo` is approving asks in this session. */
  get yolo(): boolean {
    return this.#yolo;
  }

  /**
   * Switch the user's auto mode from inside the session (`/auto`), and store
   * it for later sessions. Switching on is refused with POLICY_DENIED unless
   * the distribution allows it, and is audited first: the event is flushed,
   * and when a required sink has not taken it (AUDIT_UNAVAILABLE) the switch
   * stays off. Switching off only restores prompts, so it always applies
   * first; its event is best effort, and a failure to record it is
   * returned as `warning`.
   */
  async switchUserAuto(
    enabled: boolean,
  ): Promise<UserAutoStatus & { readonly warning?: string }> {
    let warning: string | undefined;
    if (enabled) {
      if (!this.#userAuto.allowed)
        throw userAutoDenied(
          this.options.lock.app.command,
          this.options.lock.deployment.mode,
        );
      this.audit.assertAvailable();
      this.emit("policy.auto_enabled", {
        policy: this.policyId,
        detail: { source: "session" },
      });
      await this.audit.flush();
      const loss = requiredAuditLoss(
        this.audit.status(),
        "Auto mode was not switched on, because its audit was not recorded",
      );
      if (loss) throw loss;
      setUserAuto(this.options.stateDir, true);
    } else {
      // `off` ends `--yolo` for the rest of the session as well.
      const wasYolo = this.#yolo;
      this.#yolo = false;
      setUserAuto(this.options.stateDir, false);
      if (wasYolo)
        try {
          this.options.onYoloEnd?.();
          if (this.options.onYoloEnd)
            warning =
              "Auto mode is off. Exit and restart without --yolo before changing provider settings, which may restore its old auto-approval value.";
        } catch (error) {
          warning = `Auto mode is off, but the provider override could not be restored: ${formatError(error)}`;
        }
      if (this.#userAuto.allowed || wasYolo)
        try {
          this.audit.assertAvailable();
          this.emit("policy.auto_disabled", {
            policy: this.policyId,
            detail: { source: "session" },
          });
        } catch (error) {
          warning = `Auto mode is off, but its audit was not recorded: ${formatError(error)}`;
        }
    }
    this.#userAuto = userAutoStatus(
      this.options.stateDir,
      this.manifest.policy,
      this.options.lock.deployment.mode,
    );
    return { ...this.#userAuto, ...(warning ? { warning } : {}) };
  }

  /** Throws AUDIT_UNAVAILABLE while a required audit sink has lost events. */
  assertAuditAvailable(): void {
    this.audit.assertAvailable();
  }

  #runtimeBlock: PiShipError | undefined;

  /**
   * Enforced instructions or tools were changed and could not be restored,
   * or PiShip's own enforcement failed: every later model request of this
   * process is refused. The first failure is kept. Never throws, so a Pi
   * handler that calls it cannot have the block swallowed with its error.
   */
  blockRuntime(resource: string, reason: string): void {
    this.#runtimeBlock ??= new PiShipError(
      "POLICY_DENIED",
      "Enforced instructions or tools of this session were changed and could not be restored",
      {
        component: "policy",
        userAction: `Start ${this.options.lock.app.command} again`,
      },
    );
    try {
      this.emit("runtime.mutation.reverted", {
        resource,
        decision: "denied",
        detail: { repair: "failed", reason: redact(reason) },
      });
    } catch {
      // The block stands whether or not its audit was recorded.
    }
  }

  /** Throws POLICY_DENIED once `blockRuntime` was called. */
  assertRuntimeIntact(): void {
    if (this.#runtimeBlock) throw this.#runtimeBlock;
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
   * Evaluate, resolve `ask` through the channel (headless: deny), or approve
   * it without a prompt while the user's auto mode or `--yolo` is on (recorded
   * as `policy.auto_approved`), record denials, and fail closed when a required
   * audit sink is down. Neither ever touches `deny`. Several
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
    const prompt = {
      title: `${this.options.lock.app.name} policy approval`,
      message: `${action} ${approvalSubject(events?.prompt ?? events?.resource ?? decision.resource)}${decision.reason ? `\n${decision.reason}` : ""}`,
    };
    // Pi does not queue extension dialogs: a second confirm replaces the
    // first, whose promise never settles. Approvals of concurrent tool
    // calls (parallel top-level calls, Codemode's nested calls) wait their
    // turn; the queue is held only while a prompt is open. A call that waited
    // while the user switched auto mode on is approved without its prompt.
    const approved = {
      ...decision,
      outcome: "allow" as const,
      approval: "auto" as const,
    };
    // A session allow is the user's own earlier answer to this very ask: it
    // is looked up only for an `ask` (never a `deny`), under the exact action
    // and targets, and looked up again once the prompt queue reaches this call.
    const remembered = sessionAllowKey(action, resources);
    const sessionApproved = {
      ...decision,
      outcome: "allow" as const,
      approval: "session" as const,
    };
    const offered =
      decision.effect === "ask" &&
      channel &&
      this.#offersSession(action, resources)
        ? { ...prompt, scopes: ["once", "session"] as const }
        : prompt;
    let auto = this.#autoApproval(action, resources, decision);
    const resolved: ResolvedDecision = auto
      ? approved
      : decision.effect === "ask" && this.#sessionAllowed.has(remembered)
        ? sessionApproved
        : decision.effect === "ask" && channel
          ? await this.#serialized(async () => {
              auto = this.#autoApproval(action, resources, decision);
              if (auto) return approved;
              if (this.#sessionAllowed.has(remembered)) return sessionApproved;
              return resolveDecision(decision, channel, offered);
            })
          : await resolveDecision(decision, channel, prompt);
    if (resolved.remember === "session") this.#sessionAllowed.add(remembered);
    const fields = {
      resource: events?.resource ?? redact(decision.resource),
      policy: decision.policyId,
      rule: decision.ruleId,
      enforcement: decision.enforcement,
      detail: {
        action,
        ...(events?.detail ?? {}),
        ...(resolved.approval ? { approval: resolved.approval } : {}),
        ...(resolved.remember ? { remember: resolved.remember } : {}),
        // `source` is taken (a tool call's origin), so the switch that
        // approved gets its own key. The stored auto mode, the usual one,
        // leaves none.
        ...(auto === "yolo" ? { autoSource: "yolo" } : {}),
      },
      ...(events?.content ? { content: events.content } : {}),
    };
    // Metadata only: the same fields as the action's own event, no content.
    if (auto)
      this.emit("policy.auto_approved", {
        resource: fields.resource,
        policy: fields.policy,
        rule: fields.rule,
        enforcement: fields.enforcement,
        detail: fields.detail,
        decision: "approved",
      });
    if (resolved.outcome === "deny") {
      this.metrics.recordPolicyDenial(action);
      if (events) this.emit(events.denied, { ...fields, decision: "denied" });
    } else if (events?.allowed)
      this.emit(events.allowed, {
        ...fields,
        decision:
          resolved.approval === "approved" ||
          resolved.approval === "auto" ||
          resolved.approval === "session"
            ? "approved"
            : "allowed",
      });
    return resolved;
  }

  /**
   * Which switch approves this ask without a prompt, if one does: `--yolo`
   * (this session only) or the user's stored auto mode. Both keep the prompt
   * of an explicit `ask` that an enforced, team, project, or managed user
   * rule wrote to keep it. A personal user owns every layer, so `--yolo`
   * there approves every ask.
   */
  #autoApproval(
    action: PolicyAction,
    resources: readonly string[],
    decision: PolicyDecision,
  ): "yolo" | "state" | undefined {
    const switchedOn = this.#yolo
      ? "yolo"
      : this.#userAuto.active
        ? "state"
        : undefined;
    if (!switchedOn || decision.effect !== "ask") return undefined;
    if (this.#yolo && this.options.lock.deployment.mode === "personal")
      return switchedOn;
    return resources.some((item) =>
      this.engine.keepsPrompt({ action, resource: item }),
    )
      ? undefined
      : switchedOn;
  }

  /**
   * The asks the user answered "allow for this session": action and exact
   * targets. In memory only, so it ends with the session; a `deny` never
   * consults it, and nothing here is stored.
   */
  readonly #sessionAllowed = new Set<string>();

  /**
   * Whether the prompt may offer "allow for this session". Not for an ask an
   * enforced, team, project, or managed user rule wrote to keep its prompt:
   * that rule asks for a confirmation each time. A personal user owns every
   * layer, as with `--yolo`.
   */
  #offersSession(action: PolicyAction, resources: readonly string[]): boolean {
    if (this.options.lock.deployment.mode === "personal") return true;
    return !resources.some((item) =>
      this.engine.keepsPrompt({ action, resource: item }),
    );
  }

  #approvalTail: Promise<unknown> = Promise.resolve();

  /** Run `prompt` after every approval prompt queued before it settled. */
  #serialized<T>(prompt: () => Promise<T>): Promise<T> {
    const next = this.#approvalTail.then(prompt, prompt);
    this.#approvalTail = next.catch(() => undefined);
    return next;
  }

  /**
   * Run a dialog of PiShip's own (`ask_user`) in the approval queue, so it
   * never replaces an open approval prompt or another question.
   */
  serializeDialog<T>(dialog: () => Promise<T>): Promise<T> {
    return this.#serialized(dialog);
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
  /**
   * The exposure table of the current Pi session; set when the runtime
   * creates a session (again for `/new`, `/resume`, and fork).
   */
  exposure: ToolExposureTable | null = null;
  /**
   * The extensions Pi runs, in handler order; set with `exposure`. Read
   * live, as Pi reads each extension's handlers at every event.
   */
  piExtensions: (() => readonly Extension[]) | null = null;
  /** Current piship-workflow mode; null when the workflow is not active. */
  workflowMode: "plan" | "build" | null = null;

  #workspaceWarned = false;
  #pendingNotices: string[] = [];
  #notify: ((message: string) => void) | undefined;

  /**
   * Show session notices through `notify` (the governance extension's UI).
   * Notices raised before a sink is attached are shown when it is.
   */
  attachNotices(notify: (message: string) => void): void {
    this.#notify = notify;
    for (const message of this.#pendingNotices.splice(0)) this.#notice(message);
  }

  /** Show a session notice now, or once a UI is attached. */
  notice(message: string): void {
    this.#notice(message);
  }

  #notice(message: string): void {
    if (!this.#notify) {
      this.#pendingNotices.push(message);
      return;
    }
    try {
      this.#notify(message);
    } catch {
      // a notice never decides a command
    }
  }

  /**
   * A workspace verification result: recorded in local metrics (enums and a
   * time only), and one notice per session when the effective mode is lower
   * than declared. A lower mode is a warning, not a failure; only an unsafe
   * workspace (writable git control files) fails its command closed.
   */
  #workspaceReport(report: WorkspaceReport): void {
    this.metrics.recordWorkspace(
      report.declared,
      report.effective,
      report.verification,
      report.verifiedAt,
    );
    if (
      this.#workspaceWarned ||
      WORKSPACE_STRENGTH[report.effective] >=
        WORKSPACE_STRENGTH[report.declared]
    )
      return;
    this.#workspaceWarned = true;
    // The sentence holds modes, a time, and a fixed reason; never a path,
    // token, or endpoint. Whether commands still run is not said here: an
    // unsafe workspace fails its command with its own error.
    this.#notice(
      `The sandbox workspace is weaker than the distribution declares. ${describeWorkspace(report)}`,
    );
  }

  /** Whether a capability is effective (all six axes). */
  effective(name: string): boolean {
    return (
      this.capabilities.find((state) => state.name === name)?.axes.effective
        .value === "yes"
    );
  }

  /**
   * End the session: record `session.end`, stop MCP servers, dispose the
   * sandbox, remove the session's shell output, and flush audit. Audit is
   * flushed and metrics saved even when a cleanup step fails; a failed
   * metrics save never fails the close. Throws AUDIT_UNAVAILABLE, after
   * cleanup, when a required sink did not take every event of the session
   * (that error wins over a cleanup error); otherwise returns the final audit
   * status.
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
        try {
          await this.sandbox.dispose();
        } finally {
          await this.outputStore.dispose();
        }
      }
    } finally {
      try {
        status = await this.audit.close(this.options.auditCloseDeadlineMs);
      } finally {
        bestEffort(() => this.metrics.save());
      }
      const loss = requiredAuditLoss(status, "The session ended");
      // biome-ignore lint/correctness/noUnsafeFinally: undelivered required audit outranks a cleanup error
      if (loss) throw loss;
    }
    return status;
  }
}
