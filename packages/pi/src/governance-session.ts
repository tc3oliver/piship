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
import {
  type CapabilityState,
  denialHint,
  expandPathTokens,
  isPathAction,
  type PolicyEngine,
  type ProjectIdentity,
  type ProjectResourceCandidate,
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

/**
 * Whether a rule pattern (path tokens already expanded) has a literal
 * character other than `/`, `:`, or whitespace before its first `*`, after a
 * path's drive letter. A pattern led by a wildcard, a root, a drive root, or
 * a space (`**`, `*:*`, a bare `/` or `C:/` before the first `*`) reaches
 * every target and grants no rule for the session.
 */
export function hasLiteralPrefix(
  pattern: string,
  pathAction: boolean,
): boolean {
  const literal = pathAction ? pattern.replace(/^[A-Za-z]:/, "") : pattern;
  return /[^/:\s]/.test(literal.split("*")[0] ?? "");
}

/** One `ask` a prompt answers: its action and exact targets. */
interface ApprovalTarget {
  readonly action: PolicyAction;
  readonly resources: readonly string[];
}

/** A governed tool call's `tool.execute` ask, left to its first resource decision. */
interface DeferredToolAsk {
  readonly tool: string;
  readonly decision: PolicyDecision;
  /** The call's audit detail (source, parent, exposure). */
  readonly detail: Readonly<Record<string, string>>;
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
        // A session delivers what crashed processes spooled; short commands do not.
        replaySpool: true,
        fetch: options.fetch,
        // A sink not set to httpTransport: https: plain HTTP to its own
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
          ...(options.subagent
            ? { subagent: true, parentSession: options.subagent.parentSession }
            : {}),
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

  /** How to change a blocking decision, led by a space; empty when none applies. */
  denialHint(decision: Parameters<typeof denialHint>[0]): string {
    const hint = denialHint(decision, this.options.lock.deployment.mode);
    return hint ? ` ${hint}` : "";
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
      "git.push",
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
          const shared = this.options.onYoloEnd?.();
          if (this.options.onYoloEnd)
            warning = `Auto mode is off. ${shared ? `${shared} ` : ""}Exit and restart without --yolo before changing provider settings, which may restore its old auto-approval value.`;
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
   * the strictest decision wins and at most one approval is asked. The first
   * decision inside a governed tool call also answers that call's deferred
   * `tool.execute` ask (`deferToolAsk`): one prompt for both, never past a
   * `deny`, and each recorded as its own event.
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
    const own = resources
      .map((item) => this.engine.evaluate({ action, resource: item }))
      .reduce((current, next) =>
        STRICTNESS[next.effect] > STRICTNESS[current.effect] ? next : current,
      );
    const held = this.#toolCall.getStore();
    const deferred = held?.ask;
    if (held) held.ask = undefined;
    // A resource `deny` refuses the call without asking for the tool.
    const tool = own.effect === "deny" ? undefined : deferred;
    const decision = tool && own.effect === "allow" ? tool.decision : own;
    const asks: ApprovalTarget[] = [
      ...(tool
        ? [{ action: "tool.execute" as const, resources: [tool.tool] }]
        : []),
      ...(own.effect === "ask" ? [{ action, resources }] : []),
    ];
    // What "allow for this session" grants for each ask, in `asks` order.
    const grants = asks.map((ask) => this.#sessionGrant(ask));
    const offersSession =
      decision.effect === "ask" &&
      channel !== undefined &&
      asks.every((ask) => this.#offersSession(ask.action, ask.resources));
    const prompt = {
      title: `${this.options.lock.app.name} policy approval`,
      // A combined prompt names the tool ask, and each ask's reason, so the
      // answer (an Allow for this session too) covers only what it shows.
      message: [
        ...(tool
          ? [
              `tool.execute ${tool.tool}`,
              ...(tool.decision.reason ? [tool.decision.reason] : []),
            ]
          : []),
        `${action} ${approvalSubject(events?.prompt ?? events?.resource ?? own.resource)}`,
        ...(own.reason && (!tool || own.effect === "ask") ? [own.reason] : []),
      ].join("\n"),
    };
    // A grant wider than the target shown says so, for each ask, where the
    // session answer is shown.
    const sessionCovers = grants.some((grant) => grant.rule)
      ? asks
          .map((ask, index) => {
            const grant = grants[index];
            return grant?.rule
              ? `Allow for this session covers any target matching ${grant.pattern} (rule ${grant.rule}) for ${ask.action} in this session`
              : `Allow for this session covers this ${ask.action} target only`;
          })
          .join("\n")
      : undefined;
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
    // A session allow is the user's own earlier answer to this ask (or, for a
    // rule grant, to the same rule's ask for the same action): it is looked
    // up only for an `ask` (never a `deny`), and looked up again once the
    // prompt queue reaches this call. A combined prompt is covered only when
    // every ask in it was allowed.
    const sessionAllowed = () =>
      grants.every((grant) => this.#sessionAllowed.has(grant.key));
    const sessionApproved = {
      ...decision,
      outcome: "allow" as const,
      approval: "session" as const,
    };
    const offered = offersSession
      ? {
          ...prompt,
          scopes: ["once", "session"] as const,
          ...(sessionCovers ? { sessionCovers } : {}),
        }
      : prompt;
    let auto = this.#autoApproval(asks, decision);
    let prompted = false;
    const resolved: ResolvedDecision = auto
      ? approved
      : decision.effect === "ask" && sessionAllowed()
        ? sessionApproved
        : decision.effect === "ask" && channel
          ? await this.#serialized(async () => {
              auto = this.#autoApproval(asks, decision);
              if (auto) return approved;
              if (sessionAllowed()) return sessionApproved;
              prompted = true;
              bestEffort(() => this.metrics.recordPrompt("shown"));
              const answered = await resolveDecision(
                decision,
                channel,
                offered,
              );
              bestEffort(() => {
                this.metrics.recordPrompt(
                  answered.outcome === "allow"
                    ? "allowed"
                    : answered.approval === "denied"
                      ? "denied"
                      : "cancelled",
                );
                if (answered.remember === "session")
                  this.metrics.recordPrompt("sessionGrants");
              });
              return answered;
            })
          : await resolveDecision(decision, channel, prompt);
    // An answer for a grant already held keeps its count of uses.
    if (resolved.remember === "session")
      for (const { key } of grants)
        if (!this.#sessionAllowed.has(key)) this.#sessionAllowed.set(key, 0);
    if (resolved.approval === "session")
      for (const { key } of grants)
        this.#sessionAllowed.set(key, (this.#sessionAllowed.get(key) ?? 0) + 1);
    // The grant and each use it satisfied: the rule grant marked, and the
    // number of uses so far. Counts only, never a target.
    const sessionUse = resolved.approval === "session";
    const grantDetail = (index: number) => {
      const grant = grants[index];
      if (!grant || !(resolved.remember === "session" || sessionUse)) return {};
      return {
        ...(grant.rule ? { sessionGrant: "rule" } : {}),
        ...(sessionUse
          ? { sessionUses: String(this.#sessionAllowed.get(grant.key)) }
          : {}),
      };
    };
    const answer = {
      ...(resolved.approval ? { approval: resolved.approval } : {}),
      ...(resolved.remember ? { remember: resolved.remember } : {}),
      // `source` is taken (a tool call's origin), so the switch that
      // approved gets its own key. The stored auto mode, the usual one,
      // leaves none.
      ...(auto === "yolo" ? { autoSource: "yolo" } : {}),
    };
    // Each decision of a combined prompt keeps its own event and rule; the
    // answer is recorded on the ones that asked. A resource that was allowed
    // in a call whose tool ask was refused records nothing: it never ran.
    const records = [
      ...(tool
        ? [
            {
              action: "tool.execute" as const,
              effect: tool.decision.effect,
              events: {
                allowed: "tool.allowed",
                denied: "tool.denied",
              } as const,
              fields: {
                resource: tool.tool,
                policy: tool.decision.policyId,
                rule: tool.decision.ruleId,
                enforcement: tool.decision.enforcement,
                detail: {
                  action: "tool.execute",
                  ...tool.detail,
                  ...answer,
                  ...grantDetail(0),
                },
              },
            },
          ]
        : []),
      ...(own.effect !== "allow" || resolved.outcome === "allow"
        ? [
            {
              action,
              effect: own.effect,
              events,
              fields: {
                resource: events?.resource ?? redact(own.resource),
                policy: own.policyId,
                rule: own.ruleId,
                enforcement: own.enforcement,
                detail: {
                  action,
                  ...(events?.detail ?? {}),
                  ...(own.effect === "ask"
                    ? { ...answer, ...grantDetail(tool ? 1 : 0) }
                    : {}),
                },
                ...(events?.content ? { content: events.content } : {}),
              },
            },
          ]
        : []),
    ];
    for (const record of records) {
      const { fields } = record;
      // Metadata only: the same fields as the action's own event, no content.
      if (auto && "approval" in fields.detail)
        this.emit("policy.auto_approved", {
          resource: fields.resource,
          policy: fields.policy,
          rule: fields.rule,
          enforcement: fields.enforcement,
          detail: fields.detail,
          decision: "approved",
        });
      // Counts by action kind only; never the target or any user text.
      const kinds =
        record.effect === "allow"
          ? []
          : resolved.approval === "auto" || resolved.approval === "session"
            ? ["auto"]
            : [
                ...(prompted ? ["prompted"] : []),
                resolved.outcome === "allow" ? "approved" : "denied",
              ];
      for (const kind of kinds)
        bestEffort(() => this.metrics.recordApproval(record.action, kind));
      if (resolved.outcome === "deny") {
        this.metrics.recordPolicyDenial(record.action);
        if (record.events)
          this.emit(record.events.denied, { ...fields, decision: "denied" });
      } else if (record.events?.allowed)
        this.emit(record.events.allowed, {
          ...fields,
          decision:
            fields.detail.approval === "approved" ||
            fields.detail.approval === "auto" ||
            fields.detail.approval === "session"
              ? "approved"
              : "allowed",
        });
    }
    return resolved;
  }

  /**
   * Which switch approves these asks without a prompt, if one does: `--yolo`
   * (this session only) or the user's stored auto mode. Both keep the prompt
   * of an explicit `ask` that an enforced, team, project, or managed user
   * rule wrote to keep it. A personal user owns every layer, so `--yolo`
   * there approves every ask.
   */
  #autoApproval(
    asks: readonly ApprovalTarget[],
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
    return asks.some((ask) =>
      ask.resources.some((item) =>
        this.engine.keepsPrompt({ action: ask.action, resource: item }),
      ),
    )
      ? undefined
      : switchedOn;
  }

  /**
   * The governed built-in tools of this session that decide each file or
   * command they touch (`governedTools`): their `tool.execute` ask is
   * deferred to that decision.
   */
  resourceTools: ReadonlySet<string> = new Set();
  readonly #deferredDetail = new Map<
    string,
    Readonly<Record<string, string>>
  >();
  readonly #toolCall = new AsyncLocalStorage<{
    ask?: DeferredToolAsk | undefined;
  }>();

  /**
   * Leave a governed tool call's `tool.execute` ask to the call's first file
   * or command decision, so the user answers one prompt for both. Only an
   * `ask` is left; the caller decides anything else at once. Returns whether
   * it was left, keeping the call's audit detail for that decision.
   */
  deferToolAsk(
    callId: string,
    tool: string,
    detail: Readonly<Record<string, string>>,
  ): boolean {
    if (!this.resourceTools.has(tool)) return false;
    this.audit.assertAvailable();
    if (
      this.engine.evaluate({ action: "tool.execute", resource: tool })
        .effect !== "ask"
    )
      return false;
    this.#deferredDetail.set(callId, detail);
    return true;
  }

  /** Drop the detail of a deferred call that never ran (another hook refused it). */
  dropToolAsk(callId: string): void {
    this.#deferredDetail.delete(callId);
  }

  /**
   * Run a governed tool's execute with its `tool.execute` ask, if it has one.
   * The ask is evaluated here, not taken from the hook, so it holds even for
   * a call whose ID the hook did not see; only the audit detail is looked up.
   */
  withToolCall<T>(callId: string, tool: string, run: () => T): T {
    const detail = this.#deferredDetail.get(callId) ?? {};
    this.#deferredDetail.delete(callId);
    const decision = this.resourceTools.has(tool)
      ? this.engine.evaluate({ action: "tool.execute", resource: tool })
      : undefined;
    // Only an ask is carried: a deny was already blocked by the tool_call
    // hook, which Pi runs before every execute, top-level and nested.
    return this.#toolCall.run(
      decision?.effect === "ask" ? { ask: { tool, decision, detail } } : {},
      run,
    );
  }

  /**
   * The asks the user answered "allow for this session" (see `#sessionGrant`),
   * with the number of later asks each one approved. In memory only, so it
   * ends with the session and no other session (a subagent child included)
   * sees it; a `deny` never consults it, and nothing here is stored.
   */
  readonly #sessionAllowed = new Map<string, number>();

  /**
   * What "allow for this session" grants for one ask. Where the user owns the
   * policy or the administrator allows auto-approval (`policy.userAuto`), an
   * ask that one rule of the user's preferences or the distribution defaults
   * decides on every target, that no rule keeps the prompt of, and whose
   * pattern does not match everything, grants that rule for that action: any
   * target it asks for next. Any other grants its exact targets.
   */
  #sessionGrant(ask: ApprovalTarget): {
    key: string;
    rule?: string;
    pattern?: string;
  } {
    const exact = { key: sessionAllowKey(ask.action, ask.resources) };
    if (
      this.options.lock.deployment.mode !== "personal" &&
      !this.#userAuto.allowed
    )
      return exact;
    const explained = ask.resources
      .map((resource) => this.engine.explain({ action: ask.action, resource }))
      .filter((explanation) => explanation.decision.effect !== "allow");
    const asked = explained.map((explanation) => explanation.decision);
    const [first] = asked;
    const byRule =
      first !== undefined &&
      (first.layer === "user-preference" ||
        first.layer === "distribution-default") &&
      asked.every(
        (decision) =>
          decision.effect === "ask" &&
          decision.layer === first.layer &&
          decision.ruleId === first.ruleId,
      ) &&
      !ask.resources.some((resource) =>
        this.engine.keepsPrompt({ action: ask.action, resource }),
      );
    if (!byRule) return exact;
    const pattern = explained[0]?.matches.find(
      (match) =>
        match.first &&
        match.layer === first.layer &&
        match.ruleId === first.ruleId,
    )?.resource;
    if (pattern === undefined) return exact;
    const pathAction = isPathAction(ask.action);
    if (
      !hasLiteralPrefix(
        pathAction ? expandPathTokens(pattern, this.engine.context) : pattern,
        pathAction,
      )
    )
      return exact;
    return {
      key: JSON.stringify([ask.action, first.layer, first.ruleId]),
      rule: first.ruleId,
      pattern,
    };
  }

  /**
   * Whether the prompt may offer "allow for this session". Not for an ask an
   * enforced, team, project, or managed user rule wrote to keep its prompt:
   * that rule asks for a confirmation each time. A personal user owns every
   * layer, as with `--yolo`.
   */
  #offersSession(action: PolicyAction, resources: readonly string[]): boolean {
    // A grant for an unnamed push target would cover every later bare push.
    if (action === "git.push" && resources.some((item) => item.includes("*")))
      return false;
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
