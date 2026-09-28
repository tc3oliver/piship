// Launch-time governance for piship/v1alpha3 distributions: audit, project
// origin, sandbox, policy, resource and provider trust, capability state, and
// MCP. Every mandatory control that cannot be established fails the launch.
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { AuditLog, LocalMetrics } from "@piship/audit";
import {
  type ApprovalChannel,
  type AuditEventType,
  type ManagedFetch,
  type PolicyAction,
  PiShipError,
  type ResolvedDecision,
  redact,
  resolveDecision,
} from "@piship/contracts";
import {
  type DistributionLock,
  type GovernanceLock,
  treeDigest,
} from "@piship/core";
import {
  type McpAuditEvent,
  McpGovernor,
  type McpServerConfig,
  type McpServerReport,
  parseExternalMcpDefinitions,
} from "@piship/mcp";
import {
  type CapabilityState,
  type ProjectIdentity,
  type ProjectResourceCandidate,
  PolicyEngine,
  type ProviderTrustDecision,
  type VerificationResult,
  computeCapabilityStates,
  discoverProjectResources,
  identifyProject,
  parseRuleList,
  providerTrustDecision,
  readProjectRestrictions,
  resourceTrustDecision,
} from "@piship/policy";
import {
  type ActiveSandbox,
  type ContainmentReport,
  activateSandbox,
  adapterIdFor,
  describeContainment,
} from "@piship/sandbox";
import type {
  BuiltinExtension,
  DeclaredResource,
  GovernanceManifest,
  PolicyRule,
  ResourceKind,
} from "@piship/schema";

export interface GovernanceOptions {
  readonly lock: DistributionLock & { readonly governance: GovernanceLock };
  readonly distributionDir: string;
  readonly stateDir: string;
  readonly cwd: string;
  readonly piVersion: string;
  /** Whether a person can answer startup approvals on this terminal. */
  readonly interactive: boolean;
  readonly fetch: ManagedFetch;
  readonly resolveTemplate: (key: string, template: string) => string;
  /** Identity subject for audit events; never a token. */
  readonly user?: string | null;
  /** Bearer for `credential: runtime` MCP servers. */
  readonly credential?: () => Promise<string | undefined>;
  readonly homeDir?: string;
  /** Override the startup approval channel (tests). */
  readonly startupApproval?: ApprovalChannel;
}

/** Evidence for one declared, builtin, or project resource. */
const STRICTNESS = { allow: 0, ask: 1, deny: 2 } as const;

export interface DecisionEvents {
  readonly allowed?: AuditEventType;
  readonly denied: AuditEventType;
  /** Metadata-only resource for the audit record (defaults to the redacted resource). */
  readonly resource?: string;
  /**
   * What the approval prompt shows the person, such as the tool and its
   * path or command. It is redacted and never written to audit.
   */
  readonly prompt?: string;
  readonly detail?: Readonly<Record<string, string | number | boolean | null>>;
  /** Content kept only for classes the distribution opted in to capture. */
  readonly content?: Readonly<Record<string, string>>;
}

export interface ResourceEvidence {
  readonly kind: ResourceKind | "mcp" | "settings" | "agents" | "providers";
  readonly class: string;
  readonly path: string;
  readonly loaded: boolean;
  readonly reason: string;
  readonly integrity?: "verified" | "not-applicable";
  readonly compatible?: boolean;
  readonly origin?: string;
}

export interface LoaderInputs {
  readonly instructions: readonly { path: string; content: string }[];
  readonly skills: readonly string[];
  readonly extensions: readonly string[];
  readonly prompts: readonly string[];
  readonly themes: readonly string[];
  readonly builtin: ReadonlySet<BuiltinExtension>;
}

const KIND_ACTION: Readonly<Record<string, PolicyAction>> = {
  instructions: "instruction.load",
  skills: "skill.load",
  extensions: "extension.load",
  prompts: "resource.load",
  themes: "resource.load",
};

/** Longest subject shown in an approval prompt. */
const APPROVAL_SUBJECT_MAX = 2000;

/** The redacted subject of an approval prompt, shortened for a dialog. */
function approvalSubject(subject: string): string {
  const shown = redact(subject);
  return shown.length > APPROVAL_SUBJECT_MAX
    ? `${shown.slice(0, APPROVAL_SUBJECT_MAX)}…`
    : shown;
}

function sha256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Hash the installed files of one declared root inside the payload. */
function payloadTree(resourceDir: string, declared: string): string {
  const root = join(resourceDir, ...declared.slice(2).split("/"));
  const files: { path: string; sha256: string }[] = [];
  const visit = (path: string) => {
    const stat = statSync(path);
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) visit(join(path, name));
      return;
    }
    const rel = relative(root, path).split(sep).join("/");
    files.push({
      path: rel === "" ? (declared.split("/").at(-1) ?? declared) : rel,
      sha256: sha256(readFileSync(path)),
    });
  };
  if (existsSync(root)) visit(root);
  return treeDigest(files);
}

/** A y/N prompt on the terminal before the TUI starts; headless has none. */
export function terminalApproval(): ApprovalChannel | undefined {
  if (!process.stdin.isTTY || !process.stderr.isTTY) return undefined;
  return async (_decision, detail) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });
    try {
      const answer = await new Promise<string>((done) =>
        rl.question(`${detail.title}\n${detail.message}\nAllow? [y/N] `, done),
      );
      return /^y(es)?$/i.test(answer.trim()) ? "approved" : "denied";
    } finally {
      rl.close();
    }
  };
}

function readUserRules(stateDir: string): PolicyRule[] {
  const path = join(stateDir, "config", "policy.json");
  if (!existsSync(path)) return [];
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new PiShipError(
      "CONFIG_INVALID",
      "The user policy file is not valid JSON",
      { userAction: `Fix or remove ${path}` },
    );
  }
  return [
    ...parseRuleList(value, "user-preference", { narrowingOnly: false }).rules,
  ];
}

async function readTeamRules(
  distributionDir: string,
  adapter: string | undefined,
): Promise<PolicyRule[]> {
  if (!adapter) return [];
  const path = join(
    distributionDir,
    "resources",
    ...adapter.slice(2).split("/"),
  );
  let exported: unknown;
  try {
    const module = (await import(pathToFileURL(path).href)) as {
      default?: unknown;
      rules?: unknown;
    };
    const source = module.rules ?? module.default;
    exported = typeof source === "function" ? await source() : source;
  } catch (error) {
    // A required policy that cannot load fails closed.
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `The policy adapter could not be loaded: ${redact(String((error as Error)?.message ?? error))}`,
      { component: "policy" },
    );
  }
  return withIgnored(
    parseRuleList(exported, "team-project", { narrowingOnly: true }),
  );
}

/** Keep ignored allow rules so the engine reports them in explain and doctor. */
function withIgnored(parsed: {
  readonly rules: readonly PolicyRule[];
  readonly ignored: readonly { readonly rule: PolicyRule }[];
}): PolicyRule[] {
  return [...parsed.rules, ...parsed.ignored.map((item) => item.rule)];
}

function discoverProject(options: GovernanceOptions, homeDir: string) {
  const manifest = options.lock.governance.manifest;
  const project = identifyProject(options.cwd, manifest.policy.projectTrust, {
    homeDir,
  });
  const candidates = discoverProjectResources(project, manifest.policy, {
    homeDir,
  });
  return { project, candidates };
}

function sandboxConfig(options: GovernanceOptions) {
  const sandbox = options.lock.governance.manifest.sandbox;
  return {
    ...sandbox,
    filesystem: {
      ...sandbox.filesystem,
      read: { deny: [...sandbox.filesystem.read.deny, options.stateDir] },
    },
  };
}

async function buildEngine(
  options: GovernanceOptions,
  project: ProjectIdentity,
  candidates: readonly ProjectResourceCandidate[],
  report: ContainmentReport,
  tmpDir: string,
  homeDir: string,
): Promise<PolicyEngine> {
  const manifest = options.lock.governance.manifest;
  const enforced = report.level === "enforced";
  return new PolicyEngine({
    policy: manifest.policy,
    teamRules: await readTeamRules(
      options.distributionDir,
      manifest.policy.adapter,
    ),
    projectRules: withIgnored(readProjectRestrictions(candidates)),
    userRules: readUserRules(options.stateDir),
    context: {
      workspaceRoot: project.root,
      homeDir,
      tmpDir,
      containment: {
        filesystem:
          enforced &&
          report.planes.some((plane) => plane.startsWith("filesystem")),
        network: enforced && report.network === "deny",
        shell: enforced,
      },
    },
  });
}

/** Provider trust and payload verification, from the lock and the payload. */
function providerEvidence(options: GovernanceOptions): {
  trust: Record<string, ProviderTrustDecision>;
  verification: Record<string, VerificationResult>;
} {
  const { lock, distributionDir } = options;
  const resourceDir = join(distributionDir, "resources");
  const trust: Record<string, ProviderTrustDecision> = {};
  const verification: Record<string, VerificationResult> = {};
  for (const entry of lock.governance.providers) {
    trust[entry.id] = providerTrustDecision(
      lock.governance.manifest.policy,
      entry.class as Parameters<typeof providerTrustDecision>[1],
    );
    if (entry.path && entry.integrity) {
      const found = payloadTree(resourceDir, entry.path);
      verification[entry.id] =
        found === entry.integrity
          ? { ok: true }
          : { ok: false, reason: "provider files do not match the lock" };
    }
  }
  return { trust, verification };
}

function capabilityStates(
  options: GovernanceOptions,
  workflowLoaded: boolean,
  policyDenied: Readonly<Record<string, string>> = {},
): CapabilityState[] {
  const manifest = options.lock.governance.manifest;
  const { trust, verification } = providerEvidence(options);
  return computeCapabilityStates({
    capabilities: manifest.capabilities,
    providerTrust: trust,
    verification,
    piVersion: options.piVersion,
    platform: process.platform,
    health: {
      permissions: { ok: true },
      ...(manifest.capabilities.some(
        (item) => item.name === "workflow" && item.enabled,
      )
        ? {
            workflow: workflowLoaded
              ? { ok: true }
              : {
                  ok: false,
                  reason: "the workflow extension is not loaded",
                },
          }
        : {}),
      ...Object.fromEntries(
        Object.entries(policyDenied).map(([name, reason]) => [
          name,
          { ok: false, reason: `the provider is not loaded: ${reason}` },
        ]),
      ),
    },
  });
}

/** Provider requests the policy decides before a provider's extension loads. */
function providerRequests(
  provider: GovernanceLock["providers"][number],
): [PolicyAction, string][] {
  const requests: [PolicyAction, string][] = [["provider.load", provider.id]];
  if (provider.path)
    requests.push(["extension.load", `${provider.class}:${provider.path}`]);
  return requests;
}

/** Capabilities whose non-builtin provider the policy always denies. */
function staticProviderDenials(
  options: GovernanceOptions,
  engine: PolicyEngine,
): Record<string, string> {
  const denied: Record<string, string> = {};
  for (const provider of options.lock.governance.providers) {
    if (provider.class === "builtin") continue;
    for (const [action, resource] of providerRequests(provider)) {
      const decision = engine.evaluate({ action, resource });
      if (decision.effect !== "deny") continue;
      denied[provider.capability] = `policy ${decision.ruleId} (${action})`;
      break;
    }
  }
  return denied;
}

export interface GovernanceInspection {
  readonly project: ProjectIdentity;
  readonly candidates: readonly ProjectResourceCandidate[];
  readonly sandbox: ContainmentReport;
  readonly containment: string;
  readonly engine: PolicyEngine;
  readonly capabilities: readonly CapabilityState[];
  /** Declared resources as trust and integrity see them, before approvals. */
  readonly resources: readonly ResourceEvidence[];
}

/**
 * Static governance state for doctor, `policy explain`, and `capabilities`:
 * no audit, no MCP start, no approvals. The sandbox probe runs so the
 * reported containment is the real one; a required sandbox that is
 * unavailable is reported, not thrown.
 */
export async function inspectGovernance(
  options: GovernanceOptions,
): Promise<GovernanceInspection> {
  const homeDir = options.homeDir ?? homedir();
  const manifest = options.lock.governance.manifest;
  const { project, candidates } = discoverProject(options, homeDir);
  let report: ContainmentReport;
  let tmpDir = tmpdir();
  try {
    const sandbox = await activateSandbox(sandboxConfig(options), {
      workspace: project.root,
      homeDir,
      // MCP modules run from the installed payload, which may sit under a
      // directory the sandbox otherwise replaces (such as /tmp).
      extraReadOnly: [options.distributionDir],
    });
    report = sandbox.report;
    tmpDir = sandbox.profile.tmpDir;
    sandbox.dispose();
  } catch (error) {
    report = {
      level: "unavailable",
      adapter: adapterIdFor(process.platform),
      required: manifest.sandbox.required,
      planes: [],
      network: manifest.sandbox.network.mode,
      reason: redact(String((error as Error)?.message ?? error)),
      warnings: [],
    };
  }
  const engine = await buildEngine(
    options,
    project,
    candidates,
    report,
    tmpDir,
    homeDir,
  );
  const resourceDir = join(options.distributionDir, "resources");
  const certified = new Map(
    options.lock.governance.certified.map((entry) => [
      `${entry.kind}:${entry.path}`,
      entry,
    ]),
  );
  const resources: ResourceEvidence[] = [];
  for (const item of manifest.resources.declared) {
    const trust = resourceTrustDecision(manifest.policy, item.class, item.kind);
    const base = { kind: item.kind, class: item.class, path: item.path };
    if (!trust.allowed) {
      resources.push({ ...base, loaded: false, reason: trust.reason });
      continue;
    }
    let integrity: ResourceEvidence["integrity"] = "not-applicable";
    let compatible = true;
    let reason = trust.reason;
    const entry = certified.get(`${item.kind}:${item.path}`);
    if (item.class === "certified") {
      const ok =
        !!entry && payloadTree(resourceDir, item.path) === entry.integrity;
      if (!ok) {
        resources.push({
          ...base,
          loaded: false,
          reason: "certified content does not match its reviewed integrity",
        });
        continue;
      }
      integrity = "verified";
      compatible =
        entry.evidence.pi.includes(options.piVersion) &&
        (entry.evidence.platforms.length === 0 ||
          entry.evidence.platforms.includes(process.platform));
      if (!compatible) reason = "not certified for this Pi version or platform";
    }
    const decision = engine.evaluate({
      action: KIND_ACTION[item.kind] ?? "resource.load",
      resource: `${item.class}:${item.path}`,
    });
    const loaded = compatible && decision.effect !== "deny";
    resources.push({
      ...base,
      loaded,
      reason:
        decision.effect === "allow"
          ? reason
          : `policy ${decision.ruleId} (${decision.effect})`,
      integrity,
      compatible,
    });
  }
  for (const name of manifest.resources.builtin) {
    const decision = engine.evaluate({
      action: "extension.load",
      resource: `builtin:${name}`,
    });
    resources.push({
      kind: "extensions",
      class: "builtin",
      path: name,
      loaded: decision.effect !== "deny",
      reason:
        decision.effect === "allow"
          ? "builtin"
          : `policy ${decision.ruleId} (${decision.effect})`,
      integrity: "not-applicable",
    });
  }
  const workflowLoaded =
    resources.some((item) => item.path === "piship-workflow" && item.loaded) ||
    options.lock.governance.providers.some(
      (item) => item.capability === "workflow" && item.class !== "builtin",
    );
  return {
    project,
    candidates,
    sandbox: report,
    containment: describeContainment(report),
    engine,
    capabilities: capabilityStates(
      options,
      workflowLoaded,
      staticProviderDenials(options, engine),
    ),
    resources,
  };
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
    const metrics = LocalMetrics.load(options.stateDir);
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
      // subprocesses never need to read it.
      sandbox = await activateSandbox(sandboxConfig(options), {
        workspace: project.root,
        homeDir,
        extraReadOnly: [options.distributionDir],
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
      // A team or project file that tries to widen the policy is recorded.
      for (const diagnostic of engine.diagnostics)
        session.emit("policy.violation", {
          policy: engine.id,
          ...(diagnostic.ruleId ? { rule: diagnostic.ruleId } : {}),
          detail: { source: diagnostic.source },
        });
      await session.#resolveResources();
      await session.#resolveProject();
      await session.#startMcp();
      await session.#computeCapabilities();
      metrics.recordStartupLatency(Date.now() - started);
      metrics.save();
      return session;
    } catch (error) {
      const code =
        error instanceof PiShipError ? error.code : "CONFIG_UNAVAILABLE";
      metrics.recordStartupFailure(code);
      metrics.save();
      sandbox?.dispose();
      await audit?.close();
      throw error;
    }
  }

  get policyId(): string {
    return this.engine.id;
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

  async #resolveResources(): Promise<void> {
    const { lock, distributionDir, piVersion } = this.options;
    const resourceDir = join(distributionDir, "resources");
    const policy = this.manifest.policy;
    const certified = new Map(
      lock.governance.certified.map((entry) => [
        `${entry.kind}:${entry.path}`,
        entry,
      ]),
    );
    for (const item of this.manifest.resources.declared) {
      const record = await this.#declared(
        item,
        resourceDir,
        certified.get(`${item.kind}:${item.path}`),
        piVersion,
      );
      this.resources.push(record);
      if (!record.loaded) continue;
      const absolute = join(resourceDir, ...item.path.slice(2).split("/"));
      if (item.kind === "instructions")
        this.loader.instructions.push({
          path: absolute,
          content: readFileSync(absolute, "utf8"),
        });
      else this.loader[item.kind].push(absolute);
    }
    for (const name of this.manifest.resources.builtin) {
      const trust = resourceTrustDecision(policy, "builtin", "extensions");
      let loaded = trust.allowed;
      let reason = trust.reason;
      if (loaded) {
        const decision = await this.decide(
          "extension.load",
          `builtin:${name}`,
          this.startupChannel(),
        );
        loaded = decision.outcome === "allow";
        if (!loaded) reason = `policy ${decision.ruleId}`;
      }
      this.emit(loaded ? "resource.load" : "resource.denied", {
        resource: `builtin:${name}`,
        detail: { kind: "extensions", class: "builtin" },
      });
      if (loaded) this.loader.builtin.add(name);
      this.resources.push({
        kind: "extensions",
        class: "builtin",
        path: name,
        loaded,
        reason,
        integrity: "not-applicable",
      });
    }
  }

  async #declared(
    item: DeclaredResource,
    resourceDir: string,
    certified: GovernanceLock["certified"][number] | undefined,
    piVersion: string,
  ): Promise<ResourceEvidence> {
    const resource = `${item.class}:${item.path}`;
    const base = {
      kind: item.kind,
      class: item.class,
      path: item.path,
    } as const;
    const deny = (reason: string, extra: Partial<ResourceEvidence> = {}) => {
      this.emit("resource.denied", {
        resource,
        detail: { kind: item.kind, class: item.class },
      });
      return { ...base, loaded: false, reason, ...extra };
    };
    const trust = resourceTrustDecision(
      this.manifest.policy,
      item.class,
      item.kind,
    );
    if (!trust.allowed) return deny(trust.reason);
    let integrity: ResourceEvidence["integrity"] = "not-applicable";
    let compatible = true;
    if (item.class === "certified") {
      if (!certified)
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `No certified evidence is locked for ${item.path}`,
          { userAction: "Re-lock and rebuild the distribution" },
        );
      const found = payloadTree(resourceDir, item.path);
      if (found !== certified.integrity)
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `Certified resource ${item.path} does not match its reviewed integrity`,
          { userAction: "Reinstall the distribution from a trusted artifact" },
        );
      integrity = "verified";
      const evidence = certified.evidence;
      compatible =
        evidence.pi.includes(piVersion) &&
        (evidence.platforms.length === 0 ||
          evidence.platforms.includes(process.platform));
      if (!compatible)
        return deny(
          `certified for Pi ${evidence.pi.join(", ")}${evidence.platforms.length ? ` on ${evidence.platforms.join(", ")}` : ""}; running Pi ${piVersion} on ${process.platform}`,
          { integrity, compatible },
        );
    }
    const decision = await this.decide(
      KIND_ACTION[item.kind] ?? "resource.load",
      resource,
      this.startupChannel(),
    );
    if (decision.outcome !== "allow")
      return deny(`policy ${decision.ruleId}`, { integrity, compatible });
    this.emit("resource.load", {
      resource,
      policy: decision.policyId,
      rule: decision.ruleId,
      detail: { kind: item.kind, class: item.class },
    });
    return {
      ...base,
      loaded: true,
      reason: trust.reason,
      integrity,
      compatible,
    };
  }

  async #resolveProject(): Promise<void> {
    const channel = this.startupChannel();
    for (const candidate of this.projectCandidates) {
      if (candidate.dimension === "restrictions") continue;
      const shown = this.#projectPath(candidate.path);
      const resource = `project:${shown}`;
      let loaded = false;
      let reason = candidate.reason;
      const kind = candidate.kind;
      const loadable = [
        "instructions",
        "instruction-import",
        "system-prompt",
        "prompts",
        "skills",
        "extensions",
        "themes",
      ].includes(kind);
      if (kind === "mcp") {
        loaded = await this.#projectMcp(candidate, channel);
        reason = loaded ? "project MCP definitions admitted" : reason;
      } else if (!loadable) {
        reason =
          candidate.effect === "deny"
            ? reason
            : `${kind} from projects are not loaded by this release`;
      } else if (
        candidate.effect !== "deny" &&
        candidate.effect !== "company-approved"
      ) {
        const trust = resourceTrustDecision(
          this.manifest.policy,
          "project",
          kind === "skills" || kind === "extensions" || kind === "themes"
            ? kind
            : kind === "prompts"
              ? "prompts"
              : "instructions",
          this.project.origin,
        );
        if (!trust.allowed) reason = trust.reason;
        else {
          const dimensionDecision =
            candidate.effect === "ask"
              ? await resolveDecision(
                  {
                    effect: "ask",
                    policyId: this.engine.id,
                    ruleId: `project-trust.${candidate.dimension}`,
                    enforcement: "control-plane",
                    action: KIND_ACTION[kind] ?? "resource.load",
                    resource,
                    layer: "distribution-enforced",
                  },
                  channel,
                  {
                    title: "Project resource",
                    message: `Load ${shown} from ${this.project.origin} project ${this.project.root}?`,
                  },
                )
              : undefined;
          if (dimensionDecision && dimensionDecision.outcome !== "allow")
            reason = `project trust ${candidate.dimension}: ${dimensionDecision.approval ?? "denied"}`;
          else {
            const decision = await this.decide(
              KIND_ACTION[
                kind === "instruction-import" || kind === "system-prompt"
                  ? "instructions"
                  : kind
              ] ?? "resource.load",
              resource,
              channel,
            );
            loaded = decision.outcome === "allow";
            if (!loaded) reason = `policy ${decision.ruleId}`;
          }
        }
      }
      if (loaded && loadable) this.#loadProject(candidate);
      this.emit(loaded ? "resource.load" : "resource.denied", {
        resource,
        detail: {
          kind,
          class: "project",
          origin: candidate.origin,
          dimension: candidate.dimension,
        },
      });
      this.resources.push({
        kind:
          kind === "instruction-import" || kind === "system-prompt"
            ? "instructions"
            : kind === "settings"
              ? "settings"
              : (kind as ResourceEvidence["kind"]),
        class: "project",
        path: shown,
        loaded,
        reason,
        origin: candidate.origin,
      });
    }
  }

  /** A project path as shown to people and audit: relative to the project root. */
  #projectPath(path: string): string {
    const rel = relative(this.project.root, path);
    return rel && !rel.startsWith("..") ? rel.split(sep).join("/") : path;
  }

  #loadProject(candidate: ProjectResourceCandidate): void {
    const path = candidate.resolvedPath;
    switch (candidate.kind) {
      case "instructions":
      case "instruction-import":
      case "system-prompt":
        this.loader.instructions.push({
          path,
          content: readFileSync(path, "utf8"),
        });
        return;
      case "skills":
        this.loader.skills.push(path);
        return;
      case "extensions":
        this.loader.extensions.push(path);
        return;
      case "prompts":
        this.loader.prompts.push(path);
        return;
      case "themes":
        this.loader.themes.push(path);
        return;
    }
  }

  #projectServers: McpServerConfig[] = [];

  async #projectMcp(
    candidate: ProjectResourceCandidate,
    channel: ApprovalChannel | undefined,
  ): Promise<boolean> {
    const mcp = this.manifest.mcp;
    if (candidate.effect === "deny") return false;
    if (candidate.allowlistOnly || mcp.mode !== "explicit") return false;
    if (mcp.project !== "allow") return false;
    if (candidate.effect === "ask") {
      const answer = await resolveDecision(
        {
          effect: "ask",
          policyId: this.engine.id,
          ruleId: "project-trust.mcp",
          enforcement: "control-plane",
          action: "mcp.server.start",
          resource: `project:${this.#projectPath(candidate.path)}`,
          layer: "distribution-enforced",
        },
        channel,
        {
          title: "Project MCP servers",
          message: `Use MCP servers defined in ${this.#projectPath(candidate.path)}?`,
        },
      );
      if (answer.outcome !== "allow") return false;
    }
    let json: unknown;
    try {
      json = JSON.parse(readFileSync(candidate.resolvedPath, "utf8"));
    } catch {
      return false;
    }
    const parsed = parseExternalMcpDefinitions(json, "project");
    const declared = new Set(mcp.servers.map((server) => server.id));
    for (const server of parsed.servers)
      if (!declared.has(server.id)) this.#projectServers.push(server);
    return parsed.servers.length > 0;
  }

  async #startMcp(): Promise<void> {
    const mcp = this.manifest.mcp;
    const servers = [
      ...(mcp.mode === "off" ? [] : mcp.servers),
      ...this.#projectServers,
    ] as McpServerConfig[];
    if (!servers.length) return;
    const channel = this.startupChannel();
    const governor = new McpGovernor({
      servers,
      distributionDir: join(this.options.distributionDir, "resources"),
      workspace: this.project.root,
      fetch: this.options.fetch,
      ...(this.sandbox.report.level === "enforced"
        ? { sandbox: this.sandbox }
        : {}),
      ...(this.options.credential
        ? {
            credential: async () => {
              const value = await this.options.credential?.();
              if (!value)
                throw new PiShipError(
                  "CREDENTIAL_REQUIRED",
                  "No runtime credential is available for the MCP server",
                );
              return value;
            },
          }
        : {}),
      // A tool the policy always denies is never offered to the model;
      // every call is still authorized when it happens.
      expose: ({ resource }) =>
        this.engine.evaluate({ action: "mcp.tool.call", resource }).effect !==
        "deny",
      authorize: async (request) => {
        const channelNow =
          request.action === "mcp.server.start"
            ? channel
            : this.currentChannel();
        const resolved = await this.decide(
          request.action,
          request.resource,
          channelNow,
        );
        return {
          allowed: resolved.outcome === "allow",
          reason: resolved.reason ?? `policy ${resolved.ruleId}`,
          decision: resolved,
        };
      },
      audit: (event: McpAuditEvent) => {
        this.emit(event.event, {
          resource: event.resource,
          ...(event.decision ? { decision: event.decision } : {}),
          ...(event.policy ? { policy: event.policy } : {}),
          ...(event.rule ? { rule: event.rule } : {}),
          ...(event.enforcement ? { enforcement: event.enforcement } : {}),
          ...(event.detail ? { detail: event.detail } : {}),
        });
      },
    });
    this.mcp = governor;
    try {
      this.mcpReports = await governor.start();
    } finally {
      for (const report of governor.health())
        if (report.state !== "denied")
          this.metrics.recordMcpHealth(report.id, report.state);
    }
  }

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

  async #computeCapabilities(): Promise<void> {
    const workflowLoaded = () =>
      this.loader.builtin.has("piship-workflow") ||
      this.#providerExtension("workflow") !== undefined;
    const states = capabilityStates(this.options, workflowLoaded());
    const denied: Record<string, string> = {};
    const channel = this.startupChannel();
    for (const state of states) {
      const provider = this.options.lock.governance.providers.find(
        (entry) => entry.capability === state.name,
      );
      if (!provider || provider.class === "builtin") continue;
      if (state.axes.effective.value !== "yes") {
        this.emit("provider.denied", {
          resource: provider.id,
          detail: { capability: state.name, version: provider.version },
        });
        continue;
      }
      // Provider trust made the capability effective; policy still decides
      // whether the provider and its extension load.
      const refusal = await this.#providerPolicy(provider, channel);
      if (refusal) {
        denied[state.name] = refusal.reason;
        this.emit("provider.denied", {
          resource: provider.id,
          policy: refusal.policyId,
          rule: refusal.ruleId,
          detail: { capability: state.name, version: provider.version },
        });
        this.resources.push({
          kind: "providers",
          class: provider.class,
          path: provider.id,
          loaded: false,
          reason: refusal.reason,
        });
        continue;
      }
      this.emit("provider.load", {
        resource: provider.id,
        detail: { capability: state.name, version: provider.version },
      });
      const extension = this.#providerExtension(state.name);
      if (extension) this.loader.extensions.push(extension);
    }
    this.capabilities = capabilityStates(
      this.options,
      workflowLoaded() && denied.workflow === undefined,
      denied,
    );
  }

  /** `provider.load` for the provider ID, then `extension.load` for its extension. */
  async #providerPolicy(
    provider: GovernanceLock["providers"][number],
    channel: ApprovalChannel | undefined,
  ): Promise<{ reason: string; policyId: string; ruleId: string } | undefined> {
    for (const [action, resource] of providerRequests(provider)) {
      const decision = await this.decide(action, resource, channel);
      if (decision.outcome !== "allow")
        return {
          reason: `policy ${decision.ruleId} (${action})`,
          policyId: decision.policyId,
          ruleId: decision.ruleId,
        };
    }
    return undefined;
  }

  #providerExtension(capability: string): string | undefined {
    const entry = this.options.lock.governance.providers.find(
      (item) => item.capability === capability,
    );
    if (!entry?.path) return undefined;
    return resolve(
      this.options.distributionDir,
      "resources",
      ...entry.path.slice(2).split("/"),
    );
  }

  /** Whether a capability is effective (all six axes). */
  effective(name: string): boolean {
    return (
      this.capabilities.find((state) => state.name === name)?.axes.effective
        .value === "yes"
    );
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.emit("session.end");
    await this.mcp?.close();
    this.sandbox.dispose();
    await this.audit.close();
    this.metrics.save();
  }
}
