import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { PISHIP_ERROR_CODES, POLICY_ACTIONS } from "@piship/contracts";

export const METRICS_SCHEMA = "piship-metrics/v1" as const;
export const METRICS_FILE = join("logs", "metrics.json");

export type McpHealthState = "healthy" | "degraded" | "failed";
export type SandboxContainment = "enforced" | "unavailable" | "not-required";

export interface McpHealthMetric {
  readonly state: McpHealthState;
  readonly healthy: number;
  readonly degraded: number;
  readonly failed: number;
  readonly updatedAt: string;
}

export interface SandboxMetric {
  readonly level: SandboxContainment;
  /** Adapter identifier such as `linux-bubblewrap`; never a path. */
  readonly adapter?: string;
  readonly updatedAt: string;
}

export interface StartupLatencyMetric {
  readonly count: number;
  readonly lastMs: number;
  readonly minMs: number;
  readonly maxMs: number;
  readonly totalMs: number;
}

/** Operations whose duration is recorded, by fixed name. */
export type LatencyMetricKind =
  | "identity"
  | "credential.acquire"
  | "credential.refresh";
const LATENCY_KINDS = new Set<string>([
  "identity",
  "credential.acquire",
  "credential.refresh",
]);

export interface GatewayReachabilityMetric {
  /** Result of the most recent gateway request or probe. */
  readonly reachable: boolean;
  /** PiShip error code of the most recent failure, when it was unreachable. */
  readonly code?: string;
  readonly reachableCount: number;
  readonly unreachableCount: number;
  /** Time of the most recent result. */
  readonly checkedAt: string;
  /** Time of the most recent reachable result. */
  readonly lastReachableAt?: string;
}

export interface ModelCatalogMetric {
  /** Time of the most recent successful catalog fetch. */
  readonly fetchedAt: string;
  /** Number of models in that catalog. */
  readonly models: number;
}

/** Versions of the running distribution; semantic versions only. */
export interface VersionsMetric {
  readonly distribution: string;
  readonly piship: string;
  readonly pi: string;
  readonly node?: string;
  readonly updatedAt: string;
}

/** Load failures by component class: `resource` or `provider`. */
export type LoadFailureKind = "resource" | "provider";

/** Metadata-only operational signals. Every string is an identifier or code. */
export interface MetricsSnapshot {
  readonly schema: typeof METRICS_SCHEMA;
  readonly updatedAt: string;
  readonly policyDenials: Readonly<Record<string, number>>;
  readonly mcpHealth: Readonly<Record<string, McpHealthMetric>>;
  readonly sandbox?: SandboxMetric;
  readonly startupFailures: Readonly<Record<string, number>>;
  readonly startupLatency?: StartupLatencyMetric;
  /** Update, check, and rollback outcomes: `<kind>:ok` or `<kind>:<error code>`. */
  readonly lifecycle?: Readonly<Record<string, number>>;
  /** Identity and credential durations, by operation. */
  readonly latency?: Readonly<
    Partial<Record<LatencyMetricKind, StartupLatencyMetric>>
  >;
  readonly gateway?: GatewayReachabilityMetric;
  readonly modelCatalog?: ModelCatalogMetric;
  /** Resource load failures by PiShip error code (`UNKNOWN` otherwise). */
  readonly resourceLoadFailures?: Readonly<Record<string, number>>;
  /** Provider load failures by PiShip error code (`UNKNOWN` otherwise). */
  readonly providerLoadFailures?: Readonly<Record<string, number>>;
  readonly versions?: VersionsMetric;
}

export type LifecycleMetricKind = "update" | "check" | "rollback";
const LIFECYCLE_KINDS = new Set<string>(["update", "check", "rollback"]);
function lifecycleKey(key: string): boolean {
  const [kind, outcome, extra] = key.split(":");
  return (
    extra === undefined &&
    LIFECYCLE_KINDS.has(kind ?? "") &&
    (outcome === "ok" ||
      outcome === "UNKNOWN" ||
      ERROR_CODES.has(outcome ?? ""))
  );
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const ACTIONS = new Set<string>(POLICY_ACTIONS);
const ERROR_CODES = new Set<string>(PISHIP_ERROR_CODES);
const MCP_STATES = new Set<string>(["healthy", "degraded", "failed"]);
const CONTAINMENT = new Set<string>([
  "enforced",
  "unavailable",
  "not-required",
]);
const MAX_ENTRIES = 256;

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isTime(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
  );
}

const VERSION = /^\d{1,9}\.\d{1,9}\.\d{1,9}(?:-[0-9A-Za-z.-]{1,32})?$/;

function isVersion(value: unknown): value is string {
  return typeof value === "string" && VERSION.test(value);
}

function isErrorKey(key: string): boolean {
  return ERROR_CODES.has(key) || key === "UNKNOWN";
}

function durationStat(value: unknown): StartupLatencyMetric | undefined {
  const item = value as Record<string, unknown> | null | undefined;
  if (
    item &&
    typeof item === "object" &&
    isCount(item.count) &&
    isCount(item.lastMs) &&
    isCount(item.minMs) &&
    isCount(item.maxMs) &&
    isCount(item.totalMs)
  )
    return {
      count: item.count,
      lastMs: item.lastMs,
      minMs: item.minMs,
      maxMs: item.maxMs,
      totalMs: item.totalMs,
    };
  return undefined;
}

function addDuration(
  current: StartupLatencyMetric | undefined,
  ms: number,
): StartupLatencyMetric {
  const value = Math.round(ms);
  return current
    ? {
        count: current.count + 1,
        lastMs: value,
        minMs: Math.min(current.minMs, value),
        maxMs: Math.max(current.maxMs, value),
        totalMs: current.totalMs + value,
      }
    : { count: 1, lastMs: value, minMs: value, maxMs: value, totalMs: value };
}

function counters(
  value: unknown,
  accept: (key: string) => boolean,
): Record<string, number> {
  const output: Record<string, number> = {};
  if (!value || typeof value !== "object") return output;
  for (const [key, count] of Object.entries(value))
    if (accept(key) && isCount(count)) output[key] = count;
  return output;
}

/**
 * Local operational metrics for doctor. Only identifiers, codes, states, and
 * numbers are stored; unexpected strings are rejected at record and load time.
 */
export class LocalMetrics {
  readonly path: string;
  readonly #now: () => Date;
  #policyDenials: Record<string, number> = {};
  #mcpHealth: Record<string, McpHealthMetric> = {};
  #sandbox: SandboxMetric | undefined;
  #startupFailures: Record<string, number> = {};
  #startupLatency: StartupLatencyMetric | undefined;
  #lifecycle: Record<string, number> = {};
  #latency: Partial<Record<LatencyMetricKind, StartupLatencyMetric>> = {};
  #gateway: GatewayReachabilityMetric | undefined;
  #modelCatalog: ModelCatalogMetric | undefined;
  #resourceLoadFailures: Record<string, number> = {};
  #providerLoadFailures: Record<string, number> = {};
  #versions: VersionsMetric | undefined;
  #updatedAt: string;

  constructor(stateDir: string, options: { readonly now?: () => Date } = {}) {
    this.path = join(stateDir, METRICS_FILE);
    this.#now = options.now ?? (() => new Date());
    this.#updatedAt = this.#time();
  }

  /** Load existing metrics; an unreadable or invalid file starts empty. */
  static load(
    stateDir: string,
    options: { readonly now?: () => Date } = {},
  ): LocalMetrics {
    const metrics = new LocalMetrics(stateDir, options);
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(metrics.path, "utf8"));
    } catch {
      return metrics;
    }
    metrics.#restore(raw);
    return metrics;
  }

  recordPolicyDenial(action: string): void {
    if (!ACTIONS.has(action)) return;
    this.#increment(this.#policyDenials, action);
  }

  recordMcpHealth(serverId: string, state: McpHealthState): void {
    if (!isIdentifier(serverId) || !MCP_STATES.has(state)) return;
    const current = this.#mcpHealth[serverId];
    if (!current && Object.keys(this.#mcpHealth).length >= MAX_ENTRIES) return;
    const base = current ?? { healthy: 0, degraded: 0, failed: 0 };
    this.#mcpHealth[serverId] = {
      state,
      healthy: base.healthy + (state === "healthy" ? 1 : 0),
      degraded: base.degraded + (state === "degraded" ? 1 : 0),
      failed: base.failed + (state === "failed" ? 1 : 0),
      updatedAt: this.#touch(),
    };
  }

  recordSandbox(level: SandboxContainment, adapter?: string): void {
    if (!CONTAINMENT.has(level)) return;
    this.#sandbox = {
      level,
      ...(isIdentifier(adapter) ? { adapter } : {}),
      updatedAt: this.#touch(),
    };
  }

  /** Count a startup failure by PiShip error code; other codes count as UNKNOWN. */
  recordStartupFailure(code: string): void {
    this.#increment(
      this.#startupFailures,
      ERROR_CODES.has(code) ? code : "UNKNOWN",
    );
  }

  recordStartupLatency(ms: number): void {
    if (!Number.isFinite(ms) || ms < 0) return;
    this.#startupLatency = addDuration(this.#startupLatency, ms);
    this.#touch();
  }

  /**
   * Duration of an identity sign-in or session check (`identity`), or of a
   * credential acquisition or refresh (`credential.acquire`,
   * `credential.refresh`), in milliseconds.
   */
  recordLatency(kind: LatencyMetricKind, ms: number): void {
    if (!LATENCY_KINDS.has(kind) || !Number.isFinite(ms) || ms < 0) return;
    this.#latency[kind] = addDuration(this.#latency[kind], ms);
    this.#touch();
  }

  recordIdentityLatency(ms: number): void {
    this.recordLatency("identity", ms);
  }

  recordCredentialLatency(operation: "acquire" | "refresh", ms: number): void {
    if (operation !== "acquire" && operation !== "refresh") return;
    this.recordLatency(`credential.${operation}`, ms);
  }

  /**
   * Result of a gateway request or probe. Unreachable results carry a PiShip
   * error code (`UNKNOWN` otherwise); never a URL, host, or response.
   */
  recordGatewayReachability(reachable: boolean, code?: string): void {
    if (typeof reachable !== "boolean") return;
    const current = this.#gateway;
    const checkedAt = this.#touch();
    const lastReachableAt = reachable ? checkedAt : current?.lastReachableAt;
    this.#gateway = {
      reachable,
      ...(reachable
        ? {}
        : { code: code && ERROR_CODES.has(code) ? code : "UNKNOWN" }),
      reachableCount: (current?.reachableCount ?? 0) + (reachable ? 1 : 0),
      unreachableCount: (current?.unreachableCount ?? 0) + (reachable ? 0 : 1),
      checkedAt,
      ...(lastReachableAt ? { lastReachableAt } : {}),
    };
  }

  /** A successful model catalog fetch and its model count; never model data. */
  recordModelCatalogFetch(models: number): void {
    if (!isCount(models)) return;
    this.#modelCatalog = { fetchedAt: this.#touch(), models };
  }

  /** Count a resource or provider load failure by PiShip error code. */
  recordLoadFailure(kind: LoadFailureKind, code: string): void {
    const target =
      kind === "resource"
        ? this.#resourceLoadFailures
        : kind === "provider"
          ? this.#providerLoadFailures
          : undefined;
    if (!target) return;
    this.#increment(target, ERROR_CODES.has(code) ? code : "UNKNOWN");
  }

  /**
   * Distribution, PiShip, Pi, and Node versions of the running release.
   * Ignored unless every given value is a semantic version.
   */
  recordVersions(versions: {
    readonly distribution: string;
    readonly piship: string;
    readonly pi: string;
    readonly node?: string;
  }): void {
    if (
      !isVersion(versions.distribution) ||
      !isVersion(versions.piship) ||
      !isVersion(versions.pi) ||
      (versions.node !== undefined && !isVersion(versions.node))
    )
      return;
    this.#versions = {
      distribution: versions.distribution,
      piship: versions.piship,
      pi: versions.pi,
      ...(versions.node !== undefined ? { node: versions.node } : {}),
      updatedAt: this.#touch(),
    };
  }

  /** Count an update, check, or rollback by outcome (`ok` or an error code). */
  recordLifecycle(kind: LifecycleMetricKind, outcome: string): void {
    if (!LIFECYCLE_KINDS.has(kind)) return;
    const code =
      outcome === "ok" || ERROR_CODES.has(outcome) ? outcome : "UNKNOWN";
    this.#increment(this.#lifecycle, `${kind}:${code}`);
  }

  snapshot(): MetricsSnapshot {
    return {
      schema: METRICS_SCHEMA,
      updatedAt: this.#updatedAt,
      policyDenials: { ...this.#policyDenials },
      mcpHealth: structuredClone(this.#mcpHealth),
      ...(this.#sandbox ? { sandbox: { ...this.#sandbox } } : {}),
      startupFailures: { ...this.#startupFailures },
      ...(this.#startupLatency
        ? { startupLatency: { ...this.#startupLatency } }
        : {}),
      ...(Object.keys(this.#lifecycle).length
        ? { lifecycle: { ...this.#lifecycle } }
        : {}),
      ...(Object.keys(this.#latency).length
        ? { latency: structuredClone(this.#latency) }
        : {}),
      ...(this.#gateway ? { gateway: { ...this.#gateway } } : {}),
      ...(this.#modelCatalog
        ? { modelCatalog: { ...this.#modelCatalog } }
        : {}),
      ...(Object.keys(this.#resourceLoadFailures).length
        ? { resourceLoadFailures: { ...this.#resourceLoadFailures } }
        : {}),
      ...(Object.keys(this.#providerLoadFailures).length
        ? { providerLoadFailures: { ...this.#providerLoadFailures } }
        : {}),
      ...(this.#versions ? { versions: { ...this.#versions } } : {}),
    };
  }

  /** Atomically write `logs/metrics.json` (directory 0700, file 0600). */
  save(): void {
    const directory = dirname(this.path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") chmodSync(directory, 0o700);
    const temporary = `${this.path}.${process.pid}.tmp`;
    try {
      writeFileSync(
        temporary,
        `${JSON.stringify(this.snapshot(), null, 2)}\n`,
        {
          mode: 0o600,
          flag: "w",
        },
      );
      if (process.platform !== "win32") chmodSync(temporary, 0o600);
      renameSync(temporary, this.path);
    } catch (error) {
      rmSync(temporary, { force: true });
      throw error;
    }
  }

  #time(): string {
    return this.#now().toISOString();
  }

  #touch(): string {
    this.#updatedAt = this.#time();
    return this.#updatedAt;
  }

  #increment(target: Record<string, number>, key: string): void {
    if (!(key in target) && Object.keys(target).length >= MAX_ENTRIES) return;
    target[key] = (target[key] ?? 0) + 1;
    this.#touch();
  }

  #restore(raw: unknown): void {
    if (!raw || typeof raw !== "object") return;
    const value = raw as Record<string, unknown>;
    if (value.schema !== METRICS_SCHEMA) return;
    if (isTime(value.updatedAt)) this.#updatedAt = value.updatedAt;
    this.#policyDenials = counters(value.policyDenials, (key) =>
      ACTIONS.has(key),
    );
    this.#startupFailures = counters(
      value.startupFailures,
      (key) => ERROR_CODES.has(key) || key === "UNKNOWN",
    );
    if (value.mcpHealth && typeof value.mcpHealth === "object")
      for (const [id, entry] of Object.entries(value.mcpHealth)) {
        const item = entry as Record<string, unknown> | null;
        if (
          isIdentifier(id) &&
          item &&
          MCP_STATES.has(item.state as string) &&
          isCount(item.healthy) &&
          isCount(item.degraded) &&
          isCount(item.failed) &&
          isTime(item.updatedAt)
        )
          this.#mcpHealth[id] = {
            state: item.state as McpHealthState,
            healthy: item.healthy,
            degraded: item.degraded,
            failed: item.failed,
            updatedAt: item.updatedAt,
          };
      }
    this.#lifecycle = counters(value.lifecycle, lifecycleKey);
    const sandbox = value.sandbox as Record<string, unknown> | undefined;
    if (
      sandbox &&
      CONTAINMENT.has(sandbox.level as string) &&
      isTime(sandbox.updatedAt)
    )
      this.#sandbox = {
        level: sandbox.level as SandboxContainment,
        ...(isIdentifier(sandbox.adapter) ? { adapter: sandbox.adapter } : {}),
        updatedAt: sandbox.updatedAt,
      };
    this.#startupLatency = durationStat(value.startupLatency);
    if (value.latency && typeof value.latency === "object")
      for (const [kind, entry] of Object.entries(value.latency)) {
        const stat = durationStat(entry);
        if (LATENCY_KINDS.has(kind) && stat)
          this.#latency[kind as LatencyMetricKind] = stat;
      }
    const gateway = value.gateway as Record<string, unknown> | undefined;
    if (
      gateway &&
      typeof gateway.reachable === "boolean" &&
      isCount(gateway.reachableCount) &&
      isCount(gateway.unreachableCount) &&
      isTime(gateway.checkedAt)
    ) {
      const code =
        typeof gateway.code === "string" && isErrorKey(gateway.code)
          ? gateway.code
          : undefined;
      this.#gateway = {
        reachable: gateway.reachable,
        ...(!gateway.reachable ? { code: code ?? "UNKNOWN" } : {}),
        reachableCount: gateway.reachableCount,
        unreachableCount: gateway.unreachableCount,
        checkedAt: gateway.checkedAt,
        ...(isTime(gateway.lastReachableAt)
          ? { lastReachableAt: gateway.lastReachableAt }
          : {}),
      };
    }
    const catalog = value.modelCatalog as Record<string, unknown> | undefined;
    if (catalog && isTime(catalog.fetchedAt) && isCount(catalog.models))
      this.#modelCatalog = {
        fetchedAt: catalog.fetchedAt,
        models: catalog.models,
      };
    this.#resourceLoadFailures = counters(
      value.resourceLoadFailures,
      isErrorKey,
    );
    this.#providerLoadFailures = counters(
      value.providerLoadFailures,
      isErrorKey,
    );
    const versions = value.versions as Record<string, unknown> | undefined;
    if (
      versions &&
      isVersion(versions.distribution) &&
      isVersion(versions.piship) &&
      isVersion(versions.pi) &&
      (versions.node === undefined || isVersion(versions.node)) &&
      isTime(versions.updatedAt)
    )
      this.#versions = {
        distribution: versions.distribution,
        piship: versions.piship,
        pi: versions.pi,
        ...(versions.node !== undefined
          ? { node: versions.node as string }
          : {}),
        updatedAt: versions.updatedAt,
      };
  }
}
