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
    const value = Math.round(ms);
    const current = this.#startupLatency;
    this.#startupLatency = current
      ? {
          count: current.count + 1,
          lastMs: value,
          minMs: Math.min(current.minMs, value),
          maxMs: Math.max(current.maxMs, value),
          totalMs: current.totalMs + value,
        }
      : { count: 1, lastMs: value, minMs: value, maxMs: value, totalMs: value };
    this.#touch();
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
    const latency = value.startupLatency as Record<string, unknown> | undefined;
    if (
      latency &&
      isCount(latency.count) &&
      isCount(latency.lastMs) &&
      isCount(latency.minMs) &&
      isCount(latency.maxMs) &&
      isCount(latency.totalMs)
    )
      this.#startupLatency = {
        count: latency.count,
        lastMs: latency.lastMs,
        minMs: latency.minMs,
        maxMs: latency.maxMs,
        totalMs: latency.totalMs,
      };
  }
}
