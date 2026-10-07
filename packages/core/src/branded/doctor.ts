// The doctor groups that need no Pi runtime or governed session.
import { statfsSync } from "node:fs";
import { LocalMetrics } from "@piship/audit";
import { isLoopbackHost } from "@piship/contracts";
import { resolveTemplate } from "@piship/schema";
import {
  abandonedTemporaryCount,
  installHome,
  inspectInstalledLauncher,
  lifecycleStatus,
} from "../index.js";
import type { BrandedContext, DoctorLine } from "./context.js";
import { installedHere } from "./lifecycle.js";

/** The doctor groups whose lines need no Pi runtime or governed session. */
export type LifecycleDoctorGroup = "Supply Chain" | "Release" | "Update";

/**
 * One lifecycle group of doctor: Supply Chain (manifest, lock, and payload
 * verification), Release (where the running payload came from), or Update
 * (release tracking, channel, trust, rollback). Each group is its own call,
 * so the caller decides where it goes.
 */
export function lifecycleDoctor(
  ctx: BrandedContext,
  group: LifecycleDoctorGroup,
  ok: DoctorLine,
  warn: DoctorLine,
  failures?: DoctorFailures,
): void {
  if (group === "Supply Chain") supplyChainDoctor(ctx, ok, failures);
  else if (group === "Release") releaseDoctor(ctx, ok, warn);
  else updateDoctor(ctx, ok, warn);
}

/** What a caller passes to report a verification that failed as one failed line. */
export interface DoctorFailures {
  readonly bad: DoctorLine;
  /** Why the full payload verification failed. */
  readonly integrityProblem?: string;
}

function supplyChainDoctor(
  ctx: BrandedContext,
  ok: DoctorLine,
  failures?: DoctorFailures,
): void {
  const { metadata } = ctx;
  ok("manifest", `verified (${metadata.manifest.schema})`);
  ok("lockfile", `verified (${metadata.schema})`);
  if (failures?.integrityProblem !== undefined)
    failures.bad("integrity", failures.integrityProblem);
  else ok("integrity", "payload inventory verified by doctor");
}

function releaseDoctor(
  ctx: BrandedContext,
  ok: DoctorLine,
  warn: DoctorLine,
): void {
  const here = installedHere(ctx);
  const active = here?.releases.find((item) => item.version === here.active);
  if (active?.release)
    ok(
      "release",
      `verified ${active.release.target} artifact (${active.release.channel})`,
    );
  else if (here)
    warn("release", "installed from a payload directory, not a release");
  else ok("release", "none; running from a build directory");
}

function updateDoctor(
  ctx: BrandedContext,
  ok: DoctorLine,
  warn: DoctorLine,
): void {
  const { metadata } = ctx;
  // Doctor attempts temporary maintenance before collecting this report.
  // Only a count: the paths are not reported.
  const abandoned = abandonedTemporaryCount(metadata.app.id);
  if (abandoned > 0)
    warn(
      "temporaries",
      `${abandoned} abandoned PiShip temporary director${abandoned === 1 ? "y" : "ies"} could not be removed; check the permissions of the OS temp directory and the install home`,
    );
  const here = installedHere(ctx);
  if (!here) {
    warn("installation", "not installed; running from a build directory");
    return;
  }
  const status = lifecycleStatus(metadata.app.id, metadata);
  if (!status.tracked) {
    warn(
      "installation",
      "installed without release tracking; reinstall to enable update and rollback",
    );
    return;
  }
  ok("active", status.active ?? metadata.app.version);
  const launcher = inspectInstalledLauncher(metadata.app.id);
  if (launcher?.current) ok("launcher", `build ${launcher.expected}`);
  else if (launcher)
    warn(
      "launcher",
      `build ${launcher.build ?? "before builds were stamped"}, but this PiShip writes ${launcher.expected}; doctor and the end of a session replace it`,
    );
  if (!metadata.updates) {
    warn("updates", `not configured (${metadata.manifest.schema})`);
  } else {
    ok(
      "channel",
      `${status.channel} (allowed: ${(status.channels ?? []).join(", ")})`,
    );
    if (status.source && plainHttpSource(ctx, status.source))
      warn("source", `http (integrity by signature only): ${status.source}`);
    else if (status.source) ok("source", status.source);
    else warn("source", "none declared; update needs --from");
    if (metadata.updates.transport === "http-allowed")
      ok(
        "transport",
        "http-allowed (plain HTTP to a private or internal update host; signatures, digests, and sequence checks still apply)",
      );
    if (status.trustProblem)
      warn(
        "update trust",
        `${status.trustProblem}; update fails until trust is re-established by reinstalling a verified release`,
      );
    else if (status.updateRoot)
      ok(
        "update root",
        `version ${status.updateRoot.version} (${status.updateRoot.origin}), expires ${status.updateRoot.expires}, channel threshold ${status.updateRoot.channelThreshold}`,
      );
    const keys = status.keys ?? [];
    const trusted = keys.filter((key) => !key.retiredBy);
    const retired = keys.filter((key) => key.retiredBy);
    if (trusted.length)
      ok(
        "trusted keys",
        `${trusted.length} (${trusted.map((key) => `${key.id} ${key.fingerprint}`).join(", ")})`,
      );
    else warn("trusted keys", "none; updates cannot be verified");
    if (retired.length)
      ok(
        "retired keys",
        retired
          .map((key) => `${key.id} ${key.fingerprint} (by ${key.retiredBy})`)
          .join(", "),
      );
  }
  if (status.previous) ok("rollback", `${status.previous} retained`);
  else ok("rollback", "no retained release");
  const free = freeInstallBytes();
  if (free !== undefined) {
    const kept = [status.active, status.previous].filter(Boolean).join(", ");
    const text = `${(free / 1_073_741_824).toFixed(1)} GiB free on the install volume; keeping ${kept}`;
    if (free < LOW_DISK_BYTES)
      warn(
        "disk",
        `${text}. Free some space: an update needs about the size of a release`,
      );
    else ok("disk", text);
  }
  if (status.lastCheck)
    ok("last check", `${status.lastCheck.result} (${status.lastCheck.time})`);
  if (status.leftovers.length)
    warn(
      "interrupted",
      `${status.leftovers.length} leftover item(s) in the install directory (${status.leftovers.slice(0, 3).join(", ")}${status.leftovers.length > 3 ? ", ..." : ""}); update, rollback, and doctor remove obsolete releases once no running session uses them`,
    );
  if (status.runtimeLeases) {
    if (status.runtimeLeases.live)
      ok("runtime leases", `${status.runtimeLeases.live} live session(s)`);
    if (status.runtimeLeases.stale)
      warn(
        "runtime leases",
        `${status.runtimeLeases.stale} stale lease record(s) from sessions that ended without cleaning up; they hold nothing back and are removed by uninstall or repair`,
      );
  }
  const counts = LocalMetrics.load(ctx.stateDir).snapshot().lifecycle ?? {};
  if (Object.keys(counts).length)
    ok(
      "lifecycle metrics",
      Object.entries(counts)
        .map(([key, count]) => `${key}=${count}`)
        .join(", "),
    );
}

/** Below this, an update (about one release of extra space) may not fit. */
const LOW_DISK_BYTES = 1_073_741_824;

function freeInstallBytes(): number | undefined {
  try {
    const stats = statfsSync(installHome());
    return stats.bavail * stats.bsize;
  } catch {
    return undefined;
  }
}

/** Whether the update source resolves to plain HTTP on a non-loopback host. */
function plainHttpSource(ctx: BrandedContext, template: string): boolean {
  try {
    const url = new URL(
      resolveTemplate(
        "updates.source",
        template,
        ctx.metadata.access?.variables ?? [],
        process.env,
      ),
    );
    return url.protocol === "http:" && !isLoopbackHost(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Streamable HTTP MCP servers and HTTP audit sinks whose resolved host a
 * private-only network policy would refuse. A warning only: hosts are never
 * allowed implicitly. URLs that do not resolve are reported elsewhere.
 */
export function undeclaredGovernanceHosts(
  ctx: BrandedContext,
  allowHosts: readonly string[],
): { label: string; host: string }[] {
  const manifest = ctx.metadata.governance?.manifest;
  if (!manifest) return [];
  const targets = [
    ...manifest.mcp.servers
      .filter((server) => server.transport === "streamable-http")
      .map((server) => ({
        label: `mcp ${server.id}`,
        key: `mcp.servers.${server.id}.url`,
        url: server.url,
      })),
    ...manifest.audit.sinks
      .filter((sink) => sink.type === "http")
      .map((sink) => ({
        label: `audit ${sink.id}`,
        key: "audit.sinks.url",
        url: sink.url,
      })),
  ];
  const found: { label: string; host: string }[] = [];
  for (const target of targets) {
    if (!target.url) continue;
    let host: string;
    try {
      host = new URL(
        resolveTemplate(
          target.key,
          target.url,
          ctx.metadata.access?.variables ?? [],
          process.env,
        ),
      ).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (!allowHosts.includes(host)) found.push({ label: target.label, host });
  }
  return found;
}
