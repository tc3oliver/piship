// The doctor groups that need no Pi runtime or governed session.
import { LocalMetrics } from "@piship/audit";
import { resolveTemplate } from "@piship/schema";
import { abandonedTemporaryCount, lifecycleStatus } from "../index.js";
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
): void {
  if (group === "Supply Chain") supplyChainDoctor(ctx, ok);
  else if (group === "Release") releaseDoctor(ctx, ok, warn);
  else updateDoctor(ctx, ok, warn);
}

function supplyChainDoctor(ctx: BrandedContext, ok: DoctorLine): void {
  const { metadata } = ctx;
  ok("manifest", `verified (${metadata.manifest.schema})`);
  ok("lockfile", `verified (${metadata.schema})`);
  ok("integrity", "payload inventory verified at launch");
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
  // The launch removed every abandoned temporary directory it could, so any
  // that remain resisted removal. Only a count: the paths are not reported.
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
  if (!metadata.updates) {
    warn("updates", `not configured (${metadata.manifest.schema})`);
  } else {
    ok(
      "channel",
      `${status.channel} (allowed: ${(status.channels ?? []).join(", ")})`,
    );
    if (status.source) ok("source", status.source);
    else warn("source", "none declared; update needs --from");
    if (status.trustedKeys) ok("trusted keys", String(status.trustedKeys));
    else warn("trusted keys", "none; updates cannot be verified");
  }
  if (status.previous) ok("rollback", `${status.previous} retained`);
  else ok("rollback", "no retained release");
  if (status.lastCheck)
    ok("last check", `${status.lastCheck.result} (${status.lastCheck.time})`);
  if (status.leftovers.length)
    warn(
      "interrupted",
      `${status.leftovers.length} leftover item(s); cleaned by the next update or rollback`,
    );
  if (status.runtimeLeases) {
    if (status.runtimeLeases.live)
      ok("runtime leases", `${status.runtimeLeases.live} live session(s)`);
    if (status.runtimeLeases.stale)
      warn(
        "runtime leases",
        `${status.runtimeLeases.stale} stale lease(s); cleaned by the next update or rollback`,
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
