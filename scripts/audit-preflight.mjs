// Runs once, before the E2E shards: every test release runs the release
// vulnerability gate (packages/core/src/release/scans.ts) against the
// shipped dependency lockfile, so an advisory at or above `high` there fails
// every shard the same way. This asks npm for the same report from the
// repository lockfile, and fails once, naming each advisory and package.
// shortcut: it audits the workspace production tree, not the built payload
// lockfile, and ignores release.vulnerabilities.allow; upgrade if they diverge.
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const SEVERITY_ORDER = ["info", "low", "moderate", "high", "critical"];

/** The `npm audit --json` advisories at or above high, one per package. */
export function blockingAdvisories(audit) {
  if (audit?.auditReportVersion !== 2 || !audit.vulnerabilities)
    throw new Error("npm audit returned no v2 report");
  const found = new Map();
  for (const [name, entry] of Object.entries(audit.vulnerabilities))
    for (const via of entry.via ?? []) {
      if (!via || typeof via !== "object") continue;
      const severity = via.severity ?? entry.severity;
      // As the release gate: an unrecognised severity cannot be ranked, so it blocks.
      const rank = SEVERITY_ORDER.indexOf(severity);
      if (rank !== -1 && rank < SEVERITY_ORDER.indexOf("high")) continue;
      const id =
        String(via.url ?? "").match(
          /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i,
        )?.[0] ?? `npm-${via.source ?? "unknown"}`;
      found.set(`${id} ${name}`, `${id} (${name}, ${severity})`);
    }
  return [...found.values()];
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const run = spawnSync("npm", ["audit", "--omit=dev", "--json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: process.platform === "win32",
  });
  let advisories;
  try {
    advisories = blockingAdvisories(JSON.parse(run.stdout));
  } catch (error) {
    console.error(`::error::dependency audit unavailable: ${error.message}`);
    process.exit(1);
  }
  if (advisories.length) {
    console.error(
      `::error title=Release vulnerability gate would reject every test release::${advisories.join(", ")}`,
    );
    process.exit(1);
  }
  console.log("no advisory at or above high in the production dependencies");
}
