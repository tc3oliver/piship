// Footprint regression budgets: the deterministic size of what a distribution
// ships and installs, checked against scripts/performance-budgets.json.
//
//   node scripts/check-budgets.mjs [--only personal,managed,developer]
//     [--developer] [--record] [--out <dir>]
//
// Only counts and bytes are budgeted (payload files, installed files, archive
// bytes of the payload): they do not depend on the machine's speed, so a pull
// request can fail on them. Timings (build, install, start) are never gated
// here; they are measured by scripts/benchmark-footprint.mjs in the manual and
// qualification workflows. A figure above its budget by more than the
// tolerance fails; one more than the tolerance below it is reported, so the
// budget can be tightened with --record. A platform with no recorded budget
// reports that and passes: the counts include platform packages, so each
// platform records its own.
//
// The managed example builds offline and in seconds, so it is the pull
// request check. The personal example downloads its pinned fd and rg archives
// from GitHub (runtime.searchTools) and the developer example vendors six Pi
// packages and needs the npm registry or a warm npm cache, so both are checked
// only when asked for (--developer, or --only): the nightly and qualification
// run does.
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { arch, platform, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const SCHEMA = "piship-performance-budgets/v1";
export const METRICS = ["payloadFiles", "installedFiles", "archiveBytes"];

/**
 * Compare measured figures with a budget. `measured` and `budget` map
 * distribution -> metric -> number. Returns what failed, what improved, and
 * what has no budget.
 */
export function compareBudgets(measured, budget, tolerance) {
  const failures = [];
  const improvements = [];
  const missing = [];
  for (const [name, metrics] of Object.entries(measured)) {
    const limits = budget?.[name];
    if (!limits) {
      missing.push(name);
      continue;
    }
    for (const metric of METRICS) {
      const value = metrics[metric];
      const allowed = limits[metric];
      if (typeof value !== "number" || typeof allowed !== "number") continue;
      const change = (value - allowed) / allowed;
      if (change > tolerance)
        failures.push({ name, metric, value, budget: allowed, change });
      else if (change < -tolerance)
        improvements.push({ name, metric, value, budget: allowed, change });
    }
  }
  return { failures, improvements, missing };
}

const percent = (change) => `${(change * 100).toFixed(1)}%`;

function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) =>
    args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const budgetFile = join(root, "scripts", "performance-budgets.json");
  const only = option(
    "--only",
    args.includes("--developer")
      ? "personal,managed,developer"
      : "managed",
  )
    .split(",")
    .filter(Boolean);
  const key = `${platform()}-${arch()}`;
  const budgets = existsSync(budgetFile)
    ? JSON.parse(readFileSync(budgetFile, "utf8"))
    : { schema: SCHEMA, tolerance: 0.1, platforms: {} };
  const out = option("--out", mkdtempSync(join(tmpdir(), "piship-budgets-")));
  mkdirSync(out, { recursive: true });
  const run = spawnSync(
    process.execPath,
    [
      join(root, "scripts", "benchmark-footprint.mjs"),
      "--root",
      root,
      "--out",
      out,
      "--label",
      "budgets",
      "--only",
      only.join(","),
      "--deterministic",
    ],
    { stdio: ["ignore", "inherit", "inherit"], env: process.env },
  );
  if (run.status !== 0) {
    console.error("The footprint measurement failed");
    process.exit(1);
  }
  const report = JSON.parse(readFileSync(join(out, "budgets.json"), "utf8"));
  const measured = Object.fromEntries(
    only.map((name) => [
      name,
      Object.fromEntries(
        METRICS.map((metric) => [metric, report.summary[name][metric].median]),
      ),
    ]),
  );
  if (!args.includes("--out")) rmSync(out, { recursive: true, force: true });
  if (args.includes("--record")) {
    budgets.schema = SCHEMA;
    budgets.tolerance ??= 0.1;
    budgets.platforms ??= {};
    budgets.platforms[key] = { ...budgets.platforms[key], ...measured };
    writeFileSync(budgetFile, `${JSON.stringify(budgets, null, 2)}\n`);
    console.log(`Recorded ${only.join(", ")} for ${key} in ${budgetFile}`);
    return;
  }
  const recorded = budgets.platforms?.[key];
  if (!recorded) {
    console.log(
      `No footprint budget is recorded for ${key}; measured ${JSON.stringify(measured)}. Record it with: npm run check:budgets -- --record`,
    );
    return;
  }
  const result = compareBudgets(measured, recorded, budgets.tolerance ?? 0.1);
  for (const name of result.missing)
    console.log(`${name}: no budget recorded for ${key}`);
  for (const item of result.improvements)
    console.log(
      `${item.name} ${item.metric}: ${item.value} is ${percent(-item.change)} under its budget ${item.budget}; tighten it with --record`,
    );
  for (const item of result.failures)
    console.error(
      `${item.name} ${item.metric}: ${item.value} is ${percent(item.change)} over its budget ${item.budget} (tolerance ${percent(budgets.tolerance ?? 0.1)})`,
    );
  if (result.failures.length) {
    console.error(
      "A footprint regression needs an explanation in the pull request, or a re-recorded budget (npm run check:budgets -- --record) that a reviewer accepts.",
    );
    process.exit(1);
  }
  console.log(
    `Footprint within budget for ${only.join(", ")} on ${key} (tolerance ${percent(budgets.tolerance ?? 0.1)})`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();
