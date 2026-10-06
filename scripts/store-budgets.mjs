// Regression budgets for the file store and for install and startup cost
// (scripts/store-budgets.json): the rules, and the arithmetic that applies
// them to the reports of scripts/benchmark-store.mjs and
// scripts/benchmark-install.mjs.
//
//   node scripts/store-budgets.mjs --store-report <report.json> [--mode hardlink]
//     [--baseline <earlier store report>]
//   node scripts/store-budgets.mjs --install-report <candidate report.json>
//     --install-baseline <baseline report.json> [--distribution personal]
//
// Exit status 1 when a budget is blocked; an "explain" finding is printed and
// does not fail.
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function readBudgets(path = join(here, "store-budgets.json")) {
  return JSON.parse(readFileSync(path, "utf8"));
}

const median = (value) => {
  if (Array.isArray(value)) {
    const sorted = value.filter(Number.isFinite).sort((a, b) => a - b);
    return sorted.length
      ? sorted[Math.floor((sorted.length - 1) / 2)]
      : undefined;
  }
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
};

const lookup = (source, path) =>
  path.split(".").reduce((value, key) => value?.[key], source);

/** `explain` above the first threshold, `block` above the second, nothing otherwise. */
function level(ratio, rules) {
  const percent = (ratio - 1) * 100;
  if (percent > rules.blockAbovePercent) return "block";
  if (percent > rules.explainAbovePercent) return "explain";
  return undefined;
}

/**
 * The store budgets of `budgets.store` for placement mode `mode`, on a report of
 * benchmark-store.mjs, and, with `baseline`, every scenario's median against
 * the same scenario of an earlier report.
 */
export function evaluateStoreBudgets(report, budgets, { baseline, mode } = {}) {
  const findings = [];
  const effective =
    mode ??
    (report.config?.defaultMode && report.config.defaultMode !== "off"
      ? report.config.defaultMode
      : undefined);
  const scenario = (source, name) => source?.scenarios?.[name]?.median;
  if (effective)
    for (const budget of budgets.store.budgets) {
      const name = budget.metric.replace("<mode>", effective);
      const reference = scenario(report, budget.relativeTo);
      const value = scenario(report, name);
      if (value === undefined || reference === undefined) continue;
      const ratio = value / reference;
      if (ratio > budget.maxRatio)
        findings.push({
          level: "block",
          name,
          message: `${name} is ${ratio.toFixed(2)}x ${budget.relativeTo}; the budget is ${budget.maxRatio}x. ${budget.why}`,
        });
    }
  if (baseline)
    for (const name of Object.keys(report.scenarios ?? {})) {
      const value = scenario(report, name);
      const before = scenario(baseline, name);
      if (value === undefined || !before) continue;
      const found = level(value / before, budgets.rules);
      if (found)
        findings.push({
          level: found,
          name,
          message: `${name} median ${before.toFixed(0)} -> ${value.toFixed(0)} ms (${((value / before - 1) * 100).toFixed(1)}%)`,
        });
    }
  return findings;
}

/**
 * The install and startup metrics of `budgets.installMetrics` on a candidate
 * report of benchmark-install.mjs against its baseline.
 */
export function evaluateInstallMetrics(candidate, baseline, budgets) {
  const findings = [];
  for (const metric of budgets.installMetrics.metrics) {
    const value = median(lookup(candidate, metric.path));
    const before = median(lookup(baseline, metric.path));
    if (value === undefined || before === undefined || before === 0) {
      if (!metric.optional && (value === undefined) !== (before === undefined))
        findings.push({
          level: "explain",
          name: metric.label,
          message: `${metric.label} is reported by only one of the two reports`,
        });
      continue;
    }
    const found = level(value / before, budgets.rules);
    if (found)
      findings.push({
        level: found,
        name: metric.label,
        message: `${metric.label} ${before} -> ${value} (${((value / before - 1) * 100).toFixed(1)}%)`,
      });
  }
  return findings;
}

export function printFindings(
  findings,
  write = (text) => process.stdout.write(text),
) {
  for (const finding of findings)
    write(
      `${finding.level === "block" ? "BLOCK" : "EXPLAIN"} ${finding.message}\n`,
    );
  if (!findings.length) write("within budget\n");
}

function main() {
  const args = process.argv.slice(2);
  const option = (name) =>
    args.includes(name) ? args[args.indexOf(name) + 1] : undefined;
  const budgets = readBudgets(
    option("--budgets") && resolve(option("--budgets")),
  );
  const read = (name) =>
    JSON.parse(readFileSync(resolve(option(name)), "utf8"));
  let findings = [];
  if (option("--store-report"))
    findings = evaluateStoreBudgets(read("--store-report"), budgets, {
      ...(option("--baseline") ? { baseline: read("--baseline") } : {}),
      ...(option("--mode") ? { mode: option("--mode") } : {}),
    });
  else if (option("--install-report") && option("--install-baseline")) {
    const distribution = option("--distribution");
    if (
      distribution &&
      !budgets.installMetrics.distributions.includes(distribution)
    )
      throw new Error(
        `--distribution must be one of ${budgets.installMetrics.distributions.join(", ")}`,
      );
    process.stdout.write(`${distribution ?? "distribution"}: `);
    findings = evaluateInstallMetrics(
      read("--install-report"),
      read("--install-baseline"),
      budgets,
    );
  } else
    throw new Error(
      "Pass --store-report, or --install-report with --install-baseline",
    );
  printFindings(findings);
  if (findings.some((finding) => finding.level === "block"))
    process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main();
