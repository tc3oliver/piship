#!/usr/bin/env node
// Rebuilds tests/helpers/unit-durations.json from CI unit logs: pass the
// files `gh run view --job <id> --log` writes for recent CI unit runners of
// every target. Each file's seconds on a target are the median of the runs,
// as Vitest reports them per file; a file a target skips counts 0 there.
import { readFileSync, writeFileSync } from "node:fs";

const TARGETS = ["ubuntu", "macos", "windows"];
const runs = TARGETS.map(() => new Map());
const args = process.argv.slice(2);
const output =
  args[0] === "--out"
    ? args[1]
    : new URL("../tests/helpers/unit-durations.json", import.meta.url);
const logs = args[0] === "--out" ? args.slice(2) : args;
if (!output || logs.length === 0)
  throw new Error("Usage: unit-durations.mjs [--out file] <CI unit log>...");
// `gh run view --log` can retain raw ANSI escape bytes or their ^[[ spelling.
const ansi = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");
for (const log of logs) {
  const text = readFileSync(log, "utf8")
    .replace(ansi, "")
    .replace(/\^\[\[[0-9;]*m/g, "");
  const target = TARGETS.findIndex((name) => text.startsWith(`check (${name}`));
  if (target < 0) throw new Error(`${log} is not a CI check log`);
  let parsed = 0;
  for (const [, file, value, unit] of text.matchAll(
    / [✓✗×❯↓] (\S+\.test\.ts) .*?\) +([\d.]+)(ms|s)\b/g,
  )) {
    const seconds = Number(value) / (unit === "ms" ? 1000 : 1);
    runs[target].set(file, [...(runs[target].get(file) ?? []), seconds]);
    parsed += 1;
  }
  if (parsed === 0)
    throw new Error(`${log} has no parsed Vitest file durations`);
}
for (const [index, durations] of runs.entries())
  if (durations.size === 0)
    throw new Error(`No unit durations for ${TARGETS[index]}`);
const median = (values = [0]) =>
  [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
const files = [...new Set(runs.flatMap((run) => [...run.keys()]))].sort();
const lines = files.map(
  (file) =>
    `  ${JSON.stringify(file)}: [${runs.map((run) => Math.round(median(run.get(file)) * 10) / 10).join(", ")}]`,
);
writeFileSync(output, `{\n${lines.join(",\n")}\n}\n`);
