// Local iterative payload-build profiler; preparation/lock are excluded.
// node scripts/benchmark-build.mjs --out <fresh-dir> [--root <checkout>] [--label before] [--release]
// --release times `piship release` instead of `piship build` and records its
// stages from the piship-timing/v1 summary (stages overlap, so they can sum to
// more than the run). Release needs registry access for its audits.
import { spawn } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { arch, cpus, platform, release } from "node:os";
const args = process.argv.slice(2);
const option = (name, fallback) =>
  args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const root = resolve(option("--root", "."));
const out = resolve(option("--out", "build-profile"));
const label = option("--label", "local");
const releaseMode = args.includes("--release");
mkdirSync(out, { recursive: true });
const cli = join(root, "packages/cli/dist/bin.js");
const run = (command, argv, cwd, env = process.env) =>
  new Promise((done, reject) => {
    const started = performance.now();
    const child = spawn(command, argv, { cwd, env, windowsHide: true });
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (value) => (stdout += value));
    child.stderr.on("data", (value) => (stderr += value));
    child.stdin.end();
    child.on("error", reject);
    child.on("close", (code) =>
      code
        ? reject(new Error(`${argv.join(" ")}: ${code}\n${stderr}\n${stdout}`))
        : done({ elapsedMs: performance.now() - started, stdout, stderr }),
    );
  });
const count = (directory) =>
  readdirSync(directory, { withFileTypes: true }).reduce(
    (total, entry) =>
      total +
      (entry.isDirectory()
        ? count(join(directory, entry.name))
        : entry.isFile()
          ? 1
          : 0),
    0,
  );
function buildMeasurement(built, directory, bundled, iteration) {
  const stages = Object.fromEntries(
    [...built.stderr.matchAll(/^(.+): ([\d.]+) ms$/gm)].map((match) => [
      match[1],
      Number(match[2]),
    ]),
  );
  return {
    bundled,
    iteration,
    elapsedMs: built.elapsedMs,
    stagesMs: stages,
    uninstrumentedMs:
      built.elapsedMs -
      Object.values(stages).reduce((total, value) => total + value, 0),
    files: count(join(directory, "dist", "mypi")),
  };
}
// A release prints its stages longest first and ends with one JSON line;
// stages that ran side by side overlap, so `overlapMs` is what parallelism hid.
function releaseMeasurement(built, bundled, iteration) {
  const summary = built.stderr
    .split("\n")
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line))
    .findLast(
      (item) =>
        item.schema === "piship-timing/v1" && item.command === "release",
    );
  if (!summary)
    throw new Error("The release printed no piship-timing/v1 summary");
  const archive = /^ {2}archive {2}(.+)$/m.exec(built.stdout)?.[1];
  const stages = Object.fromEntries(
    summary.stages.map((stage) => [stage.name, stage.ms]),
  );
  return {
    bundled,
    iteration,
    elapsedMs: built.elapsedMs,
    totalMs: summary.totalMs,
    stagesMs: stages,
    stagesStartMs: Object.fromEntries(
      summary.stages.map((stage) => [stage.name, stage.startMs]),
    ),
    overlapMs: Math.max(
      0,
      Object.values(stages).reduce((total, value) => total + value, 0) -
        summary.totalMs,
    ),
    uninstrumentedMs: built.elapsedMs - summary.totalMs,
    archiveBytes: archive ? statSync(archive).size : undefined,
    files: archive ? count(archive.replace(/\.tar\.gz$/, "")) : undefined,
    qualified: /Built qualified release /.test(built.stdout),
  };
}
const result = {
  label,
  setup: {
    root,
    node: process.version,
    platform: `${platform()}-${arch()}`,
    osRelease: release(),
    cpu: cpus()[0]?.model,
    cache: `warm OS/npm caches; two consecutive ${releaseMode ? "releases" : "builds"} of the same manifest and lock`,
    mode: releaseMode ? "release" : "build",
  },
  builds: [],
};
if (args.includes("--compile")) {
  result.workspaceBuildMs = {};
  for (const [name, argv] of [
    ["TypeScript incremental", ["node_modules/typescript/bin/tsc", "-b"]],
    ["prepare build input", ["scripts/prepare-build-input.mjs"]],
    ["mark CLI executable", ["scripts/mark-cli-executable.mjs"]],
  ]) {
    const compiled = await run(process.execPath, argv, root);
    result.workspaceBuildMs[name] = compiled.elapsedMs;
  }
  console.log(JSON.stringify(result.workspaceBuildMs));
}
for (const bundled of [false, true]) {
  const directory = join(out, bundled ? "bundled" : "unbundled");
  const distribution = join(directory, "distribution");
  if (!args.includes("--reuse-manifests")) {
    cpSync(join(root, "examples/personal"), distribution, { recursive: true });
    const manifest = join(distribution, "piship.yaml");
    const source = readFileSync(manifest, "utf8")
      .replace(/^ {2}(strip|bundle): .*\n/gm, "")
      .replace(
        "\nrelease:\n",
        `\nrelease:\n  strip: true\n  bundle: ${bundled}\n`,
      );
    writeFileSync(manifest, source);
    console.log(
      `Preparing ${bundled ? "bundled" : "unbundled"} lock (not timed)`,
    );
    await run(process.execPath, [cli, "lock", manifest], directory);
  }
  const manifest = join(distribution, "piship.yaml");
  for (const iteration of [1, 2]) {
    const built = await run(
      process.execPath,
      releaseMode
        ? [cli, "release", manifest, "--out", join(directory, "release-out")]
        : [cli, "build", manifest],
      directory,
      { ...process.env, PISHIP_DEBUG_TIMING: "1" },
    );
    const measurement = releaseMode
      ? releaseMeasurement(built, bundled, iteration)
      : buildMeasurement(built, directory, bundled, iteration);
    result.builds.push(measurement);
    writeFileSync(
      join(directory, `${label}-${iteration}.log`),
      built.stdout + built.stderr,
    );
    writeFileSync(
      join(out, `${label}.json`),
      `${JSON.stringify(result, null, 2)}\n`,
    );
    console.log(JSON.stringify(measurement));
  }
}
