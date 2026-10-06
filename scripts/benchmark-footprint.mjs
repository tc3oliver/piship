// Footprint baseline: the same workload over the personal example, the managed
// reference (examples/demo-company), and the developer example (six vendored
// Pi packages). Deterministic metrics (file counts, bytes, archive bytes) and
// timings (cold and warm build, install, first and warm start) in one JSON
// report, so a revision before a footprint change and one after compare on
// identical inputs.
//
//   node scripts/benchmark-footprint.mjs --out <fresh-dir> [--root <checkout>]
//     [--label before] [--only personal,managed,developer] [--runs 1]
//     [--reverse] [--startup] [--release] [--windows]
//
// --reverse runs the distributions in reverse order, so an order or cache bias
// shows when a baseline and a candidate are each measured both ways.
// --startup installs each payload into an isolated home and starts it with
// --smoke once cold and twice warm. --release times `piship release` too (it
// needs registry access for its audits). --windows is the manual Windows
// workflow: it implies --startup and --runs 3 unless given, and records the
// Defender status. Builds use the machine's own npm cache (a developer build
// needs it warm or the network); the PiShip cache, install, state, and bin
// directories are isolated inside --out. Archive bytes are the payload as
// `createArchive` writes it, not the full release archive (--release adds that).
import { spawn } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { arch, cpus, platform, release as osRelease } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const option = (name, fallback) =>
  args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const root = resolve(option("--root", "."));
const out = resolve(option("--out", "footprint-benchmark"));
const label = option("--label", "local");
const windowsMode = args.includes("--windows");
const startup = args.includes("--startup") || windowsMode;
const withRelease = args.includes("--release");
const runs = Number(option("--runs", windowsMode ? "3" : "1"));
const reverse = args.includes("--reverse");

export const DISTRIBUTIONS = {
  personal: { example: "personal" },
  managed: { example: "demo-company" },
  developer: { example: "developer" },
};
const selected = option("--only", Object.keys(DISTRIBUTIONS).join(","))
  .split(",")
  .filter(Boolean);
for (const name of selected)
  if (!DISTRIBUTIONS[name])
    throw new Error(
      `Unknown distribution ${name}; expected ${Object.keys(DISTRIBUTIONS).join(", ")}`,
    );
if (reverse) selected.reverse();

const cli = join(root, "packages", "cli", "dist", "bin.js");
if (!existsSync(cli))
  throw new Error(`${cli} is missing: run npm run build in ${root}`);
mkdirSync(out, { recursive: true });

const run = (argv, cwd, env) =>
  new Promise((done, reject) => {
    const started = performance.now();
    const child = spawn(process.execPath, argv, {
      cwd,
      env,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (value) => {
      stdout += value;
    });
    child.stderr.on("data", (value) => {
      stderr += value;
    });
    child.stdin.end();
    child.on("error", reject);
    child.on("close", (code) =>
      code
        ? reject(new Error(`${argv.join(" ")}: ${code}\n${stderr}\n${stdout}`))
        : done({ elapsedMs: performance.now() - started, stdout, stderr }),
    );
  });

/** Files, bytes, and the top-level breakdown of a directory tree. */
function tree(directory) {
  let files = 0;
  let bytes = 0;
  const top = {};
  const visit = (current, first) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      const group = first ?? entry.name;
      if (entry.isDirectory()) visit(path, group);
      else if (entry.isFile()) {
        files += 1;
        bytes += statSync(path).size;
        top[group] = (top[group] ?? 0) + 1;
      }
    }
  };
  visit(directory);
  return { files, bytes, top: Object.fromEntries(Object.entries(top).sort()) };
}

const stages = (stderr) =>
  Object.fromEntries(
    [...stderr.matchAll(/^(.+): ([\d.]+) ms$/gm)].map((match) => [
      match[1],
      Number(match[2]),
    ]),
  );

const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
};

const { createArchive } = await import(
  pathToFileURL(join(root, "packages", "core", "dist", "index.js")).href
);

async function measure(name, iteration) {
  const base = join(out, label, name, `run-${iteration}`);
  rmSync(base, { recursive: true, force: true });
  mkdirSync(base, { recursive: true });
  const distribution = join(base, "distribution");
  cpSync(join(root, "examples", DISTRIBUTIONS[name].example), distribution, {
    recursive: true,
  });
  rmSync(join(distribution, "dist"), { recursive: true, force: true });
  const manifest = join(distribution, "piship.yaml");
  const env = {
    ...process.env,
    PISHIP_CACHE_HOME: join(base, "cache"),
    PISHIP_INSTALL_HOME: join(base, "install"),
    PISHIP_STATE_HOME: join(base, "state"),
    PISHIP_BIN_HOME: join(base, "bin"),
    PI_OFFLINE: "1",
    PISHIP_DEBUG_TIMING: "1",
  };
  delete env.PISHIP_BUILD_INPUT;
  const lock = JSON.parse(readFileSync(join(distribution, "piship.lock")));
  const id = lock.app.id;
  const output = join(distribution, "dist", id);
  const result = { distribution: name, example: DISTRIBUTIONS[name].example };

  // Cold: an empty PiShip cache and no build stamp. Warm: the runtime cache is
  // populated, the output is new. Unchanged: the stamp reuses the output.
  const cold = await run(
    [cli, "build", manifest, "--rebuild"],
    distribution,
    env,
  );
  result.coldBuildMs = cold.elapsedMs;
  result.coldBuildStagesMs = stages(cold.stderr);
  const payload = tree(output);
  result.payloadFiles = payload.files;
  result.payloadBytes = payload.bytes;
  result.payloadByTopLevel = payload.top;
  const archiveFile = join(base, "payload.tar.gz");
  const archive = await createArchive(output, "payload", archiveFile);
  result.archiveBytes = archive.bytes;
  result.archiveEntries = archive.entries;
  rmSync(output, { recursive: true, force: true });
  rmSync(join(distribution, "dist", `${id}.piship-build.json`), {
    force: true,
  });
  const warm = await run([cli, "build", manifest], distribution, env);
  result.warmBuildMs = warm.elapsedMs;
  result.warmBuildStagesMs = stages(warm.stderr);
  const unchanged = await run([cli, "build", manifest], distribution, env);
  result.unchangedRebuildMs = unchanged.elapsedMs;
  const rebuilt = tree(output);
  if (rebuilt.files !== payload.files)
    throw new Error(
      `${name}: a warm build has ${rebuilt.files} files, the cold one ${payload.files}`,
    );

  const installed = await run(
    [join(output, "piship.mjs"), "install", output],
    distribution,
    env,
  );
  result.installMs = installed.elapsedMs;
  const receipt = JSON.parse(
    readFileSync(join(env.PISHIP_INSTALL_HOME, "receipts", `${id}.json`)),
  );
  result.installedPayloadFiles = tree(receipt.payload).files;
  result.installedFiles = tree(env.PISHIP_INSTALL_HOME).files;
  if (startup) {
    const smoke = () => run([receipt.launcher, "--smoke"], base, env);
    try {
      const first = await smoke();
      const warmStarts = [await smoke(), await smoke()];
      const report = JSON.parse(first.stdout);
      result.firstStartMs = first.elapsedMs;
      result.warmStartMs = median(warmStarts.map((item) => item.elapsedMs));
      result.smoke = {
        piVersion: report.piVersion,
        sessionCreated: Boolean(report.sessionId),
        extensions: report.extensions,
        tools: report.tools?.length,
      };
    } catch (error) {
      result.startError = String(error.message).slice(0, 400);
    }
  }
  if (withRelease) {
    try {
      const releaseOut = join(base, "release");
      const first = await run(
        [cli, "release", manifest, "--out", releaseOut, "--rebuild"],
        distribution,
        env,
      );
      result.coldReleaseMs = first.elapsedMs;
      const second = await run(
        [cli, "release", manifest, "--out", releaseOut],
        distribution,
        env,
      );
      result.warmReleaseMs = second.elapsedMs;
      const archivePath = /^ {2}archive {2}(.+)$/m.exec(second.stdout)?.[1];
      if (archivePath) result.releaseArchiveBytes = statSync(archivePath).size;
    } catch (error) {
      result.releaseError = String(error.message).slice(0, 400);
    }
  }
  return result;
}

const measurements = [];
for (let iteration = 1; iteration <= runs; iteration++)
  for (const name of selected) {
    console.error(`${label}: ${name} run ${iteration}/${runs}`);
    measurements.push({ iteration, ...(await measure(name, iteration)) });
  }

const summary = {};
for (const name of selected) {
  const mine = measurements.filter((item) => item.distribution === name);
  const row = {};
  for (const key of [
    "payloadFiles",
    "payloadBytes",
    "archiveBytes",
    "installedPayloadFiles",
    "installedFiles",
    "coldBuildMs",
    "warmBuildMs",
    "unchangedRebuildMs",
    "installMs",
    "firstStartMs",
    "warmStartMs",
    "coldReleaseMs",
    "warmReleaseMs",
  ]) {
    const values = mine.map((item) => item[key]).filter((v) => v !== undefined);
    if (values.length)
      row[key] = Number.isInteger(values[0])
        ? {
            median: median(values),
            min: Math.min(...values),
            max: Math.max(...values),
          }
        : {
            median: Math.round(median(values)),
            min: Math.round(Math.min(...values)),
            max: Math.round(Math.max(...values)),
          };
  }
  summary[name] = row;
}

let defender;
if (platform() === "win32") {
  try {
    const status = await new Promise((done) => {
      const child = spawn(
        "powershell.exe",
        [
          "-NoProfile",
          "-Command",
          "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusSignatureVersion | ConvertTo-Json -Compress",
        ],
        { windowsHide: true },
      );
      let text = "";
      child.stdout.on("data", (value) => {
        text += value;
      });
      child.on("close", () => done(text.trim()));
      child.on("error", () => done(""));
    });
    defender = status || "unavailable";
  } catch {
    defender = "unavailable";
  }
}

const report = {
  label,
  setup: {
    root,
    node: process.version,
    platform: `${platform()}-${arch()}`,
    osRelease: osRelease(),
    cpu: cpus()[0]?.model,
    runs,
    order: reverse ? "reversed" : "forward",
    distributions: selected,
    startup,
    release: withRelease,
    defender: defender ?? process.env.PISHIP_BENCH_DEFENDER ?? "not recorded",
    cache:
      "npm and OS caches warm; the PiShip cache is empty for each cold build and populated for the warm one. Not storage-cold, not a Windows result unless run on Windows.",
  },
  summary,
  measurements,
};
writeFileSync(
  join(out, `${label}.json`),
  `${JSON.stringify(report, null, 2)}\n`,
);

const pad = (value, width) => String(value ?? "-").padStart(width);
console.log(
  `\n${label} (${report.setup.platform}, Node ${process.version}, ${runs} run${runs === 1 ? "" : "s"}, ${report.setup.order})`,
);
console.log(
  `${"".padEnd(11)}${pad("payload", 9)}${pad("installed", 10)}${pad("archive MB", 12)}${pad("cold ms", 9)}${pad("warm ms", 9)}${pad("rebuild", 9)}${pad("install", 9)}`,
);
for (const name of selected) {
  const row = summary[name];
  console.log(
    `${name.padEnd(11)}${pad(row.payloadFiles?.median, 9)}${pad(row.installedFiles?.median, 10)}${pad(((row.archiveBytes?.median ?? 0) / 1e6).toFixed(2), 12)}${pad(row.coldBuildMs?.median, 9)}${pad(row.warmBuildMs?.median, 9)}${pad(row.unchangedRebuildMs?.median, 9)}${pad(row.installMs?.median, 9)}`,
  );
}
console.log(`\nReport: ${join(out, `${label}.json`)}`);
