// Manual measurement: sweep extraction/copy concurrency against the small-file
// buffer threshold on the real code paths (verifyRelease -> extractArchive for
// an archive install and an update, copyTree for a directory install).
// Build first (npm run build). Defaults in production are unchanged; this only
// passes the optional tuning that those functions accept.
// Usage: node scripts/benchmark-concurrency.mjs --out <dir> [--root <checkout>]
//   [--reps 3] [--bundle true|false] [--concurrency 4,8,16,32] [--buffer-kib 256,1024,4096] [--keep]
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { arch, cpus, platform, release, totalmem } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const option = (name, fallback) =>
  args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const list = (name, fallback) =>
  option(name, fallback)
    .split(",")
    .map((value) => Number(value.trim()));
const root = resolve(
  option("--root", fileURLToPath(new URL("..", import.meta.url))),
);
const out = resolve(option("--out", "benchmark-concurrency-output"));
const reps = Number(option("--reps", "3"));
// `--bundle false` measures the unbundled layout (thousands of files), where file-count costs dominate.
const bundle = option("--bundle", "true") !== "false";
const concurrencies = list("--concurrency", "4,8,16,32");
const bufferKib = list("--buffer-kib", "256,1024,4096");
const keep = args.includes("--keep");
if (!(reps >= 1) || [...concurrencies, ...bufferKib].some((n) => !(n >= 1)))
  throw new Error("--reps, --concurrency and --buffer-kib must be positive");

const target = `${platform()}-${arch()}`;
const dist = (path) =>
  pathToFileURL(join(root, "packages/core/dist", path)).href;
const { verifyRelease } = await import(dist("index.js"));
const { copyTree } = await import(dist("install/copy.js"));
const bin = join(root, "packages/cli/dist/bin.js");

mkdirSync(out, { recursive: true });
const work = join(out, "work");
const env = {
  ...process.env,
  PISHIP_INSTALL_HOME: join(work, "install"),
  PISHIP_STATE_HOME: join(work, "state"),
  PISHIP_BIN_HOME: join(work, "bin"),
  PISHIP_CACHE_HOME: join(work, "cache"),
  HOME: join(work, "home"),
  USERPROFILE: join(work, "home"),
  PI_OFFLINE: "1",
};
delete env.PISHIP_BUILD_INPUT;
mkdirSync(env.HOME, { recursive: true });
const cli = (...argv) => {
  const result = spawnSync(process.execPath, [bin, ...argv], {
    cwd: work,
    env,
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.status !== 0)
    throw new Error(`${argv.join(" ")}: ${result.status}\n${result.stderr}`);
};

// A stripped release (bundled unless --bundle false) of the personal example, two versions.
const archives = [];
for (const version of ["1.0.0", "1.1.0"]) {
  const distribution = join(work, version, "distribution");
  cpSync(join(root, "examples/personal"), distribution, { recursive: true });
  const manifest = join(distribution, "piship.yaml");
  let source = readFileSync(manifest, "utf8")
    .replace(/^( {2}version:) .+$/m, `$1 ${version}`)
    .replace(/^( {2}targets:) .+$/m, `$1 [${target}]`)
    .replace(/^ {2}(strip|bundle): .*\n/gm, "");
  source = source.replace(
    "\nrelease:\n",
    `\nrelease:\n  strip: true\n  bundle: ${bundle}\n`,
  );
  writeFileSync(manifest, source);
  console.log(`Preparing ${version}; build time is not measured`);
  cli("lock", manifest);
  cli("release", manifest, "--out", join(work, version, "release"));
  archives.push(
    join(
      work,
      version,
      "release",
      "releases",
      `mypi-${version}-${target}.tar.gz`,
    ),
  );
}
const sha = archives.map((path) =>
  createHash("sha256").update(readFileSync(path)).digest("hex"),
);

const countFiles = (dir) =>
  readdirSync(dir, { withFileTypes: true }).reduce(
    (n, entry) =>
      n +
      (entry.isDirectory()
        ? countFiles(join(dir, entry.name))
        : entry.isFile()
          ? 1
          : 0),
    0,
  );

const extract = async (index, to, tuning) => {
  const verified = await verifyRelease(archives[index], {
    fastClient: true,
    requireTarget: true,
    expectedSha256: sha[index],
    payloadTo: to,
    ...(tuning ? { tuning } : {}),
  });
  verified.cleanup();
};

// The directory-install source: one extracted payload, never timed.
const sourceDir = join(work, "source-payload");
await extract(0, sourceDir);
const payloadFiles = countFiles(sourceDir);

let runId = 0;
const fresh = () => join(work, "runs", String(runId++));
const timed = async (body) => {
  const started = performance.now();
  await body();
  return performance.now() - started;
};
const measure = {
  archiveInstall: async ({ concurrency, bufferBytes }) => {
    const base = fresh();
    mkdirSync(base, { recursive: true });
    try {
      return await timed(() =>
        extract(0, join(base, "1.0.0"), {
          concurrency,
          bufferedFileMax: bufferBytes,
        }),
      );
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  },
  update: async ({ concurrency, bufferBytes }) => {
    const base = fresh();
    mkdirSync(base, { recursive: true });
    try {
      await extract(0, join(base, "1.0.0")); // the installed version, defaults, untimed
      return await timed(() =>
        extract(1, join(base, "1.1.0"), {
          concurrency,
          bufferedFileMax: bufferBytes,
        }),
      );
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  },
  directoryCopy: async ({ concurrency, bufferBytes }) => {
    const base = fresh();
    mkdirSync(base, { recursive: true });
    try {
      let copied;
      const elapsed = await timed(async () => {
        copied = await copyTree(sourceDir, join(base, "payload"), {
          concurrency,
          chunk: bufferBytes,
        });
      });
      if (copied.size !== payloadFiles)
        throw new Error(`copied ${copied.size} of ${payloadFiles} files`);
      return elapsed;
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  },
};
const paths = Object.keys(measure);

const configs = concurrencies.flatMap((concurrency) =>
  bufferKib.map((kib) => ({
    concurrency,
    bufferKib: kib,
    bufferBytes: kib * 1024,
  })),
);
const cellKey = (path, config) =>
  `${path}|${config.concurrency}|${config.bufferKib}`;
const samples = new Map(); // cellKey -> [{ ms, order }]
for (const order of ["forward", "reversed"]) {
  const sequence = order === "forward" ? configs : [...configs].reverse();
  for (let rep = 1; rep <= reps; rep++)
    for (const config of sequence)
      for (const path of paths) {
        const ms = await measure[path](config);
        const key = cellKey(path, config);
        if (!samples.has(key)) samples.set(key, []);
        samples.get(key).push({ ms, order });
        console.log(
          `${order} rep ${rep} ${path} c=${config.concurrency} buf=${config.bufferKib}KiB ${ms.toFixed(1)} ms`,
        );
      }
}

const median = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
};
const summarize = (values) => ({
  n: values.length,
  medianMs: median(values),
  minMs: Math.min(...values),
  maxMs: Math.max(...values),
});
const results = Object.fromEntries(
  paths.map((path) => [
    path,
    configs.map((config) => {
      const all = samples.get(cellKey(path, config));
      const only = (order) =>
        all.filter((s) => s.order === order).map((s) => s.ms);
      return {
        concurrency: config.concurrency,
        bufferKib: config.bufferKib,
        ...summarize(all.map((s) => s.ms)),
        forwardMedianMs: median(only("forward")),
        reversedMedianMs: median(only("reversed")),
        samplesMs: all.map((s) => s.ms),
      };
    }),
  ]),
);
const best = Object.fromEntries(
  paths.map((path) => [
    path,
    results[path].reduce((a, b) => (b.medianMs < a.medianMs ? b : a)),
  ]),
);

let defender = "not queried";
if (platform() === "win32") {
  const query = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,OnAccessProtectionEnabled,IsTamperProtected,AntivirusSignatureVersion | ConvertTo-Json -Compress",
    ],
    { encoding: "utf8", windowsHide: true, timeout: 30000 },
  );
  try {
    if (query.status !== 0) throw new Error(query.stderr || "no output");
    defender = JSON.parse(query.stdout);
  } catch (error) {
    defender = `query failed: ${String(error.message ?? error).trim()}`;
  }
}
const npm =
  platform() === "win32"
    ? spawnSync("cmd.exe", ["/d", "/s", "/c", "call npm --version"], {
        encoding: "utf8",
        windowsVerbatimArguments: true,
      })
    : spawnSync("npm", ["--version"], { encoding: "utf8" });
const setup = {
  date: new Date().toISOString(),
  platform: target,
  osRelease: release(),
  cpuModel: cpus()[0]?.model,
  cpuCount: cpus().length,
  totalMemBytes: totalmem(),
  node: process.version,
  npm: npm.status === 0 ? npm.stdout.trim() : "unknown",
  defender,
  root,
  reps,
  concurrencies,
  bufferKib,
  payloadFiles,
  archiveBytes: archives.map((path) => readFileSync(path).length),
  note: "Fresh directory per run; OS caches not flushed; build and signing excluded; order: each config set run forward then reversed, reps each.",
};
const report = { setup, results, best };
writeFileSync(join(out, "report.json"), `${JSON.stringify(report, null, 2)}\n`);

const labels = {
  archiveInstall: "Archive install (extractArchive, BUFFERED_FILE_MAX)",
  update: "Update, second version over first (extractArchive)",
  directoryCopy: "Directory install (copyTree, CHUNK)",
};
const fmt = (n) => n.toFixed(1);
const lines = [
  "# Concurrency and buffer-threshold sweep",
  "",
  `${setup.platform}, ${setup.cpuModel} x${setup.cpuCount}, Node ${setup.node}, npm ${setup.npm}, OS ${setup.osRelease}`,
  `Defender: ${typeof defender === "string" ? defender : JSON.stringify(defender)}`,
  `${setup.payloadFiles} payload files; ${reps} reps per order, forward and reversed (n=${2 * reps} per cell). Times in ms.`,
  "",
];
for (const path of paths) {
  lines.push(
    `## ${labels[path]}`,
    "",
    "| concurrency | buffer KiB | median | min | max | fwd median | rev median |",
    "|---:|---:|---:|---:|---:|---:|---:|",
  );
  for (const cell of results[path]) {
    const mark = cell === best[path] ? "**" : "";
    const end = cell === best[path] ? "**" : "";
    lines.push(
      `| ${cell.concurrency} | ${cell.bufferKib} | ${mark}${fmt(cell.medianMs)}${end} | ${fmt(cell.minMs)} | ${fmt(cell.maxMs)} | ${fmt(cell.forwardMedianMs)} | ${fmt(cell.reversedMedianMs)} |`,
    );
  }
  lines.push("");
}
lines.push("## Recommendation (best median; defaults unchanged)", "");
for (const path of paths)
  lines.push(
    `- ${labels[path]}: concurrency ${best[path].concurrency}, buffer ${best[path].bufferKib} KiB (median ${fmt(best[path].medianMs)} ms)`,
  );
lines.push(
  "",
  "Production defaults: concurrency 8, buffer 1024 KiB. Adopt a change only if the winner beats the default cell by more than the forward/reversed spread.",
  "",
);
writeFileSync(join(out, "report.md"), lines.join("\n"));
console.log(`\n${lines.join("\n")}`);
if (!keep) rmSync(work, { recursive: true, force: true });
console.log(
  `Report: ${join(out, "report.json")} and ${join(out, "report.md")}`,
);
