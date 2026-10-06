// Manual benchmark: build/sign outside timings; retain output for inspection.
// Usage: node scripts/benchmark-install.mjs --root <checkout> --out <dir> [--bundle] [--authoring]
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  cpSync,
  createReadStream,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { resolve, join, basename } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { platform, arch, release, cpus } from "node:os";
const args = process.argv.slice(2);
const option = (name, fallback) =>
  args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const root = resolve(option("--root", "."));
const out = resolve(option("--out", "benchmark-output"));
const bundled = args.includes("--bundle");
const baseline = args.includes("--baseline");
const measureAuthoring = args.includes("--authoring");
if (measureAuthoring && !bundled)
  throw new Error("--authoring requires --bundle");
mkdirSync(out, { recursive: true });
const bin = join(root, "packages/cli/dist/bin.js");
const target = `${platform()}-${arch()}`;
const env = {
  ...process.env,
  PISHIP_INSTALL_HOME: join(out, "install"),
  PISHIP_STATE_HOME: join(out, "state"),
  PISHIP_BIN_HOME: join(out, "bin"),
  PISHIP_CACHE_HOME: join(out, "cache"),
  HOME: join(out, "home"),
  USERPROFILE: join(out, "home"),
  PI_OFFLINE: "1",
};
delete env.PISHIP_BUILD_INPUT;
mkdirSync(env.HOME, { recursive: true });
const run = (exe, argv, extra = {}) =>
  new Promise((resolveRun, reject) => {
    const started = performance.now();
    const child = spawn(exe, argv, {
      cwd: out,
      env,
      windowsHide: true,
      ...extra,
    });
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.stdin.end();
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Timeout: ${argv.join(" ")}`));
    }, 900000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0)
        reject(new Error(`${argv.join(" ")}: ${code}\n${stderr}\n${stdout}`));
      else
        resolveRun({ elapsedMs: performance.now() - started, stdout, stderr });
    });
  });
const cli = (...argv) => run(process.execPath, [bin, ...argv]);
const pair = generateKeyPairSync("ed25519");
const publicKey = pair.publicKey
  .export({ type: "spki", format: "der" })
  .toString("base64");
const key = join(out, "release.pem");
writeFileSync(key, pair.privateKey.export({ type: "pkcs8", format: "pem" }), {
  mode: 0o600,
});
const rootPair = generateKeyPairSync("ed25519");
const rootKey = rootPair.publicKey
  .export({ type: "spki", format: "der" })
  .toString("base64");
const trust = `  trust:\n    bootstrap:\n      version: 1\n      expires: 2099-01-01T00:00:00Z\n      keys:\n        - id: bench-root\n          publicKey: ${rootKey}\n        - id: bench-release\n          publicKey: ${publicKey}\n      roles:\n        root: { keyIds: [bench-root], threshold: 1 }\n        channel: { keyIds: [bench-release], threshold: 1 }\n`;
const archives = [];
for (const version of ["1.0.0", "1.1.0"]) {
  const dist = join(out, version, "distribution");
  cpSync(join(root, "examples/personal"), dist, { recursive: true });
  const manifest = join(dist, "piship.yaml");
  let source = readFileSync(manifest, "utf8")
    .replace(/^( {2}version:) .+$/m, `$1 ${version}`)
    .replace("  rollback: true\n", `  rollback: true\n${trust}`)
    .replace(/^( {2}targets:) .+$/m, `$1 [${target}]`);
  source = source.replace(/^ {2}(strip|bundle): .*\n/gm, "");
  // A revision from before release.strip existed rejects the key: the baseline
  // is built as that revision builds, with neither option.
  if (!baseline)
    source = source.replace(
      "\nrelease:\n",
      `\nrelease:\n  strip: true\n  bundle: ${bundled}\n`,
    );
  writeFileSync(manifest, source);
  console.log(
    `Preparing ${version}; build time excluded from consumer timings`,
  );
  await cli("lock", manifest);
  await cli("release", manifest, "--out", join(out, version, "release"));
  archives.push(
    join(
      out,
      version,
      "release",
      "releases",
      `mypi-${version}-${target}.tar.gz`,
    ),
  );
}
const channel = join(out, "channel");
mkdirSync(channel);
const upgrade = join(channel, basename(archives[1]));
cpSync(archives[1], upgrade);
await cli(
  "sign-channel",
  channel,
  upgrade,
  "--channel",
  "stable",
  "--key",
  key,
  "--key-id",
  "bench-release",
  "--sequence",
  "1",
);
const server = createServer((request, response) => {
  const name = decodeURIComponent(
    new URL(request.url, "http://localhost").pathname,
  ).slice(1);
  if (!name || name.includes("/") || name.includes("\\")) {
    response.writeHead(404).end();
    return;
  }
  const stream = createReadStream(join(channel, name));
  stream.on("error", () => response.writeHead(404).end());
  stream.pipe(response);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
env.MYPI_UPDATE_SOURCE = `http://127.0.0.1:${server.address().port}`;
const receiptPath = join(env.PISHIP_INSTALL_HOME, "receipts/mypi.json");
// The command shim only runs `node <launcher> <args>`. Run that directly: Node
// refuses to spawn a .cmd without a shell, and a shell would take the path and
// arguments as command text. The shim's own cost (cmd.exe starting) is
// therefore not measured.
const branded = (...argv) =>
  run(process.execPath, [
    JSON.parse(readFileSync(receiptPath)).launcher,
    ...argv,
  ]);
const count = (dir) =>
  readdirSync(dir, { withFileTypes: true }).reduce(
    (n, entry) =>
      n +
      (entry.isDirectory()
        ? count(join(dir, entry.name))
        : entry.isFile()
          ? 1
          : 0),
    0,
  );
try {
  const fingerprint = `sha256:${createHash("sha256").update(Buffer.from(publicKey, "base64")).digest("hex")}`;
  const digest = createHash("sha256")
    .update(readFileSync(archives[0]))
    .digest("hex");
  const install = await cli(
    "install",
    archives[0],
    "--sha256",
    digest,
    "--expect-key",
    fingerprint,
  );
  const cold = await branded("--smoke");
  const smoke = JSON.parse(cold.stdout);
  if (!smoke.piVersion || !smoke.sessionId)
    throw new Error("Smoke did not create a real Pi session");
  const receipt = JSON.parse(readFileSync(receiptPath));
  const payloadFiles = count(receipt.payload);
  const warm = await branded("--smoke");
  const update = await branded("update");
  const afterUpdate = await branded("--smoke");
  const upgraded = JSON.parse(readFileSync(receiptPath));
  if (upgraded.app.version !== "1.1.0")
    throw new Error("Update did not activate 1.1.0");
  let authoring;
  if (measureAuthoring) {
    // Use the installed, relocated manager, with no checkout build-input override.
    const manager = join(upgraded.payload, "piship.mjs");
    const authoringRoot = join(out, "authored-agent");
    const manifest = join(authoringRoot, "piship.yaml");
    const portable = (...argv) => run(process.execPath, [manager, ...argv]);
    await portable("init", authoringRoot);
    await portable("lock", manifest);
    const authoringCache = join(env.PISHIP_CACHE_HOME, "authoring");
    const cacheEntries = () => {
      try {
        return readdirSync(authoringCache)
          .sort()
          .map((name) => ({
            name,
            modifiedMs: statSync(join(authoringCache, name, "cache.json"))
              .mtimeMs,
            files: count(join(authoringCache, name)),
          }));
      } catch (error) {
        if (error.code === "ENOENT") return [];
        throw error;
      }
    };
    const before = cacheEntries();
    if (before.length)
      throw new Error("Authoring cache must be cold before first build");
    const firstBuild = await portable("build", manifest);
    const firstCache = cacheEntries();
    if (!firstCache.length)
      throw new Error("Portable build did not expand authoring snapshot");
    const warmBuild = await portable("build", manifest);
    const warmCache = cacheEntries();
    const reused = JSON.stringify(firstCache) === JSON.stringify(warmCache);
    if (!reused)
      throw new Error("Warm authoring build replaced the snapshot cache");
    const snapshot = readFileSync(
      join(
        upgraded.payload,
        "node_modules",
        "@piship",
        "core",
        "dist",
        "build-input",
        "authoring.json.gz",
      ),
    );
    authoring = {
      snapshotBytes: snapshot.length,
      snapshotSha256: createHash("sha256").update(snapshot).digest("hex"),
      firstBuildMs: firstBuild.elapsedMs,
      warmBuildMs: warmBuild.elapsedMs,
      cachePath: authoringCache,
      coldCacheEntries: before,
      firstCacheEntries: firstCache,
      warmCacheEntries: warmCache,
      cacheReused: reused,
      note: "End-to-end portable builds include npm and bundling; only snapshot cache is cold initially. No source checkout override; snapshot expands outside installed runtime.",
    };
  }
  // One more start of the upgraded release, with its phases reported
  // (PISHIP_DEBUG_TIMING) and its loaded modules and process spawns counted by
  // a preload. An older PiShip reports no phases; the counts still work.
  const probe = join(out, "startup-probe.mjs");
  writeFileSync(
    probe,
    `import { createRequire, registerHooks, syncBuiltinESMExports } from "node:module";
const require = createRequire(import.meta.url);
let modules = 0;
registerHooks({ load(url, context, next) { if (url.startsWith("file:")) modules += 1; return next(url, context); } });
const spawns = [];
const cp = require("node:child_process");
for (const name of ["execFileSync", "execFile", "spawnSync", "spawn", "execSync", "exec"]) {
  const original = cp[name];
  cp[name] = function (...args) { spawns.push(name + ":" + String(args[0]).split(/[\\\\/]/).pop()); return original.apply(this, args); };
}
syncBuiltinESMExports();
process.on("exit", () => process.stderr.write("PISHIP_PROBE " + JSON.stringify({ modules, spawns }) + "\\n"));
`,
  );
  const measured = await run(
    process.execPath,
    [JSON.parse(readFileSync(receiptPath)).launcher, "--smoke"],
    {
      env: {
        ...env,
        PISHIP_DEBUG_TIMING: "1",
        NODE_OPTIONS: `--import ${pathToFileURL(probe).href}`,
      },
    },
  );
  const stderrLines = measured.stderr.split("\n");
  const probed = stderrLines.find((line) => line.startsWith("PISHIP_PROBE "));
  const phases = stderrLines.find(
    (line) =>
      line.startsWith('{"schema":"piship-timing/v1"') &&
      line.includes('"command":"launch"'),
  );
  const launch = phases ? JSON.parse(phases) : undefined;
  const report = {
    setup: {
      platform: target,
      osRelease: release(),
      cpu: cpus()[0]?.model,
      node: process.version,
      root,
      bundle: bundled,
      defender: process.env.PISHIP_BENCH_DEFENDER ?? "not recorded",
      cache:
        "process-cold first installed launch; filesystem cache warmed by extraction/build; OS caches not flushed",
      channel: "signed localhost HTTP; excludes WAN transfer latency",
      entry: "node launch.mjs directly; the command shim is not measured",
    },
    elapsedMs: {
      install: install.elapsedMs,
      firstProcessStartup: cold.elapsedMs,
      warmProcessStartup: warm.elapsedMs,
      upgrade: update.elapsedMs,
      firstStartupAfterUpgrade: afterUpdate.elapsedMs,
    },
    ...(authoring ? { authoring } : {}),
    filesystem: {
      payloadFiles,
      upgradedPayloadFiles: count(upgraded.payload),
      installedFilesAfterUpgrade: count(env.PISHIP_INSTALL_HOME),
      archiveBytes: statSync(archives[0]).size,
      archiveSha256: digest,
      upgradedArchiveBytes: statSync(archives[1]).size,
    },
    operationEstimates: {
      payloadCreatesPerInstallOrUpgrade: payloadFiles,
      startupPayloadVerificationContentOpens: baseline ? payloadFiles : 0,
      installPayloadVerificationAndFlushOpensLowerBound: baseline
        ? payloadFiles * 3
        : 0,
      upgradePayloadVerificationAndFlushOpensLowerBound: baseline
        ? payloadFiles * 3 + payloadFiles
        : 0,
      successfulActivationPayloadDeletes: 0,
      note: "Structural estimates, not ETW/ProcMon counters. Extraction creates one file per archive entry. The candidate extracts straight into the version directory; the baseline (a revision before this change) extracted into a staging directory and renamed it. Baseline verifies each payload twice and flushes each file; update additionally verifies the active payload. Additional version launch and cleanup passes are excluded from these lower bounds. See docs/performance.md; Node/Defender and directory operations excluded.",
    },
    startup: {
      ...(probed ? JSON.parse(probed.slice("PISHIP_PROBE ".length)) : {}),
      ...(launch
        ? {
            totalMs: launch.totalMs,
            notes: launch.notes,
            counters: launch.counters,
            phases: launch.stages.map((stage) => ({
              name: stage.name,
              ms: stage.ms,
            })),
          }
        : {}),
    },
    smoke: {
      piVersion: smoke.piVersion,
      sessionCreated: Boolean(smoke.sessionId),
    },
  };
  writeFileSync(
    join(out, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
  );
  console.log(JSON.stringify(report, null, 2));
} finally {
  await new Promise((r) => server.close(r));
}
