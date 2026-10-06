// Manual benchmark: what the installed command shim adds to startup.
// benchmark-install.mjs runs `node <launcher> --smoke`, which skips the shim.
// On Windows a user starts `<command>.cmd`: cmd.exe -> node.exe -> launch.mjs.
// This builds and installs one bundled payload, then compares on that same
// installation (A) `node <launcher> --smoke` with (B) `<command>.cmd --smoke`.
// Measurement only; it changes no product code.
//
// Usage: node scripts/benchmark-cmd-launch.mjs --root <checkout> --out <dir>
//          [--reps 15] [--cold-first A|B]
// Needs a built checkout (`npm run build`). Writes <out>/report.json and
// <out>/summary.md. On a non-Windows host B is the POSIX `sh` shim and the
// verdict says it is not the Windows measurement.
import { spawn } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  cpSync,
  createReadStream,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { cpus, platform, arch, release, version as osVersion } from "node:os";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";

const args = process.argv.slice(2);
const option = (name, fallback) =>
  args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
const root = resolve(option("--root", "."));
const out = resolve(option("--out", "benchmark-cmd-output"));
const reps = Number.parseInt(option("--reps", "15"), 10);
const coldFirst = option("--cold-first", "B");
if (!Number.isInteger(reps) || reps < 1)
  throw new Error("--reps must be a positive integer");
if (coldFirst !== "A" && coldFirst !== "B")
  throw new Error("--cold-first must be A or B");
const windows = process.platform === "win32";
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
// The shim runs whatever `node` the PATH holds; put the node running this
// script first so A and B start the same binary. (Windows keeps the variable
// as `Path`; a second `PATH` key would be ambiguous.)
const pathKey = Object.keys(env).find((k) => k.toLowerCase() === "path");
env[pathKey ?? "PATH"] = [dirname(process.execPath), env[pathKey ?? "PATH"]]
  .filter(Boolean)
  .join(delimiter);
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
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => {
      stdout += c;
    });
    child.stderr.on("data", (c) => {
      stderr += c;
    });
    child.stdin.end();
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Timeout: ${exe} ${argv.join(" ")}`));
    }, 900000);
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0)
        reject(
          new Error(`${exe} ${argv.join(" ")}: ${code}\n${stderr}\n${stdout}`),
        );
      else
        resolveRun({ elapsedMs: performance.now() - started, stdout, stderr });
    });
  });
const cli = (...argv) => run(process.execPath, [bin, ...argv]);

// Best-effort probe for the machine record; never fails the benchmark.
const probe = async (exe, argv, extra = {}) => {
  try {
    return (await run(exe, argv, extra)).stdout.trim();
  } catch (error) {
    return `unavailable: ${String(error.message).split("\n")[0]}`;
  }
};

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
  source = source.replace(
    "\nrelease:\n",
    "\nrelease:\n  strip: true\n  bundle: true\n",
  );
  writeFileSync(manifest, source);
  console.log(`Preparing ${version}; build time excluded from timings`);
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
mkdirSync(channel, { recursive: true });
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
const receipt = () => JSON.parse(readFileSync(receiptPath));

// A: what benchmark-install.mjs measures. B: what a user types. Node refuses to
// spawn a .cmd without a shell, so on Windows B goes through cmd.exe exactly as
// `cmd /c` from a terminal does (arguments are fixed, nothing user-supplied).
const variantA = (...argv) =>
  run(process.execPath, [receipt().launcher, ...argv]);
const variantB = (...argv) => {
  const command = receipt().commandPath;
  return windows
    ? run(
        "cmd.exe",
        ["/d", "/s", "/c", `call "${command}" ${argv.join(" ")}`],
        { windowsVerbatimArguments: true },
      )
    : run(command, argv);
};
const variants = { A: variantA, B: variantB };
const smokeOk = (result) => {
  const smoke = JSON.parse(result.stdout);
  if (!smoke.piVersion || !smoke.sessionId)
    throw new Error("Smoke did not create a real Pi session");
  return smoke;
};
const timed = async (name) => {
  const result = await variants[name]("--smoke");
  smokeOk(result);
  return result.elapsedMs;
};

const stats = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  const at = (p) =>
    sorted[Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1)];
  const mid = sorted.length >> 1;
  return {
    n: sorted.length,
    minMs: sorted[0],
    medianMs:
      sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2,
    p95Ms: at(0.95),
    maxMs: sorted[sorted.length - 1],
  };
};
// First launch of a fresh or just-updated installation, then an immediate
// launch of the other variant. Only one variant can be the cold one.
const coldPair = async () => {
  const second = coldFirst === "A" ? "B" : "A";
  const first = await timed(coldFirst);
  const next = await timed(second);
  return {
    firstVariant: coldFirst,
    firstMs: first,
    secondVariant: second,
    secondMs: next,
  };
};
const round = (n) => Math.round(n * 10) / 10;

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
  const afterInstall = await coldPair();

  // Warm: R pairs, ABAB then BABA blocks, so slow drift hits both variants.
  const samples = { A: [], B: [] };
  const order = [];
  for (let i = 0; i < reps; i++) {
    const names = Math.floor(i / 2) % 2 === 0 ? ["A", "B"] : ["B", "A"];
    for (const name of names) {
      samples[name].push(await timed(name));
      order.push(name);
    }
  }
  const a = stats(samples.A);
  const b = stats(samples.B);

  // Reference points that explain the difference (not part of the verdict).
  const reference = { nodeBare: [], ...(windows ? { cmdBare: [] } : {}) };
  for (let i = 0; i < reps; i++) {
    reference.nodeBare.push(
      (await run(process.execPath, ["-e", "0"])).elapsedMs,
    );
    if (windows)
      reference.cmdBare.push(
        (await run("cmd.exe", ["/d", "/c", "exit", "0"])).elapsedMs,
      );
  }

  const update = await variantA("update");
  if (receipt().app.version !== "1.1.0")
    throw new Error("Update did not activate 1.1.0");
  const afterUpdate = await coldPair();

  const overheadMs = b.medianMs - a.medianMs;
  const ratio = b.medianMs / a.medianMs;
  const floorMs = b.minMs - a.minMs;
  const notWindows = windows
    ? ""
    : "NOT THE WINDOWS MEASUREMENT: B is the POSIX sh shim here, so there is no Windows verdict. ";
  let verdict;
  if (overheadMs < 50)
    verdict = `${notWindows}Verdict: .cmd overhead is negligible (median +${round(overheadMs)} ms, ${ratio.toFixed(2)}x, under the 50 ms threshold).`;
  else {
    const stable = floorMs >= 50;
    const consider = stable && (overheadMs >= 100 || ratio >= 1.25);
    verdict = `${notWindows}Verdict: .cmd adds a ${stable ? "stable" : "noisy (the minimums differ by under 50 ms)"} median +${round(overheadMs)} ms (${ratio.toFixed(2)}x; minimum +${round(floorMs)} ms), over the 50 ms threshold. ${consider ? "That would justify considering a native launcher in v0.11/v1.0." : "That does not by itself justify a native launcher in v0.11/v1.0."} Measurement only.`;
  }

  const defender = windows
    ? await probe("powershell.exe", [
        "-NoProfile",
        "-Command",
        "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled | ConvertTo-Json -Compress",
      ])
    : "not applicable";
  const exclusions = windows
    ? await probe("powershell.exe", [
        "-NoProfile",
        "-Command",
        "(Get-MpPreference).ExclusionPath | ConvertTo-Json -Compress",
      ])
    : "not applicable";
  const setup = {
    platform: target,
    windows,
    osRelease: release(),
    osVersion: osVersion(),
    windowsVer: windows ? await probe("cmd.exe", ["/d", "/c", "ver"]) : "n/a",
    cpu: cpus()[0]?.model,
    logicalCpus: cpus().length,
    node: process.version,
    npm: windows
      ? await probe("cmd.exe", ["/d", "/s", "/c", "call npm --version"], {
          windowsVerbatimArguments: true,
        })
      : await probe("npm", ["--version"]),
    defender,
    defenderExclusions: exclusions,
    defenderNote: process.env.PISHIP_BENCH_DEFENDER ?? "not recorded",
    root,
    reps,
    coldFirst,
    command: receipt().commandPath,
    launcher: receipt().launcher,
    variants: {
      A: "node <launcher> --smoke",
      B: windows
        ? "<command>.cmd --smoke (through cmd.exe)"
        : "<command> --smoke (POSIX sh shim; not the Windows measurement)",
    },
    cache:
      "process-cold first launch; filesystem cache warmed by install; OS caches not flushed",
  };
  const report = {
    setup,
    elapsedMs: { install: install.elapsedMs, update: update.elapsedMs },
    firstStartupAfterInstall: afterInstall,
    firstStartupAfterUpdate: afterUpdate,
    warm: {
      order: order.join(""),
      A: { ...a, samplesMs: samples.A },
      B: { ...b, samplesMs: samples.B },
      overheadMedianMs: overheadMs,
      overheadMinMs: floorMs,
      ratioMedian: ratio,
    },
    reference: Object.fromEntries(
      Object.entries(reference).map(([name, values]) => [name, stats(values)]),
    ),
    verdict,
  };
  writeFileSync(
    join(out, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
  );

  const row = (name, s) =>
    `| ${name} | ${round(s.minMs)} | ${round(s.medianMs)} | ${round(s.p95Ms)} | ${round(s.maxMs)} |`;
  const cold = (label, c) =>
    `| ${label} | ${c.firstVariant} first: ${round(c.firstMs)} ms | ${c.secondVariant} next: ${round(c.secondMs)} ms |`;
  const markdown = `# .cmd launch cost

${verdict}

- Machine: ${setup.platform}, ${setup.cpu} (${setup.logicalCpus} logical), ${setup.windows ? setup.windowsVer : `${setup.osRelease} (${setup.osVersion})`}
- Node ${setup.node}, npm ${setup.npm}
- Defender: ${setup.defender}; exclusions: ${setup.defenderExclusions}; note: ${setup.defenderNote}
- A = \`${setup.variants.A}\`; B = \`${setup.variants.B}\`
- Warm reps: ${reps} per variant, order ${report.warm.order}

## Warm startup (ms)

| Variant | min | median | P95 | max |
|---|---|---|---|---|
${row("A", a)}
${row("B", b)}

Overhead (B - A): median ${round(overheadMs)} ms, minimum ${round(floorMs)} ms; median ratio ${ratio.toFixed(2)}x.

## First startup, same installation

| Moment | first | next |
|---|---|---|
${cold("after install", afterInstall)}
${cold("after update", afterUpdate)}

The first launch of a fresh or updated installation is the cold one; the other variant follows immediately, so compare the two moments rather than A against B within a row. Rerun with \`--cold-first\` to swap.

## Reference starts (ms)

| Command | min | median | P95 | max |
|---|---|---|---|---|
${Object.entries(report.reference)
  .map(([name, s]) => row(name, s))
  .join("\n")}
`;
  writeFileSync(join(out, "summary.md"), markdown);
  console.log(markdown);
} finally {
  await new Promise((r) => server.close(r));
}
