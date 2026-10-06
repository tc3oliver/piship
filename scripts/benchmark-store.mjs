// Manual benchmark: how to give an installation the files of a shared store.
//
// Compares, on the real `ContentStore` code and the extraction's own write
// pattern (eight writers, files of up to 1 MiB held in memory), the primitives
// an install can place a stored file with, on a payload shaped like a
// `node_modules` tree:
//
//   direct          what extraction does with no store: create and write each file
//   <p>.fresh       first install: an empty store is filled, then files are placed
//   <p>.warm        a second install of the same release from a full store
//   <p>.update      an update that changes 10% of the files, from a store holding
//                   the release it replaces
//   <p>.remove      deleting the installed tree (links, read-only files);
//                   direct.remove is deleting a tree extraction wrote
//
// for p in copy, clone, hardlink, each with the object check a placement does
// (`content`, the default: the object is read and hashed first) and, with
// --verify-modes content,size, without it. `size` is not a product option; it
// shows what the check costs. A primitive the volume refuses is reported as the
// one it fell back to, and its numbers are those of the fallback.
//
// The decision rule is printed with the result and documented in
// docs/performance.md. This script changes no product code and never picks the
// default: a person reads the Windows numbers and edits DEFAULT_STORE_MODE.
//
// Build first (npm run build). Usage:
//   node scripts/benchmark-store.mjs --out <dir> [--root <checkout>]
//     [--files 3000] [--reps 5] [--primitives copy,clone,hardlink]
//     [--verify-modes content] [--store-dir <dir on another volume>]
//     [--check [--mode <primitive>] [--baseline <report.json>]] [--keep]
// Writes <out>/report.json and <out>/summary.md. Exit status 1 when --check
// finds a budget exceeded (scripts/store-budgets.json, scripts/store-budgets.mjs).
import { createHash } from "node:crypto";
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { open } from "node:fs/promises";
import { arch, cpus, platform, release, totalmem } from "node:os";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  evaluateStoreBudgets,
  printFindings,
  readBudgets,
} from "./store-budgets.mjs";

const WINDOWS = process.platform === "win32";
const CONCURRENCY = 8;

/** Median and P95 of `samples` (nearest rank), in the samples' unit. */
export function summarize(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const at = (fraction) =>
    sorted[
      Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1)
    ];
  return {
    n: sorted.length,
    min: sorted[0],
    median: at(0.5),
    p95: at(0.95),
    max: sorted[sorted.length - 1],
  };
}

/** Deterministic payload shaped like a node_modules tree. */
function payload(count, seed, changed = 0, changedSeed = 0) {
  let state = seed >>> 0;
  const random = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const bytes = (size, stamp) => {
    const data = Buffer.alloc(size);
    let word = stamp >>> 0;
    for (let at = 0; at < size; at += 4) {
      word = (Math.imul(word, 1664525) + 1013904223) >>> 0;
      for (let byte = 0; byte < 4 && at + byte < size; byte += 1)
        data[at + byte] = (word >>> (8 * byte)) & 0xff;
    }
    return data;
  };
  const files = [];
  const bucket = (roll) =>
    roll < 0.6
      ? 100 + Math.floor(random() * 1900)
      : roll < 0.9
        ? 2000 + Math.floor(random() * 18000)
        : roll < 0.99
          ? 20000 + Math.floor(random() * 180000)
          : 200000 + Math.floor(random() * 700000);
  for (let index = 0; index < count; index += 1) {
    const package_ = Math.floor(index / 12);
    const duplicate = index > 50 && random() < 0.08;
    const size = bucket(random());
    const source = duplicate ? Math.floor(random() * index) : index;
    const altered = changed > 0 && index % changed === 0;
    const data = duplicate
      ? files[source].data
      : bytes(size, (altered ? changedSeed : seed) * 7919 + index);
    files.push({
      path: `node_modules/pkg${package_}/lib/f${index}.js`,
      data,
      digest: createHash("sha256").update(data).digest("hex"),
      exec: index % 97 === 0,
    });
  }
  return files;
}

/** Run `job` for every item with at most `limit` in flight. */
async function pool(items, limit, job) {
  let next = 0;
  const worker = async () => {
    while (next < items.length) await job(items[next++]);
  };
  await Promise.all(Array.from({ length: limit }, worker));
}

async function writeDirect(file, output) {
  const handle = await open(output, "wx", file.exec ? 0o755 : 0o644);
  try {
    if (file.data.length) await handle.writeFile(file.data);
    if (!WINDOWS) await handle.chmod(file.exec ? 0o755 : 0o644);
  } finally {
    await handle.close();
  }
}

/** Create the tree of `files` under `tree`, with `put(file, output)` for each. */
async function install(files, tree, put) {
  const directories = new Set();
  for (const file of files) {
    const directory = dirname(join(tree, file.path));
    if (!directories.has(directory)) {
      mkdirSync(directory, { recursive: true });
      directories.add(directory);
    }
  }
  const start = performance.now();
  await pool(files, CONCURRENCY, (file) => put(file, join(tree, file.path)));
  return performance.now() - start;
}

function checkTree(files, tree) {
  for (const file of files.filter((_, index) => index % 50 === 0))
    if (
      createHash("sha256")
        .update(readFileSync(join(tree, file.path)))
        .digest("hex") !== file.digest
    )
      throw new Error(`The installed ${file.path} does not match its digest`);
}

function countFiles(directory) {
  let count = 0;
  for (const entry of readdirSync(directory, { withFileTypes: true }))
    count += entry.isDirectory() ? countFiles(join(directory, entry.name)) : 1;
  return count;
}

async function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) =>
    args.includes(name) ? args[args.indexOf(name) + 1] : fallback;
  const root = resolve(
    option("--root", fileURLToPath(new URL("..", import.meta.url))),
  );
  const out = resolve(option("--out", "benchmark-store-output"));
  const count = Number(option("--files", "3000"));
  const reps = Number(option("--reps", "5"));
  const primitives = option("--primitives", "copy,clone,hardlink").split(",");
  const verifyModes = option("--verify-modes", "content").split(",");
  const storeBase = option("--store-dir");
  const keep = args.includes("--keep");
  if (!(count >= 100) || !(reps >= 1))
    throw new Error("--files must be at least 100 and --reps at least 1");
  const { ContentStore } = await import(
    pathToFileURL(join(root, "packages/core/dist/store/store.js")).href
  );
  const { DEFAULT_STORE_MODE } = await import(
    pathToFileURL(join(root, "packages/core/dist/store/policy.js")).href
  );

  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const first = payload(count, 1);
  const second = payload(count, 1, 10, 2);
  const bytes = first.reduce((sum, file) => sum + file.data.length, 0);
  const samples = {};
  const notes = {};
  const sample = (name, value) => (samples[name] ??= []).push(value);
  const variants = primitives.flatMap((primitive) =>
    verifyModes.map((verify) => ({ primitive, verify })),
  );
  const label = ({ primitive, verify }) =>
    verifyModes.length > 1 ? `${primitive}+${verify}` : primitive;

  for (let rep = 0; rep < reps; rep += 1) {
    // Alternate the order so no primitive always runs first or last.
    const order = ["direct", ...variants];
    if (rep % 2 === 1) order.reverse();
    for (const step of order) {
      const base = join(
        out,
        `rep${rep}-${step === "direct" ? "direct" : label(step)}`,
      );
      if (step === "direct") {
        sample(
          "direct",
          await install(first, join(base, "tree"), (file, output) =>
            writeDirect(file, output),
          ),
        );
        checkTree(first, join(base, "tree"));
        const removing = performance.now();
        rmSync(join(base, "tree"), { recursive: true });
        sample("direct.remove", performance.now() - removing);
        rmSync(base, { recursive: true, force: true });
        continue;
      }
      const storeRoot = storeBase
        ? join(resolve(storeBase), `rep${rep}-${label(step)}`)
        : join(base, "store");
      const open_ = () =>
        ContentStore.open(storeRoot, {
          primitive: step.primitive,
          verify: step.verify,
        });
      let store = open_();
      if (!store) throw new Error(`The store at ${storeRoot} did not open`);
      const placeInto = (files, tree, active) =>
        install(files, tree, async (file, output) => {
          if (!(await active.place({ ...file, output })))
            await writeDirect(file, output);
        });
      sample(
        `${label(step)}.fresh`,
        await placeInto(first, join(base, "fresh"), store),
      );
      checkTree(first, join(base, "fresh"));
      notes[label(step)] = {
        asked: step.primitive,
        used: store.activePrimitive,
        counts: { ...store.counts },
      };
      store.end();
      // A second install and an update, from the store the first filled.
      store = open_();
      sample(
        `${label(step)}.warm`,
        await placeInto(first, join(base, "warm"), store),
      );
      checkTree(first, join(base, "warm"));
      store.end();
      store = open_();
      sample(
        `${label(step)}.update`,
        await placeInto(second, join(base, "update"), store),
      );
      checkTree(second, join(base, "update"));
      store.end();
      if (countFiles(join(base, "warm")) !== first.length)
        throw new Error("The warm tree has the wrong number of files");
      // Deleting an installation: names for shared inodes, read-only files.
      const started = performance.now();
      let removeError;
      try {
        rmSync(join(base, "warm"), { recursive: true });
      } catch (error) {
        removeError = String(error.message ?? error);
      }
      sample(`${label(step)}.remove`, performance.now() - started);
      if (removeError) notes[label(step)].removeError = removeError;
      if (!keep) rmSync(base, { recursive: true, force: true });
      if (storeBase && !keep)
        rmSync(storeRoot, { recursive: true, force: true });
    }
  }

  const scenarios = Object.fromEntries(
    Object.entries(samples).map(([name, values]) => [
      name,
      { ...summarize(values), unit: "ms", samples: values },
    ]),
  );
  const direct = scenarios.direct.median;
  const reference = (name) =>
    name.endsWith(".remove") ? scenarios["direct.remove"].median : direct;
  const report = {
    schema: "piship-store-benchmark/v1",
    when: new Date().toISOString(),
    host: {
      platform: platform(),
      arch: arch(),
      release: release(),
      node: process.version,
      cpus: cpus().length,
      cpu: cpus()[0]?.model,
      memoryGiB: Math.round(totalmem() / 2 ** 30),
      defender: process.env.PISHIP_BENCH_DEFENDER ?? "not stated",
    },
    config: {
      files: count,
      bytes,
      reps,
      concurrency: CONCURRENCY,
      primitives,
      verifyModes,
      storeOnAnotherVolume: Boolean(storeBase),
      defaultMode: DEFAULT_STORE_MODE,
    },
    scenarios,
    primitives: notes,
    ratios: Object.fromEntries(
      Object.entries(scenarios)
        .filter(([name]) => name !== "direct" && name !== "direct.remove")
        .map(([name, value]) => [name, value.median / reference(name)]),
    ),
  };
  report.decision = decide(report);
  writeFileSync(
    join(out, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
  );
  writeFileSync(join(out, "summary.md"), summary(report));
  process.stdout.write(summary(report));

  if (args.includes("--check")) {
    const baselinePath = option("--baseline");
    const findings = evaluateStoreBudgets(report, readBudgets(), {
      ...(baselinePath
        ? { baseline: JSON.parse(readFileSync(resolve(baselinePath), "utf8")) }
        : {}),
      ...(option("--mode") ? { mode: option("--mode") } : {}),
    });
    printFindings(findings);
    if (findings.some((finding) => finding.level === "block"))
      process.exitCode = 1;
  }
}

/**
 * The rule docs/performance.md states, applied to one report. It names what the
 * numbers support; it does not change a default.
 */
export function decide(report) {
  const { scenarios } = report;
  const direct = scenarios.direct.median;
  const safe = { copy: true, clone: true, hardlink: false };
  const rows = report.config.primitives.map((primitive) => {
    const name =
      report.config.verifyModes.length > 1 ? `${primitive}+content` : primitive;
    const fresh = scenarios[`${name}.fresh`]?.median / direct;
    const warm = scenarios[`${name}.warm`]?.median / direct;
    const update = scenarios[`${name}.update`]?.median / direct;
    const remove =
      scenarios[`${name}.remove`]?.median / scenarios["direct.remove"].median;
    const used = report.primitives[name]?.used;
    // Worth shipping: a repeat install is clearly cheaper than writing the
    // files, and the first install is not clearly dearer.
    const worthIt = warm <= 0.7 && update <= 0.85 && fresh <= 1.15;
    return {
      primitive,
      name,
      used,
      fresh,
      warm,
      update,
      remove,
      worthIt,
      safe: safe[primitive],
    };
  });
  const winner = rows
    .filter((row) => row.worthIt && row.used === row.primitive)
    .sort((a, b) => a.warm - b.warm)[0];
  return {
    rule: "ship a primitive when warm <= 0.70 x direct, update <= 0.85 x direct, and fresh <= 1.15 x direct, with the file system giving the primitive asked for; a primitive that shares inodes (hardlink) needs a Windows result before it becomes the default",
    rows,
    winner: winner?.primitive ?? "none: leave the default where it is",
  };
}

function summary(report) {
  const line = (cells) => `| ${cells.join(" | ")} |`;
  const ms = (value) => (value === undefined ? "" : value.toFixed(0));
  const ratio = (value) => (value === undefined ? "" : `${value.toFixed(2)}x`);
  const names = Object.keys(report.scenarios);
  return [
    `# Store placement benchmark`,
    ``,
    `${report.host.platform} ${report.host.arch} ${report.host.release}, Node ${report.host.node}, ${report.host.cpus} CPUs; Defender: ${report.host.defender}.`,
    `${report.config.files} files, ${(report.config.bytes / 2 ** 20).toFixed(1)} MiB, ${report.config.reps} repetitions, ${report.config.concurrency} writers${report.config.storeOnAnotherVolume ? ", store on another volume" : ""}.`,
    `Milliseconds; order alternated between repetitions. Default mode in this checkout: ${report.config.defaultMode}.`,
    ``,
    line(["scenario", "median", "P95", "min", "x direct"]),
    line(["---", "---:", "---:", "---:", "---:"]),
    ...names.map((name) =>
      line([
        name,
        ms(report.scenarios[name].median),
        ms(report.scenarios[name].p95),
        ms(report.scenarios[name].min),
        report.ratios[name] === undefined ? "" : ratio(report.ratios[name]),
      ]),
    ),
    ``,
    `Asked for and used: ${Object.entries(report.primitives)
      .map(([name, note]) => `${name} -> ${note.used}`)
      .join(", ")}.`,
    ...Object.entries(report.primitives)
      .filter(([, note]) => note.removeError)
      .map(
        ([name, note]) => `Removing a ${name} tree failed: ${note.removeError}`,
      ),
    ``,
    `Decision rule: ${report.decision.rule}.`,
    `Supported by these numbers: ${report.decision.winner}.`,
    ``,
  ].join("\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await main();
