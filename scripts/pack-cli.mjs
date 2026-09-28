// Packs the compiled PiShip CLI and its runtime dependencies into a
// self-contained directory, so release-candidate consumer jobs can verify
// and compare release archives without `npm ci` or a TypeScript build.
//
// Usage: node scripts/pack-cli.mjs <out-dir>
// Run it after `npm ci && npm run build`; the CLI is then
//   node <out-dir>/node_modules/@piship/cli/dist/bin.js
//
// `@piship/pi` (and with it the Pi runtime and its platform-specific native
// packages) is deliberately left out: the CLI only loads it inside built
// payloads, never itself, so the pack is plain JavaScript and runs on every
// release target. The workspace's `build-input` copy is also left out, since
// consumers verify releases and never build them.
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const workspace = fileURLToPath(new URL("../", import.meta.url));
const out = resolve(process.argv[2] ?? "");
if (!process.argv[2]) throw new Error("usage: pack-cli.mjs <out-dir>");
const excluded = new Set(["@piship/pi"]);

/** Where a real package directory lands inside the pack. */
function destination(real) {
  const path = relative(workspace, real);
  const parts = path.split(sep);
  if (parts[0] === "packages")
    return join(out, "node_modules", "@piship", ...parts.slice(1));
  if (parts[0] !== "node_modules")
    throw new Error(`unexpected package location ${real}`);
  return join(out, path);
}

/** Node's lookup of `name` from a package directory. */
function locate(name, from) {
  for (let directory = from; ; directory = dirname(directory)) {
    const candidate = join(directory, "node_modules", name);
    if (existsSync(join(candidate, "package.json")))
      return realpathSync(candidate);
    if (dirname(directory) === directory)
      throw new Error(`cannot resolve ${name} from ${from}`);
  }
}

rmSync(out, { recursive: true, force: true });
const seen = new Set();
const pending = [realpathSync(join(workspace, "packages", "cli"))];
while (pending.length) {
  const real = pending.pop();
  if (seen.has(real)) continue;
  seen.add(real);
  const manifest = JSON.parse(readFileSync(join(real, "package.json"), "utf8"));
  const target = destination(real);
  mkdirSync(target, { recursive: true });
  if (manifest.name?.startsWith("@piship/")) {
    cpSync(join(real, "package.json"), join(target, "package.json"));
    cpSync(join(real, "dist"), join(target, "dist"), {
      recursive: true,
      filter: (source) =>
        !relative(join(real, "dist"), source).startsWith("build-input"),
    });
  } else
    cpSync(real, target, {
      recursive: true,
      filter: (source) =>
        !relative(real, source).split(sep).includes("node_modules"),
    });
  for (const name of Object.keys({
    ...manifest.dependencies,
    ...manifest.optionalDependencies,
  })) {
    if (excluded.has(name)) continue;
    try {
      pending.push(locate(name, real));
    } catch (error) {
      if (!(name in (manifest.optionalDependencies ?? {}))) throw error;
    }
  }
}

// The pack must load on its own: every module the CLI imports is present.
const bin = join(out, "node_modules", "@piship", "cli", "dist", "bin.js");
const probe = spawnSync(process.execPath, [bin, "--version"], {
  cwd: out,
  encoding: "utf8",
});
if (probe.status !== 0)
  throw new Error(`the packed CLI does not run: ${probe.stderr}`);
console.log(
  `Packed PiShip ${probe.stdout.trim()} CLI (${seen.size} packages) into ${out}`,
);
