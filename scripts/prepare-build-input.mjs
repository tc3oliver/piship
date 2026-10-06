import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const packages = [
  "schema",
  "contracts",
  "policy",
  "audit",
  "sandbox",
  "mcp",
  "identity",
  "credentials",
  "inference",
  "core",
  "pi",
  "cli",
  "adapter-sdk",
];
const schema = "piship-build-input/v1";
const markerName = ".piship-build-input.json";
const posix = (path) => path.split(sep).join("/");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function stamp(path) {
  try {
    const stat = statSync(path, { bigint: true });
    return stat.isFile()
      ? `${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`
      : null;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}
function cachedState(path) {
  try {
    const state = JSON.parse(readFileSync(path, "utf8"));
    return state.schema === schema && state.files ? state : { files: {} };
  } catch {
    return { files: {} };
  }
}
function writeAtomic(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, contents);
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

/** Keep the relocatable authoring input exact without rewriting unchanged files. */
export function prepareBuildInput(workspace) {
  const input = join(workspace, "packages", "core", "dist", "build-input");
  const cachePath = join(workspace, ".cache", "piship", "build-input.json");
  const previous = cachedState(cachePath);
  const next = {};
  const expectedDirectories = new Set([""]);
  const sources = new Map();
  const metrics = { files: 0, hashed: 0, copied: 0, removed: 0, sha256: "" };
  const addFile = (source, path) => {
    sources.set(posix(path), source);
    let parent = dirname(path);
    while (parent !== ".") {
      expectedDirectories.add(posix(parent));
      parent = dirname(parent);
    }
  };
  const visitSource = (source, path, excludeBuildInput = false) => {
    expectedDirectories.add(posix(path));
    for (const entry of readdirSync(source, { withFileTypes: true })) {
      if (excludeBuildInput && entry.name === "build-input") continue;
      const child = join(source, entry.name);
      const destination = join(path, entry.name);
      if (entry.isDirectory()) visitSource(child, destination);
      else if (entry.isFile()) addFile(child, destination);
      else throw new Error(`Build input requires a regular file: ${child}`);
    }
  };
  for (const name of ["package.json", "package-lock.json"])
    addFile(join(workspace, name), name);
  for (const name of packages) {
    const source = join(workspace, "packages", name);
    const target = join("packages", name);
    addFile(join(source, "package.json"), join(target, "package.json"));
    visitSource(join(source, "dist"), join(target, "dist"), name === "core");
  }
  mkdirSync(input, { recursive: true });
  // Also remove unexpected files, not merely names remembered by the cache.
  // This maintains an exact snapshot after source deletion or an interrupted
  // previous build without deleting and recreating the whole directory.
  const prune = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const name = posix(relative(input, path));
      if (name === markerName) continue;
      if (entry.isSymbolicLink()) {
        rmSync(path, { force: true });
        metrics.removed++;
      } else if (entry.isDirectory()) {
        prune(path);
        if (!expectedDirectories.has(name)) rmdirSync(path);
      } else if (!sources.has(name)) {
        rmSync(path, { force: true });
        metrics.removed++;
      }
    }
  };
  prune(input);
  const createdDirectories = new Set();
  for (const [path, source] of [...sources].sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  )) {
    const target = join(input, path);
    const sourceStamp = stamp(source);
    const targetStamp = stamp(target);
    const cached = previous.files[path];
    let sha256;
    if (
      cached?.sourceStamp === sourceStamp &&
      typeof cached.sha256 === "string" &&
      /^[a-f0-9]{64}$/.test(cached.sha256)
    )
      sha256 = cached.sha256;
    else {
      sha256 = digest(readFileSync(source));
      metrics.hashed++;
    }
    let updatedTargetStamp = targetStamp;
    if (
      !cached ||
      cached.sha256 !== sha256 ||
      cached.targetStamp !== targetStamp ||
      targetStamp === null
    ) {
      const directory = dirname(target);
      if (!createdDirectories.has(directory)) {
        mkdirSync(directory, { recursive: true });
        createdDirectories.add(directory);
      }
      copyFileSync(source, target);
      metrics.copied++;
      updatedTargetStamp = stamp(target);
    }
    next[path] = { sourceStamp, targetStamp: updatedTargetStamp, sha256 };
  }
  metrics.files = sources.size;
  metrics.sha256 = digest(
    Object.entries(next)
      .map(([path, value]) => `${path}\0${value.sha256}\n`)
      .join(""),
  );
  const marker = { schema, sha256: metrics.sha256, files: metrics.files };
  const markerPath = join(input, markerName);
  const markerContents = `${JSON.stringify(marker)}\n`;
  if (
    !existsSync(markerPath) ||
    readFileSync(markerPath, "utf8") !== markerContents
  )
    writeAtomic(markerPath, markerContents);
  const state = { schema, sha256: metrics.sha256, files: next };
  if (JSON.stringify(previous) !== JSON.stringify(state))
    writeAtomic(cachePath, `${JSON.stringify(state)}\n`);
  return metrics;
}

// Node resolves the main module's links, so the module URL is a real path
// while argv[1] is as typed, which is a link in a symlinked or junctioned
// checkout: compare real paths on both sides.
const real = (path) => {
  try {
    return realpathSync.native(path);
  } catch {
    return resolve(path);
  }
};
if (
  process.argv[1] &&
  real(process.argv[1]) === real(fileURLToPath(import.meta.url))
)
  prepareBuildInput(fileURLToPath(new URL("../", import.meta.url)));
