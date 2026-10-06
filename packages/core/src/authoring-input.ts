import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { createTemporaryDirectory } from "@piship/contracts";
import { entrySegments } from "./archive.js";
import { PISHIP_VERSION } from "./compatibility.js";
import { canonicalJson, hash } from "./digest.js";
import { acquireLifecycleLock } from "./install/lifecycle-lock.js";
import { inventory } from "./payload.js";
import { renameWithRetry } from "./rename-retry.js";
import { buildInput, workspacePackages } from "./runtime-dependencies.js";
import { searchToolCacheDirectory } from "./search-tools/index.js";

export const AUTHORING_SNAPSHOT = "authoring.json.gz";
const SCHEMA = "piship-authoring-input/v1";

/** One deterministic file retains the original, unbundled authoring inputs. */
export function writeAuthoringSnapshot(
  input: string,
  destination: string,
): void {
  const files: [string, number, string][] = [];
  const visit = (directory: string, prefix: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort(
      (a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)),
    )) {
      const path = join(directory, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.name === "build-input") continue;
      if (entry.isDirectory()) visit(path, relative);
      else if (entry.isFile())
        files.push([
          relative,
          relative === "packages/cli/dist/bin.js" ? 0o755 : 0o644,
          readFileSync(path).toString("base64"),
        ]);
      else throw new Error(`Unsupported authoring input: ${path}`);
    }
  };
  // Match the prepared build input, including when PISHIP_BUILD_INPUT names a checkout.
  for (const name of [
    "package.json",
    "package-lock.json",
    ".piship-build-input.json",
  ])
    if (existsSync(join(input, name)))
      files.push([
        name,
        0o644,
        readFileSync(join(input, name)).toString("base64"),
      ]);
  for (const name of workspacePackages) {
    const prefix = `packages/${name}`;
    files.push([
      `${prefix}/package.json`,
      0o644,
      readFileSync(join(input, prefix, "package.json")).toString("base64"),
    ]);
    visit(join(input, prefix, "dist"), `${prefix}/dist`);
  }
  files.sort((a, b) => Buffer.compare(Buffer.from(a[0]), Buffer.from(b[0])));
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(
    destination,
    gzipSync(JSON.stringify({ schema: SCHEMA, files })),
  );
}

/** Runtime commands never expand this; builds use a private, digest-keyed cache copy. */
export function authoringBuildInput(
  input = buildInput,
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (existsSync(join(input, "packages", "core", "dist"))) return input;
  const bytes = readFileSync(join(input, AUTHORING_SNAPSHOT));
  const digest = hash(bytes);
  const parent = join(dirname(searchToolCacheDirectory(env)), "authoring");
  const location = join(parent, `${PISHIP_VERSION}-${digest}`);
  const valid = (): string | undefined => {
    try {
      const manifest = JSON.parse(
        readFileSync(join(location, "cache.json"), "utf8"),
      );
      const tree = join(location, "input");
      if (
        manifest.schema === SCHEMA &&
        manifest.digest === digest &&
        manifest.version === PISHIP_VERSION &&
        canonicalJson(inventory(tree)) === canonicalJson(manifest.inventory)
      )
        return tree;
    } catch {}
    return undefined;
  };
  const cached = valid();
  if (cached) return cached;
  const snapshot = JSON.parse(
    gunzipSync(bytes, {
      maxOutputLength: 128 * 1024 * 1024,
    }).toString("utf8"),
  ) as { schema: string; files: [string, number, string][] };
  if (
    snapshot.schema !== SCHEMA ||
    !Array.isArray(snapshot.files) ||
    snapshot.files.length > 10_000
  )
    throw new Error("Invalid PiShip authoring snapshot");
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporary = createTemporaryDirectory(parent, "build", "authoring");
  const root = join(temporary.path, "input");
  try {
    for (const entry of snapshot.files) {
      if (
        !Array.isArray(entry) ||
        entry.length !== 3 ||
        typeof entry[0] !== "string" ||
        !Number.isInteger(entry[1]) ||
        entry[1] < 0 ||
        entry[1] > 0o777 ||
        typeof entry[2] !== "string"
      )
        throw new Error("Invalid PiShip authoring snapshot entry");
      const [path, mode, data] = entry;
      const target = join(root, ...entrySegments(path, false));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, Buffer.from(data, "base64"), { flag: "wx", mode });
      chmodSync(target, mode);
    }
    for (const name of workspacePackages)
      if (!existsSync(join(root, "packages", name, "dist")))
        throw new Error(`Missing authoring input for @piship/${name}`);
    const stage = join(temporary.path, "cache");
    mkdirSync(stage);
    writeFileSync(
      join(stage, "cache.json"),
      JSON.stringify({
        schema: SCHEMA,
        version: PISHIP_VERSION,
        digest,
        inventory: inventory(root),
      }),
    );
    renameWithRetry(root, join(stage, "input"));
    // Another authoring process may have published the same digest while we expanded it.
    const hold = acquireLifecycleLock(
      `${location}.lock`,
      (_pid, holder) =>
        new Error(`Another authoring cache publisher is running: ${holder}`),
      () => new Error("Could not lock the authoring cache"),
      30_000,
    );
    try {
      if (!valid()) {
        rmSync(location, {
          recursive: true,
          force: true,
          maxRetries: 5,
          retryDelay: 100,
        });
        renameWithRetry(stage, location);
      }
    } finally {
      hold.release();
    }
    temporary.remove();
    return join(location, "input");
  } catch (error) {
    temporary.remove();
    throw error;
  }
}
