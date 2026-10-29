// Install from a Company Pack plus the official runtime archive it names: the
// pack's manifest, lock, resources, and Pi package trees are placed over the
// verified runtime payload, giving the payload layout `piship build` writes.
// Launch, rollback, and the store see an ordinary installed release.
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { createTemporaryDirectory, PiShipError } from "@piship/contracts";
import { extractArchive } from "../archive.js";
import { hash } from "../digest.js";
import { currentTarget } from "../compatibility.js";
import { verifyPayloadContents, type DistributionLock } from "../index.js";
import { launcherSource } from "../launcher-source.js";
import { verifyWrittenPayload } from "../payload.js";
import { PI_PACKAGE_VENDOR_DIRECTORY } from "../pi-packages/gates.js";
import type { PackMetadata } from "../release/index.js";
import { checkArchiveDigest } from "../release/verify.js";
import type { ContentStore } from "../store/store.js";
import { verifyChecksums } from "../supply-chain.js";
import type { InstalledRelease } from "./receipt.js";

function fail(message: string, userAction?: string): PiShipError {
  return new PiShipError("INTEGRITY_FAILED", `Pack install: ${message}`, {
    component: "install",
    userAction:
      userAction ??
      "Do not install this artifact; obtain it again from the trusted source",
  });
}

function rootName(path: string): string {
  return basename(path).replace(/\.tar\.gz$/, "");
}

/**
 * Whether `input` is a Company Pack: a directory with `pack.json`, or an
 * archive named `<id>-<version>-pack.tar.gz` (as `piship pack` names it) with
 * `pack.json` at its root. Other archives are not read, so a release archive
 * is still read only once, by its install.
 */
export async function isPack(input: string): Promise<boolean> {
  const path = resolve(input);
  if (!existsSync(path)) return false;
  if (!statSync(path).isFile()) return existsSync(join(path, "pack.json"));
  if (!path.endsWith("-pack.tar.gz")) return false;
  const root = rootName(path);
  const scratch = createTemporaryDirectory(tmpdir(), "verify");
  try {
    const found = await extractArchive(path, join(scratch.path, "x"), {
      expectedRoot: root,
      hash: false,
      capture: (key) => key === `${root}/pack.json`,
      mapEntry: () => undefined,
    });
    return found.captured?.has(`${root}/pack.json`) === true;
  } catch {
    return false;
  } finally {
    scratch.remove();
  }
}

function filesUnder(directory: string, prefix = ""): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? filesUnder(join(directory, entry.name), `${prefix}${entry.name}/`)
      : [`${prefix}${entry.name}`],
  );
}

export interface ComposedPack {
  /** The composed payload, in the staging directory. */
  readonly payload: string;
  readonly lock: DistributionLock;
  readonly release: NonNullable<InstalledRelease["release"]>;
}

export interface ComposeOptions {
  /** The pack archive's SHA-256, obtained out of band. */
  readonly expectedSha256?: string;
  /** The runtime archive; by default the one named in `pack.json`, beside the pack. */
  readonly runtime?: string;
  readonly store?: ContentStore;
}

/** The pack read and verified: `checksums.txt` covers every file, and `pack.json` agrees with the lock. */
async function openPack(
  source: string,
  staging: string,
  expectedSha256: string | undefined,
): Promise<{
  readonly directory: string;
  readonly metadata: PackMetadata;
  readonly sha256: string;
}> {
  let directory = source;
  let sha256: string | undefined;
  if (statSync(source).isFile()) {
    const extracted = await extractArchive(source, join(staging, "pack"), {
      expectedRoot: rootName(source),
    }).catch((error: Error) => {
      throw fail(error.message);
    });
    sha256 = extracted.sha256 as string;
    checkArchiveDigest(source, sha256, expectedSha256);
    directory = join(staging, "pack", extracted.root);
  } else if (expectedSha256)
    throw new PiShipError(
      "CONFIG_INVALID",
      `--sha256 checks a pack archive, but ${source} is a directory and has no archive digest`,
      {
        component: "install",
        userAction:
          "Install the pack .tar.gz archive with --sha256, or omit --sha256 for a pack directory",
      },
    );
  const checksums = join(directory, "checksums.txt");
  if (!existsSync(checksums)) throw fail("checksums.txt is missing");
  let verified: string[];
  try {
    verified = verifyChecksums(directory, readFileSync(checksums, "utf8"), {
      required: ["pack.json", "pack/piship.yaml", "pack/piship.lock"],
    });
  } catch (error) {
    throw fail((error as Error).message);
  }
  const listed = new Set(verified);
  const unlisted = [
    ...filesUnder(directory).filter(
      (file) => file !== "checksums.txt" && !listed.has(file),
    ),
  ];
  if (unlisted.length)
    throw fail(
      `files not covered by checksums.txt: ${unlisted.slice(0, 5).join(", ")}`,
    );
  const metadata = JSON.parse(
    readFileSync(join(directory, "pack.json"), "utf8"),
  ) as PackMetadata;
  const { PACK_SCHEMA } = await import("../release/index.js");
  if (metadata.schema !== PACK_SCHEMA)
    throw fail(`unsupported pack metadata ${String(metadata.schema)}`);
  if (
    hash(readFileSync(join(directory, "pack", "piship.lock"))) !==
    metadata.lockSha256
  )
    throw fail("pack/piship.lock is not the lock pack.json binds");
  return {
    directory,
    metadata,
    sha256: sha256 ?? hash(readFileSync(join(directory, "pack.json"))),
  };
}

/** Where the runtime archive for `target` is looked for besides an explicit path. */
function runtimeArchive(
  source: string,
  name: string,
  explicit: string | undefined,
): string {
  if (explicit) return resolve(explicit);
  const beside = [dirname(source), source, dirname(dirname(source))]
    .map((folder) => join(folder, name))
    .find((path) => existsSync(path));
  if (beside) return beside;
  throw new PiShipError(
    "CONFIG_INVALID",
    `The runtime archive ${name} that this pack runs on was not found beside the pack`,
    {
      component: "install",
      userAction: `Put ${name} next to the pack, or pass --runtime <path to ${name}>`,
    },
  );
}

/**
 * Verify a pack and its runtime archive against each other, place the pack
 * over the runtime payload, and run the local acceptance check. Nothing is
 * installed; the composed payload is left in `staging`.
 */
export async function composePack(
  source: string,
  staging: string,
  options: ComposeOptions = {},
): Promise<ComposedPack> {
  const path = resolve(source);
  const pack = await openPack(path, staging, options.expectedSha256);
  const { metadata } = pack;
  const target = currentTarget();
  const lock = JSON.parse(
    readFileSync(join(pack.directory, "pack", "piship.lock"), "utf8"),
  ) as DistributionLock;
  // The sandbox gate is the lock's, so a pack that excluded this target for
  // it says what a release build for it says.
  // Imported here: the release modules import this package's index, which
  // imports the installer.
  const { runPayloadCommand, sandboxGate } = await import(
    "../release/index.js"
  );
  const sandbox = sandboxGate(lock, target);
  if (sandbox) throw sandbox;
  const pinned = metadata.runtime.archives[target];
  if (!metadata.targets.includes(target) || !pinned)
    throw new PiShipError(
      "CONFIG_INVALID",
      `${lock.app.id} ${lock.app.version} is not available for ${target}: ${metadata.excluded[target] ?? `its pack serves ${metadata.targets.join(", ")}`}`,
      {
        component: "install",
        userAction:
          "Ask the publisher for a pack that includes this platform, or a per-target release",
      },
    );
  const archive = runtimeArchive(path, pinned.name, options.runtime);
  const root = rootName(archive);
  const prefix = `${root}/payload/`;
  const payload = join(staging, "payload");
  const extracted = await extractArchive(archive, payload, {
    expectedRoot: root,
    digests: true,
    ...(options.store ? { place: options.store.placer() } : {}),
    capture: (key) => key === `${root}/runtime.json`,
    mapEntry: (name) =>
      name.startsWith(prefix) ? name.slice(prefix.length) : undefined,
  }).catch((error: Error) => {
    throw fail(`${basename(archive)}: ${error.message}`);
  });
  const archiveSha256 = extracted.sha256 as string;
  if (archiveSha256 !== pinned.sha256)
    throw fail(
      `${basename(archive)} is ${archiveSha256}, but the pack pins ${pinned.sha256}`,
      "Use the runtime archive this pack was built with, or ask the publisher for a new pack",
    );
  checkArchiveDigest(archive, archiveSha256, undefined);
  const runtimeJson = extracted.captured?.get(`${root}/runtime.json`);
  if (!runtimeJson) throw fail(`${basename(archive)} has no runtime.json`);
  const runtime = JSON.parse(runtimeJson.toString("utf8")) as {
    target: string;
    pishipVersion: string;
    npmLockSha256: string;
    pi: { version: string };
    inventory: { sha256: string };
  };
  const files = extracted.files as ReadonlyMap<string, string>;
  const inventoryFile = join(payload, "metadata", "inventory.json");
  if (
    runtime.target !== target ||
    runtime.pishipVersion !== metadata.runtime.pishipVersion ||
    runtime.npmLockSha256 !== metadata.runtime.npmLockSha256 ||
    runtime.pi.version !== metadata.runtime.pi ||
    runtime.inventory.sha256 !== pinned.inventorySha256 ||
    files.get("metadata/inventory.json") !== pinned.inventorySha256
  )
    throw fail(
      `${basename(archive)} does not match the runtime this pack pins`,
      "Use the runtime archive this pack was built with, or ask the publisher for a new pack",
    );
  const inventory = JSON.parse(readFileSync(inventoryFile, "utf8")) as Record<
    string,
    string
  >;
  verifyWrittenPayload(files, inventory, payload);

  // The pack's files over the runtime, as `piship build` places them.
  const added = new Map<string, Buffer | string>();
  const put = (relative: string, content: Buffer | string): void => {
    const file = join(payload, ...relative.split("/"));
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, content);
    added.set(relative, content);
  };
  const packed = join(pack.directory, "pack");
  put("piship.yaml", readFileSync(join(packed, "piship.yaml")));
  put("piship.lock", readFileSync(join(packed, "piship.lock")));
  for (const resource of lock.resources)
    put(
      `resources/${resource.path}`,
      readFileSync(join(packed, ...resource.path.split("/"))),
    );
  const vendored = join(packed, PI_PACKAGE_VENDOR_DIRECTORY);
  if (existsSync(vendored))
    for (const file of filesUnder(vendored))
      put(
        `${PI_PACKAGE_VENDOR_DIRECTORY}/${file}`,
        readFileSync(join(vendored, ...file.split("/"))),
      );
  put(`bin/${lock.app.command}`, launcherSource());
  put(
    `bin/${lock.app.command}.cmd`,
    `@echo off\r\nnode "%~dp0\\${lock.app.command}" %*\r\n`,
  );
  if (process.platform !== "win32")
    chmodSync(join(payload, "bin", lock.app.command), 0o755);
  for (const [relative, content] of added) inventory[relative] = hash(content);
  writeFileSync(inventoryFile, `${JSON.stringify(inventory, null, 2)}\n`);
  const composed = verifyPayloadContents(payload, {
    requireTarget: true,
    verifyContents: false,
  });

  // The pack and this runtime were never run together elsewhere on this
  // target, so the combination is checked once here before it is installed.
  const state = createTemporaryDirectory(tmpdir(), "release-test");
  try {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PISHIP_NO_BROWSER: "1",
      PISHIP_STATE_HOME: state.path,
    };
    delete env.PISHIP_BUILD_INPUT;
    const run = async (args: string[], accept: (out: string) => boolean) => {
      const result = await runPayloadCommand(
        payload,
        composed.app.command,
        args,
        env,
      );
      if (result.status !== 0 || !accept(result.stdout))
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `Pack install: ${composed.app.name} ${composed.app.version} did not start on this runtime (${args.join(" ")}): ${(result.stderr || result.stdout).trim().slice(0, 500)}`,
          {
            component: "install",
            userAction:
              "Nothing was installed. Ask the publisher for a pack and runtime that were built together",
          },
        );
    };
    await run(
      ["version"],
      (out) =>
        out.includes(`${composed.app.name} ${composed.app.version}`) &&
        out
          .split(/\r?\n/)
          .some((line) => line.startsWith(`Pi ${composed.runtime.version}`)),
    );
    if (composed.governance)
      await run(["capabilities", "--json"], (out) =>
        out.trim().startsWith("["),
      );
  } finally {
    state.remove();
  }

  return {
    payload,
    lock: composed,
    release: {
      target,
      channel: composed.updates?.channel ?? "stable",
      pi: composed.runtime.version,
      piship: composed.runtime.pishipVersion,
      lockSha256: metadata.lockSha256,
      pack: { sha256: pack.sha256, version: composed.app.version },
      runtime: {
        archiveSha256,
        pishipVersion: runtime.pishipVersion,
      },
    },
  };
}
