// Company Packs: a distribution's manifest, lock, and resources without any
// per-target bytes, bound to the exact official runtime archives it runs on.
// Composition with a runtime happens at install; a pack never holds one.
import {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { createTemporaryDirectory, PiShipError } from "@piship/contracts";
import {
  readManifest,
  type ReleaseManifest,
  releaseOptions,
  SEARCH_TOOLS,
} from "@piship/schema";
import { createArchive, extractArchive } from "../archive.js";
import type { DistributionLock } from "../index.js";
import { PI_PACKAGE_VENDOR_DIRECTORY } from "../pi-packages/gates.js";
import { packageLockFiles, vendorPiPackages } from "../pi-packages/lock.js";
import { formatChecksums } from "../supply-chain.js";
import { sweepOutputStaging } from "../temporary-directories.js";
import { STATE_SCHEMAS } from "../migration.js";
import {
  checkPiGate,
  checkPolicyGates,
  piCompatibility,
  piCompatibilitySurfaces,
  requireReleaseLock,
  sandboxGate,
} from "./gates.js";
import type { ReleaseOptions } from "./metadata.js";
import { verifyRuntimeRelease } from "./runtime.js";
import { gate, hash, writeJson } from "./shared.js";

export const PACK_SCHEMA = "piship-pack/v1";

/** A runtime archive as `piship pack` binds it: read from its `runtime.json`. */
export interface PackRuntime {
  readonly name: string;
  readonly target: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly pishipVersion: string;
  readonly piVersion: string;
  readonly npmLockSha256: string;
  readonly inventorySha256: string;
  /** Version of each search tool the runtime bundles. */
  readonly searchTools: Readonly<Record<string, string>>;
}

export interface PackMetadata {
  readonly schema: typeof PACK_SCHEMA;
  readonly distribution: {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly command: string;
    readonly mode: string;
  };
  readonly manifestSchema: string;
  readonly lockSchema: string;
  readonly lockSha256: string;
  readonly pack: {
    readonly path: "pack";
    readonly inventorySha256: string;
    readonly files: number;
  };
  readonly pi: {
    readonly package: string;
    readonly version: string;
    readonly compatibility: string;
    readonly surfaces: Readonly<Record<string, string>>;
  };
  readonly stateSchemas: unknown;
  /** The exact binding: any other runtime needs a new lock and a new pack. */
  readonly runtime: {
    readonly pishipVersion: string;
    readonly pi: string;
    readonly npmLockSha256: string;
    readonly archives: Readonly<
      Record<
        string,
        {
          readonly name: string;
          readonly sha256: string;
          readonly bytes: number;
          readonly inventorySha256: string;
        }
      >
    >;
  };
  /** The pack always runs on the bundled, stripped runtime; settings it overrides. */
  readonly runtimeSettings: {
    readonly bundle: true;
    readonly strip: true;
    readonly overridden: readonly string[];
  };
  readonly targets: readonly string[];
  /** Release targets the pack does not serve, with the reason. */
  readonly excluded: Readonly<Record<string, string>>;
}

export interface PackOptions
  extends Pick<
    ReleaseOptions,
    "outputRoot" | "reclaimStaging" | "abandonedStaging"
  > {
  /** Official runtime archives, one per target. */
  readonly runtimes: readonly string[];
  /** Test seam: replaces `readRuntimeArchive`. */
  readonly readRuntime?: (path: string) => Promise<PackRuntime>;
}

export interface BuiltPack {
  readonly name: string;
  readonly directory: string;
  readonly archive: string;
  readonly sha256: string;
  readonly metadata: PackMetadata;
}

/**
 * The one reader of a runtime archive: the runtime release verifier (archive
 * digest and sidecar, checksums, every payload file against its inventory,
 * qualification, scans, tests) and then its `runtime.json`.
 */
export async function readRuntimeArchive(path: string): Promise<PackRuntime> {
  // A folder has no archive digest for pack.json to pin.
  if (!statSync(path).isFile())
    throw gate(
      "CONFIG_INVALID",
      "runtime",
      `${path} is not an archive file`,
      "Pass the piship-runtime-<version>-<target>.tar.gz archive, not its extracted folder",
    );
  const verified = await verifyRuntimeRelease(path);
  try {
    const { metadata } = verified;
    return {
      name: basename(path),
      target: metadata.target,
      sha256: verified.archiveSha256 as string,
      bytes: statSync(path).size,
      pishipVersion: metadata.pishipVersion,
      piVersion: metadata.pi.version,
      npmLockSha256: metadata.npmLockSha256,
      inventorySha256: metadata.inventory.sha256,
      searchTools: metadata.searchTools,
    };
  } finally {
    verified.cleanup();
  }
}

/** Whether the file begins like an ELF, Mach-O, or PE executable. */
function isNativeBinary(file: string): boolean {
  const head = Buffer.alloc(0x40);
  const fd = openSync(file, "r");
  try {
    const read = readSync(fd, head, 0, head.length, 0);
    if (read < 8) return false;
    const magic = head.readUInt32BE(0);
    // 0xcafebabe starts a fat Mach-O (a small architecture count follows) and
    // a Java class (a version of 45 or more follows).
    if (magic === 0xcafebabe) return head.readUInt32BE(4) < 45;
    if (
      [0x7f454c46, 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(
        magic,
      )
    )
      return true;
    if (read === head.length && head.readUInt16BE(0) === 0x4d5a) {
      const pe = Buffer.alloc(4);
      return (
        readSync(fd, pe, 0, 4, head.readUInt32LE(0x3c)) === 4 &&
        pe.toString("latin1") === "PE\0\0"
      );
    }
    return false;
  } finally {
    closeSync(fd);
  }
}

/**
 * What makes a Pi package's npm closure (its stored lockfile) unfit for a
 * cross-platform pack: install scripts, and entries bound to an OS or CPU.
 */
export function packageClosureProblems(
  lockfile: string,
  optionalDependencies?: Readonly<Record<string, readonly string[]>>,
): string[] {
  const problems: string[] = [];
  // The lock keeps an entry per target even when its list is empty.
  if (Object.values(optionalDependencies ?? {}).some((list) => list.length))
    problems.push("it has per-target optional dependencies");
  const closure = (JSON.parse(lockfile).packages ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  for (const [path, item] of Object.entries(closure)) {
    const name = path || "the package";
    if (item.hasInstallScript === true)
      problems.push(
        `${name} runs install scripts, which are not allowed in a pack`,
      );
    const bound = ["os", "cpu", "libc"].find(
      (field) => item[field] !== undefined,
    );
    if (bound) problems.push(`${name} is bound to a platform (${bound})`);
  }
  return problems;
}

/** Every reason this distribution cannot be a pack; empty when eligible. */
function ineligibility(lock: DistributionLock, base: string): string[] {
  const reasons: string[] = [];
  for (const entry of lock.packages ?? []) {
    const { lockfile } = packageLockFiles(base, entry.id);
    const problems = packageClosureProblems(
      existsSync(lockfile) ? readFileSync(lockfile, "utf8") : "{}",
      entry.optionalDependencies,
    );
    if (problems.length)
      reasons.push(
        `resources.packages ${entry.id}: ${problems.join(", ")}; use a pure-JavaScript package, or build per-target releases with piship release`,
      );
  }
  for (const resource of lock.resources) {
    const file = join(base, resource.path);
    if (
      /\.node$|(^|\/)binding\.gyp$/.test(resource.path) ||
      isNativeBinary(file)
    )
      reasons.push(`resource ${resource.path} is a native artifact`);
  }
  return reasons;
}

/**
 * `piship pack`: the static gates, the exact runtime binding, the eligibility
 * refusals, and a deterministic archive of the manifest, lock, and resources.
 */
export async function buildPack(
  manifestPath: string,
  options: PackOptions,
): Promise<BuiltPack> {
  const lock = requireReleaseLock(manifestPath);
  checkPiGate(lock);
  checkPolicyGates(lock);
  const release = lock.release as ReleaseManifest;
  const base = dirname(resolve(manifestPath));
  const { bundle, strip } = releaseOptions(lock.manifest.schema, release);
  const reasons = ineligibility(lock, base);
  if (reasons.length)
    throw gate(
      "PACK_INELIGIBLE",
      "eligibility",
      reasons.join("; "),
      "Build per-target releases with piship release (one machine per OS), or remove what the message names",
    );

  const archives: Record<string, PackRuntime> = {};
  for (const path of options.runtimes) {
    const runtime = await (options.readRuntime ?? readRuntimeArchive)(path);
    if (!(release.targets as readonly string[]).includes(runtime.target))
      throw gate(
        "CONFIG_INVALID",
        "runtime",
        `${runtime.name} is for ${runtime.target}, which is not in release.targets (${release.targets.join(", ")})`,
      );
    if (archives[runtime.target])
      throw gate(
        "CONFIG_INVALID",
        "runtime",
        `two runtime archives for ${runtime.target}`,
      );
    if (
      runtime.pishipVersion !== lock.runtime.pishipVersion ||
      runtime.npmLockSha256 !== lock.runtime.npmLockSha256 ||
      runtime.piVersion !== lock.runtime.version
    )
      throw gate(
        "LOCK_INVALID",
        "runtime",
        `${runtime.name} is PiShip ${runtime.pishipVersion} / Pi ${runtime.piVersion} / npm lock ${runtime.npmLockSha256}, but the pack is locked for PiShip ${lock.runtime.pishipVersion} / Pi ${lock.runtime.version} / npm lock ${lock.runtime.npmLockSha256}`,
        "Run piship lock with that runtime's piship.mjs, or supply the runtime the lock names",
      );
    archives[runtime.target] = runtime;
  }
  const excluded: Record<string, string> = {};
  const targets: string[] = [];
  for (const target of release.targets) {
    const sandbox = sandboxGate(lock, target);
    if (sandbox) excluded[target] = sandbox.message;
    else if (!archives[target])
      excluded[target] = "no runtime archive was supplied";
    else {
      const missing = SEARCH_TOOLS.flatMap((tool) => {
        const wanted = lock.searchTools?.[tool]?.version;
        const has = archives[target]?.searchTools[tool];
        return wanted && wanted !== has
          ? [`${tool} ${wanted} (the runtime has ${has ?? "none"})`]
          : [];
      });
      if (missing.length)
        excluded[target] =
          `${archives[target]?.name} does not bundle the locked search tools: ${missing.join(", ")}; use a runtime with those versions, or lock the versions it bundles`;
      else targets.push(target);
    }
  }
  if (!targets.length)
    throw gate(
      "CONFIG_INVALID",
      "runtime",
      `no release target can be served (${Object.values(excluded).join("; ")})`,
    );

  const name = `${lock.app.id}-${lock.app.version}-pack`;
  const outputRoot = resolve(options.outputRoot ?? "dist", "packs");
  mkdirSync(outputRoot, { recursive: true });
  sweepOutputStaging(outputRoot, "release", options);
  const temporary = createTemporaryDirectory(
    outputRoot,
    "release",
    lock.app.id,
  );
  try {
    const root = join(temporary.path, name);
    const files = [
      "piship.yaml",
      "piship.lock",
      ...lock.resources.map((resource) => resource.path),
      ...(lock.packages ?? []).flatMap((entry) => {
        const found = packageLockFiles(base, entry.id);
        return [found.manifest, found.lockfile]
          .filter((file) => existsSync(file))
          .map((file) => file.slice(base.length + 1).replaceAll("\\", "/"));
      }),
    ];
    for (const file of files) {
      const target = join(root, "pack", file);
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(
        file === "piship.yaml" ? manifestPath : join(base, file),
        target,
      );
    }
    // The pure-JavaScript Pi package trees, vendored exactly as a release
    // payload has them, so an install needs no registry.
    if (lock.packages?.length) {
      vendorPiPackages(
        lock,
        readManifest(manifestPath),
        base,
        join(root, "pack"),
      );
      const vendored = join(root, "pack", PI_PACKAGE_VENDOR_DIRECTORY);
      for (const entry of readdirSync(vendored, {
        recursive: true,
        withFileTypes: true,
      }))
        if (entry.isFile())
          files.push(
            relative(
              join(root, "pack"),
              join(entry.parentPath, entry.name),
            ).replaceAll("\\", "/"),
          );
    }
    const metadata: PackMetadata = {
      schema: PACK_SCHEMA,
      distribution: {
        id: lock.app.id,
        name: lock.app.name,
        version: lock.app.version,
        command: lock.app.command,
        mode: lock.deployment.mode,
      },
      manifestSchema: lock.manifest.schema,
      lockSchema: lock.schema,
      lockSha256: hash(readFileSync(join(base, "piship.lock"))),
      pack: {
        path: "pack",
        inventorySha256: hash(
          formatChecksums(
            join(root, "pack"),
            files.map((file) => file.replaceAll("\\", "/")),
          ),
        ),
        files: files.length,
      },
      pi: {
        package: lock.runtime.package,
        version: lock.runtime.version,
        compatibility: piCompatibility(lock),
        surfaces: piCompatibilitySurfaces(lock),
      },
      stateSchemas: lock.runtime.stateSchemas ?? STATE_SCHEMAS,
      runtime: {
        pishipVersion: lock.runtime.pishipVersion,
        pi: lock.runtime.version,
        npmLockSha256: lock.runtime.npmLockSha256,
        archives: Object.fromEntries(
          targets.map((target) => {
            const { name, sha256, bytes, inventorySha256 } = archives[
              target
            ] as PackRuntime;
            return [target, { name, sha256, bytes, inventorySha256 }];
          }),
        ),
      },
      runtimeSettings: {
        bundle: true,
        strip: true,
        overridden: [
          ...(bundle ? [] : ["release.bundle"]),
          ...(strip ? [] : ["release.strip"]),
        ],
      },
      targets,
      excluded,
    };
    writeJson(join(root, "pack.json"), metadata);
    writeFileSync(
      join(root, "checksums.txt"),
      formatChecksums(root, [
        "pack.json",
        ...files.map((file) => `pack/${file.replaceAll("\\", "/")}`),
      ]),
    );
    const staged = join(temporary.path, `${name}.tar.gz`);
    const result = await createArchive(root, name, staged);
    const directory = join(outputRoot, name);
    const archive = join(outputRoot, `${name}.tar.gz`);
    rmSync(directory, { recursive: true, force: true });
    rmSync(archive, { force: true });
    renameSync(root, directory);
    renameSync(staged, archive);
    writeFileSync(`${archive}.sha256`, `${result.sha256}  ${name}.tar.gz\n`);
    return { name, directory, archive, sha256: result.sha256, metadata };
  } finally {
    temporary.remove();
  }
}
