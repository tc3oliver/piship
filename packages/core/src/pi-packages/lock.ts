// Pi packages in `piship lock`, the stale-lock check, and `piship build`.
// Only `piship lock` resolves over the network; every other reader takes the
// lock entries as recorded and checks what it can offline.
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DeclaredPackage, Manifest } from "@piship/schema";
import { currentTarget, REVIEWED_INSTALL_SCRIPTS } from "../compatibility.js";
import type { DistributionLock } from "../lock-schema.js";
import {
  checkCertifiedPackage,
  checkLockedPiPackage,
  checkPiPackageInstallScripts,
  checkPiPackageSources,
  PI_PACKAGE_VENDOR_DIRECTORY,
} from "./gates.js";
import type { CommandRunner } from "./command.js";
import { checkLocalDeclaration, packageError } from "./refs.js";
import {
  copyLocalPackage,
  type PackageContext,
  packageTreeDigest,
  resolvePiPackage,
  type VendoredPiPackage,
  vendorPiPackage,
} from "./resolve.js";
import { effectivePackageTrust } from "./trust.js";
import type { LockedPiPackage } from "./types.js";

/**
 * Where `piship lock` stores each package's generated npm root, beside
 * `piship.lock`: `piship.lock.d/packages/<id>/{package.json,package-lock.json}`.
 */
export const PACKAGE_LOCK_DIRECTORY = "piship.lock.d/packages";

export function packageLockFiles(
  base: string,
  id: string,
): { readonly manifest: string; readonly lockfile: string } {
  const directory = join(base, ...PACKAGE_LOCK_DIRECTORY.split("/"), id);
  return {
    manifest: join(directory, "package.json"),
    lockfile: join(directory, "package-lock.json"),
  };
}

export function declaredPackages(
  manifest: Manifest,
): readonly DeclaredPackage[] {
  return manifest.governance?.resources.packages ?? [];
}

/** The resolution context of a manifest's packages. */
export function packageContext(
  manifest: Manifest,
  base: string,
  options: {
    readonly env?: NodeJS.ProcessEnv;
    readonly run?: CommandRunner;
  } = {},
): PackageContext {
  return {
    distributionDir: base,
    mode: manifest.deployment.mode,
    trust: effectivePackageTrust(
      manifest.governance?.packageTrust,
      manifest.deployment.mode,
    ),
    targets: manifest.lifecycle?.release.targets ?? [currentTarget()],
    ...(options.env ? { env: options.env } : {}),
    ...(options.run ? { run: options.run } : {}),
  };
}

/**
 * The reviewed lifecycle scripts for package closures: PiShip's own review
 * plus the manifest's `release.installScripts`
 * (`pi-packages/<id>/node_modules/<name>@<version>`).
 */
export function reviewedInstallScripts(
  release: { readonly installScripts?: readonly string[] } | undefined,
): readonly string[] {
  return [...REVIEWED_INSTALL_SCRIPTS, ...(release?.installScripts ?? [])];
}

/**
 * `piship lock`: resolve every declared package, apply the source and
 * install-script gates to its closure, and write its npm root beside the
 * lock. Package directories no longer declared are removed.
 */
export function lockPiPackages(
  manifest: Manifest,
  base: string,
  options: {
    readonly env?: NodeJS.ProcessEnv;
    readonly run?: CommandRunner;
  } = {},
): LockedPiPackage[] {
  const declared = declaredPackages(manifest);
  const root = join(base, ...PACKAGE_LOCK_DIRECTORY.split("/"));
  if (existsSync(root))
    for (const id of readdirSync(root))
      if (!declared.some((item) => item.id === id))
        rmSync(join(root, id), { recursive: true, force: true });
  if (!declared.length) return [];
  const context = packageContext(manifest, base, options);
  const release = manifest.lifecycle?.release;
  return declared.map((declaration) => {
    const resolved = resolvePiPackage(declaration, context);
    checkCertifiedPackage(declaration, resolved.locked);
    // The install-script review applies with or without lifecycle.release;
    // the source gate needs its release.sources.
    checkPiPackageInstallScripts(
      declaration.id,
      resolved.dependencies,
      resolved.ownInstallScript,
      "Release",
      reviewedInstallScripts(release),
    );
    if (release)
      checkPiPackageSources(
        declaration.id,
        resolved.dependencies,
        release.sources,
        "Release",
        reviewedInstallScripts(release),
      );
    const files = packageLockFiles(base, declaration.id);
    mkdirSync(join(files.lockfile, ".."), { recursive: true });
    writeFileSync(files.manifest, resolved.manifest);
    writeFileSync(files.lockfile, resolved.lockfile);
    return resolved.locked;
  });
}

function readLockPackages(base: string): readonly LockedPiPackage[] {
  try {
    const lock = JSON.parse(
      readFileSync(join(base, "piship.lock"), "utf8"),
    ) as Partial<DistributionLock>;
    return Array.isArray(lock.packages) ? lock.packages : [];
  } catch {
    return [];
  }
}

const sha256 = (content: Buffer) =>
  createHash("sha256").update(content).digest("hex");

/**
 * The stale-lock check, offline: the recorded entries of the packages still
 * declared, with the sha256 of each stored npm lockfile and, for a local
 * package, the tree digest of its current content recomputed. A missing
 * entry, a changed lockfile, or changed local content then differs from the
 * recorded lock, so the lock reads as stale.
 */
export function currentPiPackages(
  manifest: Manifest,
  base: string,
): LockedPiPackage[] {
  const declared = declaredPackages(manifest);
  if (!declared.length) return [];
  const recorded = readLockPackages(base);
  const context = packageContext(manifest, base);
  const output: LockedPiPackage[] = [];
  for (const declaration of declared) {
    const entry = recorded.find((item) => item.id === declaration.id);
    if (
      !entry ||
      entry.source !== declaration.source ||
      entry.class !== declaration.class
    )
      continue;
    const { lockfile } = packageLockFiles(base, declaration.id);
    // Spread first so every field keeps its recorded position: the stale
    // check compares the serialized lock. A missing lockfile never matches.
    let current: LockedPiPackage = {
      ...entry,
      lockfileSha256: existsSync(lockfile)
        ? sha256(readFileSync(lockfile))
        : "missing",
    };
    if (declaration.source === "local") {
      const source = checkLocalDeclaration(declaration, base, context.trust);
      const scratch = mkdtempSync(join(tmpdir(), "piship-package-local-"));
      try {
        const tree = localTree(declaration.id, source, scratch);
        current = {
          ...current,
          tree: `sha256-${tree.sha256}`,
          files: tree.files,
        };
      } finally {
        rmSync(scratch, { recursive: true, force: true });
      }
    }
    output.push(current);
  }
  return output;
}

/** A local package's tree digest exactly as vendoring copies it. */
function localTree(id: string, source: string, scratch: string) {
  const target = join(scratch, "package");
  copyLocalPackage(id, source, target);
  return packageTreeDigest(id, target);
}

/**
 * `piship build`: vendor every locked package into
 * `<payload>/pi-packages/<id>` from exactly what the lock and its stored npm
 * lockfiles pin. With supply-chain gates on, each closure passes the
 * release source and install-script gates first.
 */
export function vendorPiPackages(
  lock: DistributionLock,
  manifest: Manifest,
  base: string,
  payload: string,
  options: { readonly supplyChainGates?: boolean } = {},
): VendoredPiPackage[] {
  const locked = lock.packages ?? [];
  if (!locked.length) return [];
  const context = packageContext(manifest, base);
  const output: VendoredPiPackage[] = [];
  for (const entry of locked) {
    const declaration = declaredPackages(manifest).find(
      (item) => item.id === entry.id,
    );
    if (!declaration)
      throw packageError(
        "LOCK_INVALID",
        entry.id,
        "the lock records a package the manifest no longer declares",
        "Run piship lock",
      );
    const files = packageLockFiles(base, entry.id);
    if (!existsSync(files.lockfile))
      throw packageError(
        "LOCK_INVALID",
        entry.id,
        `the package npm lockfile is missing from ${PACKAGE_LOCK_DIRECTORY}`,
        "Run piship lock",
      );
    const lockfile = readFileSync(files.lockfile, "utf8");
    if (options.supplyChainGates !== false && lock.release)
      checkLockedPiPackage(entry, lockfile, {
        trust: context.trust,
        sources: lock.release.sources,
        stage: "Build",
        reviewed: reviewedInstallScripts(lock.release),
      });
    const vendored = vendorPiPackage(
      declaration,
      { locked: entry, lockfile },
      context,
      join(payload, PI_PACKAGE_VENDOR_DIRECTORY, entry.id),
    );
    // What vendoring found (a binding.gyp, the package root's own scripts)
    // passes the install-script review with or without lifecycle.release.
    if (options.supplyChainGates !== false)
      checkPiPackageInstallScripts(
        entry.id,
        vendored.dependencies,
        vendored.ownInstallScript,
        "Build",
        reviewedInstallScripts(lock.release),
      );
    output.push(vendored);
  }
  return output;
}
