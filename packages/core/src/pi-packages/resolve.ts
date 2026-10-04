// Lock-time resolution and build-time vendoring of Pi packages (spec §8.2).
// PiShip, never Pi, installs a package: npm packages and every package's
// dependencies through a generated per-package npm lockfile and
// `npm ci --ignore-scripts --omit=peer --legacy-peer-deps`, git sources through
// `git archive <sha>` (never a checkout), local sources by copy. The result is
// a vendored directory whose resource inventory is the only thing Pi sees.
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { canonicalJson } from "../digest.js";
import { type CommandRunner, mustRun, runCommand } from "./command.js";
import { expandPackageResources } from "./expand.js";
import {
  canonicalSourceUrl,
  checkGitDeclaration,
  checkLocalDeclaration,
  checkLockfileClosure,
  checkNpmDeclaration,
  isExactVersion,
  isHostProvided,
  type NpmLockfile,
  optionalDependenciesFor,
  packageError,
} from "./refs.js";
import type {
  DeclaredPackage,
  DeploymentMode,
  LockedPiPackage,
  PackageDependency,
  PackageTrustConfig,
} from "./types.js";

export interface PackageContext {
  /** The distribution directory, which local package paths are confined to. */
  readonly distributionDir: string;
  readonly mode: DeploymentMode;
  /** The effective packageTrust (see `effectivePackageTrust`). */
  readonly trust: PackageTrustConfig;
  /** Release targets whose optional dependencies the lock records. */
  readonly targets: readonly string[];
  /** Environment for npm and git; their own configuration supplies any credential. */
  readonly env?: NodeJS.ProcessEnv;
  readonly run?: CommandRunner;
  /** Parent for working directories; defaults to the OS temporary directory. */
  readonly workDir?: string;
}

/** A locked package plus the per-package npm lockfile stored beside the lock. */
export interface ResolvedPiPackage {
  readonly locked: LockedPiPackage;
  readonly lockfile: string;
  /** The generated npm root package.json the lockfile belongs to. */
  readonly manifest: string;
  /** The closure as the lockfile records it, with binding.gyp counted as an install script. */
  readonly dependencies: readonly PackageDependency[];
}

/** A vendored package directory: the npm root and the package root inside it. */
export interface VendoredPiPackage extends ResolvedPiPackage {
  /** Holds the generated package.json, the lockfile, and node_modules. */
  readonly directory: string;
  /** Root the resource inventory paths are relative to. */
  readonly packageRoot: string;
}

const NPM_FLAGS = [
  "--ignore-scripts",
  "--omit=peer",
  "--omit=dev",
  "--no-audit",
  "--no-fund",
  "--no-update-notifier",
  "--no-bin-links",
  // Deviation from the spec's `--omit=peer` alone: with it, npm still
  // resolves every peer into the lockfile, so a package that declares the
  // host-provided Pi packages as peers (as Pi's docs ask) would pull Pi's
  // whole dependency tree from the registry at lock time. Peers are never
  // resolved or installed; Pi supplies them at runtime.
  "--legacy-peer-deps",
];

const posix = (path: string) => path.split(sep).join("/");
const sha256 = (content: string | Buffer) =>
  createHash("sha256").update(content).digest("hex");

function environment(context: PackageContext): NodeJS.ProcessEnv {
  return { ...(context.env ?? process.env), GIT_TERMINAL_PROMPT: "0" };
}

function registryArgs(declaration: DeclaredPackage): string[] {
  return declaration.source === "npm" && declaration.registry
    ? [
        `--registry=${canonicalSourceUrl(declaration.id, "registry", declaration.registry)}/`,
      ]
    : [];
}

function readJson<T>(id: string, file: string, what: string): T {
  try {
    return JSON.parse(readFileSync(file, "utf8")) as T;
  } catch {
    throw packageError("CONFIG_INVALID", id, `${what} is not readable JSON`);
  }
}

/**
 * sha256 over `<sha256>  <path>` lines of the package's own files, sorted,
 * and their count. The root `node_modules` (its installed dependencies) is
 * left out: the lockfile integrity covers it. Symlinks are refused.
 */
export function packageTreeDigest(
  id: string,
  root: string,
): { sha256: string; files: number } {
  const lines: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name);
      if (dir === root && name === "node_modules") continue;
      const stat = lstatSync(path);
      if (stat.isSymbolicLink())
        throw packageError(
          "POLICY_DENIED",
          id,
          `${posix(relative(root, path))} is a symlink; packages are vendored without symlinks`,
        );
      if (stat.isDirectory()) walk(path);
      else if (stat.isFile())
        lines.push(
          `${sha256(readFileSync(path))}  ${posix(relative(root, path))}\n`,
        );
    }
  };
  walk(root);
  lines.sort();
  return { sha256: sha256(lines.join("")), files: lines.length };
}

/** Package roots under `node_modules` that ship a binding.gyp (an implicit node-gyp install). */
function bindingGypPaths(directory: string): Set<string> {
  const found = new Set<string>();
  const visit = (modules: string) => {
    if (!existsSync(modules)) return;
    for (const entry of readdirSync(modules, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
      const path = join(modules, entry.name);
      const roots = entry.name.startsWith("@")
        ? readdirSync(path, { withFileTypes: true })
            .filter((scoped) => scoped.isDirectory())
            .map((scoped) => join(path, scoped.name))
        : [path];
      for (const root of roots) {
        if (existsSync(join(root, "binding.gyp")))
          found.add(posix(relative(directory, root)));
        visit(join(root, "node_modules"));
      }
    }
  };
  visit(join(directory, "node_modules"));
  return found;
}

/** Copy a local package without node_modules, .git, or symlinks. */
export function copyLocalPackage(
  id: string,
  source: string,
  target: string,
): void {
  mkdirSync(target, { recursive: true });
  for (const name of readdirSync(source).sort()) {
    if (name === "node_modules" || name === ".git") continue;
    const from = join(source, name);
    const to = join(target, name);
    const stat = lstatSync(from);
    if (stat.isSymbolicLink())
      throw packageError(
        "POLICY_DENIED",
        id,
        `${name} is a symlink; packages are vendored without symlinks`,
      );
    if (stat.isDirectory()) copyLocalPackage(id, from, to);
    else if (stat.isFile()) copyFileSync(from, to);
  }
}

interface PackageJson {
  readonly name?: unknown;
  readonly version?: unknown;
  readonly dependencies?: Record<string, string>;
  readonly optionalDependencies?: Record<string, string>;
}

/**
 * The npm root PiShip installs a git or local package's dependencies into:
 * only `dependencies` and `optionalDependencies`, never dev or peer ones.
 */
function wrapperFor(
  id: string,
  manifest: PackageJson,
): Record<string, unknown> {
  for (const field of ["dependencies", "optionalDependencies"] as const)
    for (const name of Object.keys(manifest[field] ?? {}))
      if (isHostProvided(name))
        throw packageError(
          "POLICY_DENIED",
          id,
          `the package lists host-provided ${name} in ${field}; declare it in peerDependencies instead`,
        );
  return {
    name: `piship-package-${id}`,
    version: "0.0.0",
    private: true,
    dependencies: manifest.dependencies ?? {},
    optionalDependencies: manifest.optionalDependencies ?? {},
  };
}

function npmView(
  run: CommandRunner,
  declaration: DeclaredPackage & { source: "npm" },
  spec: string,
  field: string | undefined,
  context: PackageContext,
  cwd: string,
): unknown {
  const output = mustRun(
    run,
    declaration.id,
    "npm",
    [
      "view",
      spec,
      ...(field ? [field] : []),
      "--json",
      ...registryArgs(declaration),
    ],
    { cwd, env: environment(context) },
  ).toString();
  try {
    return JSON.parse(output);
  } catch {
    throw packageError(
      "UPDATE_FAILED",
      declaration.id,
      `npm view ${spec} returned no JSON`,
    );
  }
}

/** Resolve npm `package@version` to an exact version with its registry integrity and tarball. */
function resolveNpm(
  run: CommandRunner,
  declaration: DeclaredPackage & { source: "npm" },
  context: PackageContext,
  cwd: string,
): { version: string; integrity: string } {
  const { id } = declaration;
  const versions = npmView(
    run,
    declaration,
    `${declaration.package}@${declaration.version}`,
    "version",
    context,
    cwd,
  );
  const version = Array.isArray(versions) ? versions.at(-1) : versions;
  if (typeof version !== "string" || !isExactVersion(version))
    throw packageError(
      "CONFIG_INVALID",
      id,
      `${declaration.package}@${declaration.version} matches no published version`,
    );
  const manifest = npmView(
    run,
    declaration,
    `${declaration.package}@${version}`,
    undefined,
    context,
    cwd,
  ) as
    | (PackageJson & { dist?: { integrity?: unknown; tarball?: unknown } })
    | null;
  // The package's own dependencies are checked before npm resolves them.
  wrapperFor(id, manifest ?? {});
  const dist = manifest?.dist;
  const integrity = typeof dist?.integrity === "string" ? dist.integrity : "";
  const tarball = typeof dist?.tarball === "string" ? dist.tarball : "";
  if (context.trust.npm?.requireIntegrity !== false && !integrity)
    throw packageError(
      "INTEGRITY_FAILED",
      id,
      `${declaration.package}@${version} has no registry dist.integrity`,
    );
  // A tarball URL with userinfo or a query is refused before anything is installed.
  canonicalSourceUrl(id, "dist.tarball", tarball);
  return { version, integrity };
}

/** Resolve a git ref to a full commit SHA with `git ls-remote` (personal only). */
function resolveGitRef(
  run: CommandRunner,
  id: string,
  url: string,
  ref: string,
  context: PackageContext,
  cwd: string,
): string {
  if (/^[0-9a-f]{40}$/.test(ref)) return ref;
  const lines = mustRun(run, id, "git", ["ls-remote", "--", url, ref], {
    cwd,
    env: environment(context),
  })
    .toString()
    .split("\n")
    .map((line) => line.split("\t"))
    .filter((parts): parts is [string, string] => parts.length === 2);
  const want =
    ref === "HEAD"
      ? ["HEAD"]
      : [`refs/tags/${ref}^{}`, `refs/tags/${ref}`, `refs/heads/${ref}`, ref];
  for (const name of want) {
    const sha = lines.find(([, refName]) => refName === name)?.[0];
    if (sha && /^[0-9a-f]{40}$/.test(sha)) return sha;
  }
  throw packageError(
    "CONFIG_INVALID",
    id,
    `ref ${JSON.stringify(ref)} was not found in the repository`,
  );
}

/** Fetch one commit into a scratch bare repository and extract it with `git archive`. */
function archiveGitCommit(
  run: CommandRunner,
  id: string,
  url: string,
  sha: string,
  target: string,
  context: PackageContext,
  work: string,
): void {
  const env = environment(context);
  const bare = join(work, "repository.git");
  mustRun(run, id, "git", ["init", "--bare", "--quiet", bare], {
    cwd: work,
    env,
  });
  mustRun(
    run,
    id,
    "git",
    ["-C", bare, "fetch", "--quiet", "--no-tags", "--depth=1", "--", url, sha],
    { cwd: work, env },
  );
  // The commit must exist as fetched; its content is then pinned by the
  // locked tree digest, which is stricter than git's own tree hash.
  mustRun(run, id, "git", ["-C", bare, "cat-file", "-e", `${sha}^{commit}`], {
    cwd: work,
    env,
  });
  const archive = mustRun(
    run,
    id,
    "git",
    ["-C", bare, "archive", "--format=tar", sha],
    { cwd: work, env },
  );
  mkdirSync(target, { recursive: true });
  mustRun(run, id, "tar", ["-xf", "-", "-C", target], {
    cwd: work,
    env,
    input: archive,
  });
}

interface Pin {
  readonly locked: LockedPiPackage;
  readonly lockfile: string;
}

function materialize(
  declaration: DeclaredPackage,
  context: PackageContext,
  directory: string,
  work: string,
  pin?: Pin,
): VendoredPiPackage {
  const run = context.run ?? runCommand;
  const { id } = declaration;
  const env = environment(context);
  let url: string | undefined;
  /** npm: the exact version; git: the full commit SHA. */
  let resolved: string | undefined;
  let packageRoot: string;
  let wrapper: Record<string, unknown>;
  let integrity: string | undefined;
  mkdirSync(directory, { recursive: true });
  if (declaration.source === "npm") {
    checkNpmDeclaration(declaration, context.mode);
    const npm = pin
      ? {
          version: pin.locked.version ?? "",
          integrity: pin.locked.integrity ?? "",
        }
      : resolveNpm(run, declaration, context, work);
    resolved = npm.version;
    integrity = npm.integrity;
    packageRoot = join(
      directory,
      "node_modules",
      ...declaration.package.split("/"),
    );
    wrapper = {
      name: `piship-package-${id}`,
      version: "0.0.0",
      private: true,
      dependencies: { [declaration.package]: npm.version },
    };
  } else {
    packageRoot = join(directory, "package");
    if (declaration.source === "git") {
      url = checkGitDeclaration(declaration, context.trust);
      resolved =
        pin?.locked.commit ??
        resolveGitRef(run, id, url, declaration.ref, context, work);
      archiveGitCommit(run, id, url, resolved, packageRoot, context, work);
    } else {
      const source = checkLocalDeclaration(
        declaration,
        context.distributionDir,
        context.trust,
      );
      copyLocalPackage(id, source, packageRoot);
    }
    const own = existsSync(join(packageRoot, "package.json"))
      ? readJson<PackageJson>(
          id,
          join(packageRoot, "package.json"),
          "package.json",
        )
      : {};
    wrapper = wrapperFor(id, own);
  }
  const manifest = `${JSON.stringify(wrapper, null, 2)}\n`;
  writeFileSync(join(directory, "package.json"), manifest);
  const lockfilePath = join(directory, "package-lock.json");
  if (pin) {
    if (sha256(pin.lockfile) !== pin.locked.lockfileSha256)
      throw packageError(
        "INTEGRITY_FAILED",
        id,
        "the package npm lockfile does not match its sha256 in the lock",
        "Run piship lock again and review the package changes",
      );
    writeFileSync(lockfilePath, pin.lockfile);
  } else
    mustRun(
      run,
      id,
      "npm",
      [
        "install",
        "--package-lock-only",
        ...NPM_FLAGS,
        ...registryArgs(declaration),
      ],
      { cwd: directory, env },
    );
  const lockfile = readFileSync(lockfilePath, "utf8");
  const parsed = JSON.parse(lockfile) as NpmLockfile;
  const closure = checkLockfileClosure(id, parsed, context.trust);
  if (declaration.source === "npm") {
    const entry = parsed.packages?.[`node_modules/${declaration.package}`];
    if (
      !entry ||
      entry.version !== resolved ||
      (integrity && entry.integrity !== integrity)
    )
      throw packageError(
        "INTEGRITY_FAILED",
        id,
        `the npm lockfile does not pin ${declaration.package}@${resolved} with the registry integrity`,
      );
    url = closure.find(
      (item) => item.path === `node_modules/${declaration.package}`,
    )?.resolved as string;
  }
  mustRun(run, id, "npm", ["ci", ...NPM_FLAGS, ...registryArgs(declaration)], {
    cwd: directory,
    env,
  });
  if (declaration.source === "npm") {
    const installed = readJson<PackageJson>(
      id,
      join(packageRoot, "package.json"),
      "the installed package.json",
    );
    if (
      installed.name !== declaration.package ||
      installed.version !== resolved
    )
      throw packageError(
        "INTEGRITY_FAILED",
        id,
        `npm installed ${String(installed.name)}@${String(installed.version)}, not ${declaration.package}@${resolved}`,
      );
  }
  const gyp = bindingGypPaths(directory);
  const dependencies = closure.map((item) =>
    gyp.has(item.path) && !item.installScript
      ? { ...item, installScript: true as const }
      : item,
  );
  const tree = packageTreeDigest(id, packageRoot);
  const locked: LockedPiPackage = {
    id,
    source: declaration.source,
    class: declaration.class,
    ...(url ? { url } : {}),
    ...(resolved && declaration.source === "npm" ? { version: resolved } : {}),
    ...(resolved && declaration.source === "git" ? { commit: resolved } : {}),
    ...(integrity ? { integrity } : {}),
    tree: `sha256-${tree.sha256}`,
    files: tree.files,
    lockfileSha256: sha256(lockfile),
    resources: expandPackageResources(id, packageRoot, declaration.filters),
    optionalDependencies: Object.fromEntries(
      [...context.targets]
        .sort()
        .map((target) => [target, optionalDependenciesFor(parsed, target)]),
    ),
  };
  return { locked, lockfile, manifest, dependencies, directory, packageRoot };
}

function workDirectory(context: PackageContext): string {
  return mkdtempSync(join(context.workDir ?? tmpdir(), "piship-package-"));
}

/**
 * `piship lock` for one package: resolve it to an immutable identity, write
 * its npm lockfile, install it once without scripts, and expand its resource
 * inventory. Nothing is left on disk.
 */
export function resolvePiPackage(
  declaration: DeclaredPackage,
  context: PackageContext,
): ResolvedPiPackage {
  const work = workDirectory(context);
  try {
    const { locked, lockfile, manifest, dependencies } = materialize(
      declaration,
      context,
      join(work, "vendor"),
      work,
    );
    return { locked, lockfile, manifest, dependencies };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/**
 * `piship build` for one package: fetch exactly what the lock pins into
 * `directory`, install the lockfile with `npm ci --ignore-scripts`, and
 * require the same identity, tree digest, file count, and inventory.
 */
export function vendorPiPackage(
  declaration: DeclaredPackage,
  pin: Pin,
  context: PackageContext,
  directory: string,
): VendoredPiPackage {
  if (
    pin.locked.id !== declaration.id ||
    pin.locked.source !== declaration.source
  )
    throw packageError(
      "LOCK_INVALID",
      declaration.id,
      "the lock entry does not match the declaration",
      "Run piship lock again",
    );
  if (existsSync(directory) && readdirSync(directory).length)
    throw packageError(
      "CONFIG_INVALID",
      declaration.id,
      "the vendor directory is not empty",
    );
  const work = workDirectory(context);
  try {
    const vendored = materialize(declaration, context, directory, work, pin);
    const expected = pin.locked;
    const actual = vendored.locked;
    for (const [field, same] of [
      [
        "resolved version or commit",
        expected.version === actual.version &&
          expected.commit === actual.commit,
      ],
      ["integrity", expected.integrity === actual.integrity],
      [
        "tree digest and file count",
        expected.tree === actual.tree && expected.files === actual.files,
      ],
      [
        "resource inventory",
        canonicalJson(expected.resources) === canonicalJson(actual.resources),
      ],
    ] as const)
      if (!same)
        throw packageError(
          "INTEGRITY_FAILED",
          declaration.id,
          `the vendored package does not match the lock: ${field} differs`,
          "Run piship lock again and review the package changes",
        );
    return vendored;
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
