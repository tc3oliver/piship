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
  checkRegistrySpecs,
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
  /**
   * A git or local package whose own root has an npm install script or a
   * binding.gyp: its install-script review key, `package@<commit or tree>`.
   */
  readonly ownInstallScript?: string;
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

/**
 * The environment of a git call, or, with `git` (the refusing stub), of an
 * npm call. An npm call carries `--ignore-scripts` and `--git` in the
 * environment too: a hosted-git spec deeper in the closure can be fetched
 * as an https tarball without git, and npm prepares it with a nested
 * `npm install` that inherits this environment but none of the flags.
 */
function environment(context: PackageContext, git?: string): NodeJS.ProcessEnv {
  return {
    ...(context.env ?? process.env),
    GIT_TERMINAL_PROMPT: "0",
    ...(git ? { npm_config_ignore_scripts: "true", npm_config_git: git } : {}),
  };
}

/**
 * Write the `git` every npm call runs instead of the real one: it exits 1 for
 * any arguments. npm reaches git only to fetch a git dependency, which a
 * package closure never holds, and a git fetch runs the repository's
 * `prepare` under the repository's own npm configuration despite
 * `--ignore-scripts`. A `.cmd` on Windows, where npm cannot spawn it without
 * a shell and so fails closed as well.
 */
function refusingGit(work: string): string {
  const windows = process.platform === "win32";
  const path = join(work, windows ? "refuse-git.cmd" : "refuse-git");
  writeFileSync(path, windows ? "@exit /b 1\r\n" : "#!/bin/sh\nexit 1\n", {
    mode: 0o755,
  });
  return path;
}

/** The flags of every npm call: the refusing git, and the declared registry. */
function npmArgs(declaration: DeclaredPackage, git: string): string[] {
  return [
    `--git=${git}`,
    ...(declaration.source === "npm" && declaration.registry
      ? [
          `--registry=${canonicalSourceUrl(declaration.id, "registry", declaration.registry)}/`,
        ]
      : []),
  ];
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

/**
 * `name` spells `node_modules` as a filesystem may fold it: in any case, or
 * with a compatibility character such as `ſ` (U+017F), which APFS folds to
 * `s` and `toLowerCase` keeps.
 */
export function foldsToNodeModules(name: string): boolean {
  return name.normalize("NFKC").toUpperCase().toLowerCase() === "node_modules";
}

/**
 * The filesystem resolves `node_modules` in `dir` to an entry whose listed
 * name is not `node_modules`: a variant only the filesystem's own folding
 * matches. Node would load modules from it.
 */
export function hasNodeModulesAlias(
  dir: string,
  names: readonly string[],
): boolean {
  return (
    !names.includes("node_modules") &&
    lstatSync(join(dir, "node_modules"), { throwIfNoEntry: false }) !==
      undefined
  );
}

function refuseNodeModulesVariant(id: string, name: string): never {
  throw packageError(
    "POLICY_DENIED",
    id,
    `${name} is a variant of node_modules the filesystem resolves; dependencies are installed only from the package npm lockfile`,
  );
}

/**
 * Copy a local package without node_modules, .git, or symlinks. A variant
 * of `node_modules` (such as `Node_Modules` or `node_moduleſ`) is refused
 * rather than copied: a folding filesystem resolves modules from it.
 */
export function copyLocalPackage(
  id: string,
  source: string,
  target: string,
): void {
  mkdirSync(target, { recursive: true });
  const names = readdirSync(source).sort();
  const variant = names.find(
    (name) => name !== "node_modules" && foldsToNodeModules(name),
  );
  if (variant !== undefined) refuseNodeModulesVariant(id, variant);
  if (hasNodeModulesAlias(source, names))
    refuseNodeModulesVariant(id, "node_modules");
  for (const name of names) {
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

/**
 * A git or local package's own tree, checked right after extraction or copy
 * and before anything in it is read: no symlink, and no `node_modules` at any
 * depth. Shipped modules would load ahead of the locked closure while no
 * lockfile entry, tree digest, or binding.gyp scan covers them.
 */
function checkSourceTree(id: string, root: string): void {
  const walk = (dir: string) => {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink())
        throw packageError(
          "POLICY_DENIED",
          id,
          `${posix(relative(root, path))} is a symlink; packages are vendored without symlinks`,
        );
      if (!entry.isDirectory()) continue;
      // Any variant a folding filesystem resolves modules from.
      if (foldsToNodeModules(entry.name))
        throw packageError(
          "POLICY_DENIED",
          id,
          `${posix(relative(root, path))} ships its own node_modules; dependencies are installed only from the package npm lockfile`,
        );
      walk(path);
    }
    // A variant only the filesystem's folding matches, found by asking it.
    if (
      hasNodeModulesAlias(
        dir,
        entries.map((entry) => entry.name),
      )
    )
      throw packageError(
        "POLICY_DENIED",
        id,
        `${posix(relative(root, join(dir, "node_modules")))} resolves to a variant of node_modules; dependencies are installed only from the package npm lockfile`,
      );
  };
  walk(root);
}

/**
 * Every package directory under the npm root's `node_modules` is one the
 * package npm lockfile installs, and a `node_modules` directory holds nothing
 * else (npm's own top-level `.package-lock.json` aside). A published tarball
 * can carry a `node_modules` of its own, which npm extracts without a
 * lockfile entry, integrity, or install-script scan.
 */
function checkInstalledModules(
  id: string,
  directory: string,
  lockfile: NpmLockfile,
): void {
  const packages = lockfile.packages ?? {};
  const visit = (modules: string, top: boolean) => {
    if (!existsSync(modules)) return;
    for (const entry of readdirSync(modules, { withFileTypes: true })) {
      if (top && entry.name === ".package-lock.json" && entry.isFile())
        continue;
      const path = join(modules, entry.name);
      const roots =
        entry.isDirectory() && entry.name.startsWith("@")
          ? readdirSync(path, { withFileTypes: true }).map((scoped) => ({
              path: join(path, scoped.name),
              directory: scoped.isDirectory(),
            }))
          : [{ path, directory: entry.isDirectory() }];
      for (const root of roots) {
        const key = posix(relative(directory, root.path));
        if (!root.directory || !packages[key])
          throw packageError(
            "POLICY_DENIED",
            id,
            `${key} is not a package the npm lockfile installs; a package cannot ship its own node_modules`,
          );
        visit(join(root.path, "node_modules"), false);
      }
    }
  };
  visit(join(directory, "node_modules"), true);
}

/** npm's install-time lifecycle scripts; a binding.gyp implies `install`. */
function hasInstallScript(root: string, manifest: PackageJson): boolean {
  const scripts = manifest.scripts;
  return (
    existsSync(join(root, "binding.gyp")) ||
    (["preinstall", "install", "postinstall"] as const).some(
      (name) =>
        !!scripts &&
        typeof scripts === "object" &&
        typeof (scripts as Record<string, unknown>)[name] === "string",
    )
  );
}

interface PackageJson {
  readonly name?: unknown;
  readonly version?: unknown;
  readonly dependencies?: Record<string, string>;
  readonly optionalDependencies?: Record<string, string>;
  readonly scripts?: unknown;
}

/**
 * The npm root PiShip installs a git or local package's dependencies into:
 * only `dependencies` and `optionalDependencies`, never dev or peer ones,
 * each a registry spec (checked before npm runs).
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
  checkRegistrySpecs(id, manifest);
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
  git: string,
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
      ...npmArgs(declaration, git),
    ],
    { cwd, env: environment(context, git) },
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
  git: string,
): { version: string; integrity: string } {
  const { id } = declaration;
  const versions = npmView(
    run,
    declaration,
    `${declaration.package}@${declaration.version}`,
    "version",
    context,
    cwd,
    git,
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
    git,
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
  // The repository's own .gitattributes cannot rewrite what is archived: no
  // end-of-line conversion, filter, ident, export-subst, or re-encoding. The
  // repository-local attributes file outranks every in-tree one.
  mkdirSync(join(bare, "info"), { recursive: true });
  writeFileSync(
    join(bare, "info", "attributes"),
    "* -text -eol -filter -ident -export-subst -working-tree-encoding\n",
  );
  mustRun(
    run,
    id,
    "git",
    [
      "-c",
      "transfer.fsckObjects=true",
      "-C",
      bare,
      "fetch",
      "--quiet",
      "--no-tags",
      "--depth=1",
      "--",
      url,
      sha,
    ],
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
    [
      "-c",
      "core.autocrlf=false",
      "-c",
      "core.eol=lf",
      "-C",
      bare,
      "archive",
      "--format=tar",
      sha,
    ],
    { cwd: work, env },
  );
  mkdirSync(target, { recursive: true });
  // `git archive` writes UTF-8 names without a charset header. Windows' tar
  // (bsdtar) reads such names in the ANSI code page unless told otherwise,
  // so `node_moduleſ` would land as `node_moduleÅ¿` and a non-ASCII name
  // would not be the committed one.
  const charset =
    process.platform === "win32" ? ["--options", "hdrcharset=UTF-8"] : [];
  mustRun(run, id, "tar", [...charset, "-xf", "-", "-C", target], {
    cwd: work,
    env,
    input: archive,
  });
}

/** The first npm whose pacote (20) honours --ignore-scripts when it prepares a git dependency. */
const MINIMUM_NPM_MAJOR = 11;

/**
 * Refuse to resolve with an npm older than 11. npm 10 (pacote 19, bundled
 * with Node 22) prepares a git dependency it meets while resolving by
 * running its `prepare` in the npm process itself, with no `ignoreScripts`
 * check, so neither `--ignore-scripts` nor the refusing git stops it. `npm
 * ci` from a lockfile whose closure was checked (no git entries) is not a
 * resolving call and needs no check.
 */
function checkNpmVersion(
  run: CommandRunner,
  id: string,
  cwd: string,
  env: NodeJS.ProcessEnv,
): void {
  const version = mustRun(run, id, "npm", ["--version"], { cwd, env })
    .toString()
    .trim();
  const major = Number(/^(\d+)\./.exec(version)?.[1] ?? Number.NaN);
  if (!(major >= MINIMUM_NPM_MAJOR))
    throw packageError(
      "POLICY_DENIED",
      id,
      `npm ${Number.isNaN(major) ? JSON.stringify(version) : major} runs a git dependency's prepare despite --ignore-scripts; lock packages with npm ${MINIMUM_NPM_MAJOR} or later`,
      `Install npm ${MINIMUM_NPM_MAJOR} or later (npm install -g npm@${MINIMUM_NPM_MAJOR}) and run piship lock again`,
    );
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
  let url: string | undefined;
  /** npm: the exact version; git: the full commit SHA. */
  let resolved: string | undefined;
  let packageRoot: string;
  let wrapper: Record<string, unknown>;
  let integrity: string | undefined;
  let ownInstallScript = false;
  mkdirSync(directory, { recursive: true });
  const git = refusingGit(work);
  /** The environment of this package's npm calls. */
  const env = environment(context, git);
  if (declaration.source === "npm") {
    checkNpmDeclaration(declaration, context.mode);
    if (!pin) checkNpmVersion(run, id, work, env);
    const npm = pin
      ? {
          version: pin.locked.version ?? "",
          integrity: pin.locked.integrity ?? "",
        }
      : resolveNpm(run, declaration, context, work, git);
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
    checkSourceTree(id, packageRoot);
    const own = existsSync(join(packageRoot, "package.json"))
      ? readJson<PackageJson>(
          id,
          join(packageRoot, "package.json"),
          "package.json",
        )
      : {};
    // Checked before npm runs: every dependency must be a registry spec.
    wrapper = wrapperFor(id, own);
    ownInstallScript = hasInstallScript(packageRoot, own);
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
  } else {
    // npm has already been checked for an npm package.
    if (declaration.source !== "npm") checkNpmVersion(run, id, directory, env);
    mustRun(
      run,
      id,
      "npm",
      [
        "install",
        "--package-lock-only",
        ...NPM_FLAGS,
        ...npmArgs(declaration, git),
      ],
      { cwd: directory, env },
    );
  }
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
  mustRun(run, id, "npm", ["ci", ...NPM_FLAGS, ...npmArgs(declaration, git)], {
    cwd: directory,
    env,
  });
  checkInstalledModules(id, directory, parsed);
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
  return {
    locked,
    lockfile,
    manifest,
    dependencies,
    ...(ownInstallScript
      ? { ownInstallScript: `package@${locked.commit ?? locked.tree}` }
      : {}),
    directory,
    packageRoot,
  };
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
    const { locked, lockfile, manifest, dependencies, ownInstallScript } =
      materialize(declaration, context, join(work, "vendor"), work);
    return {
      locked,
      lockfile,
      manifest,
      dependencies,
      ...(ownInstallScript ? { ownInstallScript } : {}),
    };
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
