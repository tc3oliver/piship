// Declaration and resolved-reference checks for Pi packages (spec §§8.4, 9).
// Every check here is applied to resolved results, and the closure check to
// the whole per-package npm lockfile, not only the top-level entry.
import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { PiShipError, type PiShipErrorCode } from "@piship/contracts";
import type {
  DeploymentMode,
  GitPackage,
  LocalPackage,
  NpmPackage,
  PackageDependency,
  PackageTrustConfig,
} from "./types.js";

export function packageError(
  code: PiShipErrorCode,
  id: string,
  message: string,
  userAction?: string,
): PiShipError {
  return new PiShipError(code, `Package ${id}: ${message}`, {
    component: "packages",
    sanitizedDetail: { package: id },
    ...(userAction ? { userAction } : {}),
  });
}

const EXACT_VERSION =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/;
/** One comparator of a semver range: `^1.2`, `>=1.0.0-rc.1`, `1.x`, `*`. */
const COMPARATOR =
  /^(\^|~|[<>]=?|=)?(\d+|[xX*])(\.(\d+|[xX*]))?(\.(\d+|[xX*]))?(-[0-9A-Za-z.-]+)?$/;
const PACKAGE_NAME = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const FULL_SHA = /^[0-9a-f]{40}$/;
const ABBREVIATED_SHA = /^[0-9a-f]{4,39}$/i;
const SRI_SHA512 = /^sha512-[A-Za-z0-9+/]+=*$/;

export function isExactVersion(version: string): boolean {
  return EXACT_VERSION.test(version);
}

/** A semver range of comparators joined by spaces, `||`, or hyphen sets; never a tag. */
function isVersionRange(version: string): boolean {
  const sets = version.split("||").map((set) => set.trim());
  return sets.every((set) => {
    const parts = set.split(/\s+/).filter((part) => part !== "-");
    return parts.length > 0 && parts.every((part) => COMPARATOR.test(part));
  });
}

/**
 * A git or local package's own `dependencies` and `optionalDependencies`, and
 * an npm package's published ones, must be registry specs (an exact version
 * or a semver range) before npm sees them. npm fetches a git spec by cloning
 * it and running the repository's `prepare` under the repository's own npm
 * configuration despite `--ignore-scripts`, so a git, file, link, alias,
 * tarball, or dist-tag spec is refused here, before any npm call, rather
 * than in the lockfile npm would write.
 */
export function checkRegistrySpecs(
  id: string,
  manifest: {
    readonly dependencies?: unknown;
    readonly optionalDependencies?: unknown;
  },
): void {
  for (const field of ["dependencies", "optionalDependencies"] as const) {
    const specs = manifest[field];
    if (specs === undefined || specs === null) continue;
    if (typeof specs !== "object" || Array.isArray(specs))
      throw packageError(
        "CONFIG_INVALID",
        id,
        `the package's ${field} is not an object`,
      );
    for (const [name, spec] of Object.entries(specs)) {
      if (!PACKAGE_NAME.test(name))
        throw packageError(
          "POLICY_DENIED",
          id,
          `the package lists ${JSON.stringify(name)} in ${field}, which is not an npm package name`,
        );
      if (
        typeof spec !== "string" ||
        !(isExactVersion(spec) || isVersionRange(spec))
      )
        throw packageError(
          "POLICY_DENIED",
          id,
          `the package lists ${name}@${JSON.stringify(spec)} in ${field}; only registry versions and semver ranges are resolved, never git, file, link, alias, tarball, or dist-tag specs`,
        );
    }
  }
}

/**
 * Host-provided packages Pi supplies to extensions (Pi `docs/packages.md`).
 * A package or any dependency that lists one in `dependencies`, or a closure
 * that would vendor one, is refused.
 */
export function isHostProvided(name: string): boolean {
  return name.startsWith("@earendil-works/pi-") || name === "typebox";
}

/**
 * Parse an http(s) source URL and return it canonical (no trailing slash).
 * A URL with userinfo, a query string, or a fragment is refused without
 * echoing it, so a credential never reaches an error message or the lock.
 */
export function canonicalSourceUrl(
  id: string,
  field: string,
  value: string,
  protocols: readonly string[] = ["https:", "http:"],
): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw packageError("CONFIG_INVALID", id, `${field} is not a URL`);
  }
  if (url.username || url.password)
    throw packageError(
      "POLICY_DENIED",
      id,
      `${field} carries credentials; credentials come only from npm or git configuration in the build environment`,
      "Remove the userinfo from the URL and configure the credential for npm or git instead",
    );
  if (url.search || value.includes("?"))
    throw packageError("POLICY_DENIED", id, `${field} has a query string`);
  if (url.hash || value.includes("#"))
    throw packageError("POLICY_DENIED", id, `${field} has a fragment`);
  if (!protocols.includes(url.protocol))
    throw packageError(
      "POLICY_DENIED",
      id,
      `${field} uses ${url.protocol.replace(/:$/, "")}; only ${protocols.map((item) => item.replace(/:$/, "")).join(" or ")} is accepted`,
    );
  return url.href.replace(/\/+$/, "");
}

/** The npm declaration: a real package name and a version that is never a tag or alias. */
export function checkNpmDeclaration(
  declaration: NpmPackage,
  mode: DeploymentMode,
): void {
  const { id, version } = declaration;
  if (!PACKAGE_NAME.test(declaration.package))
    throw packageError(
      "CONFIG_INVALID",
      id,
      `${JSON.stringify(declaration.package)} is not an npm package name`,
    );
  if (isHostProvided(declaration.package))
    throw packageError(
      "POLICY_DENIED",
      id,
      `${declaration.package} is provided by the Pi host and is never vendored`,
    );
  if (declaration.registry)
    canonicalSourceUrl(id, "registry", declaration.registry);
  if (/^(npm|file|link|workspace|git|github|gitlab|https?):/i.test(version))
    throw packageError(
      "POLICY_DENIED",
      id,
      `version ${JSON.stringify(version)} is an alias or a non-registry spec`,
    );
  if (isExactVersion(version)) return;
  if (mode === "managed")
    throw packageError(
      "POLICY_DENIED",
      id,
      `version ${JSON.stringify(version)} is not exact; a managed distribution pins every package`,
      "Declare the exact version, such as 1.4.2",
    );
  if (!isVersionRange(version))
    throw packageError(
      "POLICY_DENIED",
      id,
      `version ${JSON.stringify(version)} is a dist-tag or not a semver range`,
    );
}

/** The git declaration: an https repository on an allowed host and a pinnable ref. */
export function checkGitDeclaration(
  declaration: GitPackage,
  trust: PackageTrustConfig,
): string {
  const { id, repository, ref } = declaration;
  if (
    /^(github|gitlab|bitbucket|gist):/i.test(repository) ||
    /^git\+/i.test(repository) ||
    /^(ssh|git|file):/i.test(repository) ||
    /^[^/:@\s]+@[^/:\s]+:/.test(repository)
  )
    throw packageError(
      "POLICY_DENIED",
      id,
      "repository must be an https URL; shorthands, ssh, scp-form, git://, and file:// sources are refused",
    );
  const url = canonicalSourceUrl(id, "repository", repository, ["https:"]);
  const host = new URL(url).hostname;
  const hosts = trust.git?.hosts;
  if (hosts && !hosts.includes(host))
    throw packageError(
      "POLICY_DENIED",
      id,
      `git host ${host} is not in packageTrust.git.hosts (${hosts.join(", ") || "none"})`,
    );
  if (FULL_SHA.test(ref)) return url;
  if (ABBREVIATED_SHA.test(ref))
    throw packageError(
      "POLICY_DENIED",
      id,
      `ref ${ref} is an abbreviated commit SHA; declare the full 40-character SHA`,
    );
  if (trust.git?.requireCommitSha)
    throw packageError(
      "POLICY_DENIED",
      id,
      `ref ${JSON.stringify(ref)} is not a full commit SHA, which packageTrust.git.requireCommitSha requires`,
    );
  if (!ref.trim() || ref.startsWith("-") || /[\s:?*[\\^~]|\.\./.test(ref))
    throw packageError(
      "CONFIG_INVALID",
      id,
      `ref ${JSON.stringify(ref)} is not a git ref`,
    );
  return url;
}

function inside(root: string, path: string): boolean {
  return path === root || path.startsWith(`${root}${sep}`);
}

function confinedRelative(id: string, field: string, value: string): void {
  if (
    !value ||
    isAbsolute(value) ||
    value.includes("\\") ||
    /^[A-Za-z]:/.test(value) ||
    value.split("/").includes("..")
  )
    throw packageError(
      "POLICY_DENIED",
      id,
      `${field} ${JSON.stringify(value)} must be a relative path inside the distribution directory without ..`,
    );
}

/**
 * The local declaration: a relative path inside the distribution directory
 * and inside one of `packageTrust.local.paths` (when set), whose real path
 * does not leave either through a symlink. Returns the absolute package root.
 */
export function checkLocalDeclaration(
  declaration: LocalPackage,
  distributionDir: string,
  trust: PackageTrustConfig,
): string {
  const { id, path } = declaration;
  confinedRelative(id, "path", path);
  const base = realpathSync(distributionDir);
  const target = resolve(base, path);
  let real: string;
  try {
    real = realpathSync(target);
  } catch {
    throw packageError(
      "CONFIG_INVALID",
      id,
      `path ${path} does not exist in the distribution directory`,
    );
  }
  if (real !== target || !inside(base, real))
    throw packageError(
      "POLICY_DENIED",
      id,
      `path ${path} leaves the distribution directory through a symlink`,
    );
  if (!lstatSync(real).isDirectory())
    throw packageError("CONFIG_INVALID", id, `path ${path} is not a directory`);
  const allowed = trust.local?.paths;
  if (allowed) {
    const roots = allowed.map((entry) => {
      confinedRelative(id, "packageTrust.local.paths entry", entry);
      return resolve(base, entry);
    });
    if (!roots.some((root) => inside(root, real)))
      throw packageError(
        "POLICY_DENIED",
        id,
        `path ${path} is outside packageTrust.local.paths (${allowed.join(", ") || "none"})`,
      );
  }
  return real;
}

export interface NpmLockfile {
  readonly lockfileVersion?: unknown;
  readonly packages?: Record<string, NpmLockfileEntry>;
}

export interface NpmLockfileEntry {
  readonly name?: string;
  readonly version?: string;
  readonly resolved?: string;
  readonly integrity?: string;
  readonly link?: boolean;
  readonly dev?: boolean;
  readonly peer?: boolean;
  readonly optional?: boolean;
  readonly hasInstallScript?: boolean;
  readonly dependencies?: Record<string, string>;
  readonly optionalDependencies?: Record<string, string>;
  readonly os?: readonly string[];
  readonly cpu?: readonly string[];
}

function lockfileName(path: string): string {
  const index = path.lastIndexOf("node_modules/");
  return path.slice(index + "node_modules/".length);
}

/**
 * Apply §8.4 to every entry the per-package lockfile installs (peers are
 * never installed): exact versions, pinned https/http registry tarballs with
 * integrity, no aliases, links, git, or file sources, no URL with userinfo or
 * a query, and no host-provided Pi package as a dependency or a vendored copy.
 */
export function checkLockfileClosure(
  id: string,
  lockfile: NpmLockfile,
  trust: Pick<PackageTrustConfig, "npm">,
): PackageDependency[] {
  const packages = lockfile.packages;
  if (
    (lockfile.lockfileVersion !== 2 && lockfile.lockfileVersion !== 3) ||
    !packages ||
    typeof packages !== "object"
  )
    throw packageError(
      "LOCK_INVALID",
      id,
      "the package npm lockfile is not lockfileVersion 2 or 3",
    );
  const output: PackageDependency[] = [];
  for (const [path, entry] of Object.entries(packages).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  )) {
    for (const field of ["dependencies", "optionalDependencies"] as const)
      for (const name of Object.keys(entry[field] ?? {}))
        if (isHostProvided(name))
          throw packageError(
            "POLICY_DENIED",
            id,
            `${path || "the package"} lists host-provided ${name} in ${field}; declare it in peerDependencies instead`,
          );
    if (path === "") continue;
    if (entry.peer) continue;
    const label = path;
    if (!path.startsWith("node_modules/") || entry.link)
      throw packageError(
        "POLICY_DENIED",
        id,
        `${label} is a link, workspace, or file dependency`,
      );
    const name = lockfileName(path);
    if (entry.name && entry.name !== name)
      throw packageError(
        "POLICY_DENIED",
        id,
        `${label} is an npm: alias of ${entry.name}`,
      );
    if (isHostProvided(name))
      throw packageError(
        "POLICY_DENIED",
        id,
        `${label} would vendor host-provided ${name}`,
      );
    const version = entry.version ?? "";
    if (!isExactVersion(version))
      throw packageError(
        "POLICY_DENIED",
        id,
        `${label} resolves to ${JSON.stringify(version)}, not an exact version`,
      );
    if (!entry.resolved)
      throw packageError(
        "POLICY_DENIED",
        id,
        `${label}@${version} has no resolved source`,
      );
    if (/^(git\+|git:|ssh:|file:|github:|gitlab:)/i.test(entry.resolved))
      throw packageError(
        "POLICY_DENIED",
        id,
        `${label}@${version} is a git or file dependency; only registry tarballs are vendored`,
      );
    const resolved = canonicalSourceUrl(
      id,
      `${label} resolved`,
      entry.resolved,
    );
    if (!new URL(resolved).pathname.endsWith(".tgz"))
      throw packageError(
        "POLICY_DENIED",
        id,
        `${label}@${version} does not resolve to a pinned registry tarball`,
      );
    const integrity = entry.integrity ?? "";
    if (trust.npm?.requireIntegrity !== false && !SRI_SHA512.test(integrity))
      throw packageError(
        "INTEGRITY_FAILED",
        id,
        `${label}@${version} has no sha512 integrity, which packageTrust.npm.requireIntegrity requires`,
      );
    output.push({
      path,
      name,
      version,
      integrity,
      resolved,
      ...(entry.hasInstallScript ? { installScript: true as const } : {}),
      ...(entry.optional ? { optional: true as const } : {}),
    });
  }
  return output;
}

function accepts(list: readonly string[] | undefined, value: string): boolean {
  if (!list?.length) return true;
  const denied = list.filter((item) => item.startsWith("!"));
  if (denied.some((item) => item.slice(1) === value)) return false;
  const allowed = list.filter((item) => !item.startsWith("!"));
  return allowed.length === 0 || allowed.includes(value);
}

/**
 * Optional dependencies npm installs on `target` (`<platform>-<arch>`), as
 * `path@version`, from the lockfile's `os` / `cpu` fields.
 */
export function optionalDependenciesFor(
  lockfile: NpmLockfile,
  target: string,
): string[] {
  const [platform = "", arch = ""] = target.split("-");
  return Object.entries(lockfile.packages ?? {})
    .filter(
      ([path, entry]) =>
        path !== "" &&
        entry.optional &&
        !entry.peer &&
        accepts(entry.os, platform) &&
        accepts(entry.cpu, arch),
    )
    .map(([path, entry]) => `${path}@${entry.version ?? ""}`)
    .sort();
}
