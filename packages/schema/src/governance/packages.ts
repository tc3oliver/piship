// Pi packages (piship/v1alpha6): `resources.packages` and `packageTrust`.
// Parse level only: resolution, immutability of resolved results, and the
// release gates run when the lock is written.
import type { DeploymentMode } from "../access.js";
import {
  DECLARABLE_RESOURCE_CLASSES,
  type DeclaredPackage,
  PACKAGE_RESOURCE_KINDS,
  PACKAGE_SOURCE_KINDS,
  type PackageFilters,
  type PackageResourceKind,
  type PackageTrustConfig,
} from "../governance.js";
import {
  bool,
  fail,
  isRecord,
  list,
  oneOf,
  optionalRecord,
  plainString,
  record,
  relativePath,
  semver,
} from "./fields.js";
import { CERTIFIED_FIELDS, evidence } from "./resources.js";

const PACKAGE_ID = /^[a-z][a-z0-9-]{0,63}$/;
/** npm's package name rules: lowercase, URL-safe, optionally scoped. */
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const HOST =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * An https URL without credentials, query, or fragment: a credential or a
 * token in a URL would end up in the manifest and the lock.
 */
function httpsUrl(value: unknown, path: string): string {
  const text = plainString(value, path, 2048);
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    fail(path, "Expected an https URL");
  }
  if (url.protocol !== "https:") fail(path, "Expected an https URL");
  if (url.username || url.password)
    fail(path, "URLs must not embed credentials");
  if (url.search || url.hash || text.includes("?") || text.includes("#"))
    fail(path, "URLs must not carry a query or fragment");
  return text;
}

function filterPattern(value: unknown, path: string): string {
  return plainString(value, path, 256);
}

function filters(item: Record<string, unknown>, path: string): PackageFilters {
  const output: Partial<Record<PackageResourceKind, readonly string[]>> = {};
  for (const kind of PACKAGE_RESOURCE_KINDS) {
    if (item[kind] === undefined) continue;
    output[kind] = list(item[kind], `${path}.${kind}`, filterPattern);
  }
  return output;
}

const COMMON = [
  "id",
  "source",
  "class",
  "certified",
  ...PACKAGE_RESOURCE_KINDS,
];
const SOURCE_FIELDS = {
  npm: ["package", "version", "registry"],
  git: ["repository", "ref"],
  local: ["path"],
} as const;

function parsePackage(entry: unknown, path: string): DeclaredPackage {
  if (!isRecord(entry)) fail(path, "Expected an object");
  const source = oneOf(entry.source, `${path}.source`, PACKAGE_SOURCE_KINDS);
  const item = record(entry, path, [...COMMON, ...SOURCE_FIELDS[source]]);
  const id = plainString(item.id, `${path}.id`, 64);
  if (!PACKAGE_ID.test(id))
    fail(
      `${path}.id`,
      "Package IDs use lowercase letters, digits, and hyphens (at most 64); start with a letter",
    );
  const cls = oneOf(item.class, `${path}.class`, DECLARABLE_RESOURCE_CLASSES);
  if (cls === "certified" && item.certified === undefined)
    fail(
      `${path}.certified`,
      "A certified package carries review evidence: version, source, integrity, license, pi, platforms",
    );
  if (cls !== "certified" && item.certified !== undefined)
    fail(`${path}.certified`, "Review evidence applies to certified packages");
  const certified =
    item.certified === undefined
      ? undefined
      : (() => {
          const at = `${path}.certified`;
          const fields = record(item.certified, at, [
            "version",
            ...CERTIFIED_FIELDS,
          ]);
          return evidence(
            fields,
            at,
            id,
            semver(fields.version, `${at}.version`),
          );
        })();
  const common = {
    id,
    class: cls,
    ...(certified ? { certified } : {}),
    filters: filters(item, path),
  };
  switch (source) {
    case "npm": {
      const name = plainString(item.package, `${path}.package`, 214);
      if (!NPM_NAME.test(name))
        fail(`${path}.package`, "Expected an npm package name");
      return {
        ...common,
        source,
        package: name,
        version: plainString(item.version, `${path}.version`, 128),
        ...(item.registry === undefined
          ? {}
          : { registry: httpsUrl(item.registry, `${path}.registry`) }),
      };
    }
    case "git":
      return {
        ...common,
        source,
        repository: httpsUrl(item.repository, `${path}.repository`),
        ref: plainString(item.ref, `${path}.ref`, 256),
      };
    default:
      return {
        ...common,
        source,
        path: relativePath(item.path, `${path}.path`),
      };
  }
}

/** `resources.packages`: a list of packages with unique IDs. */
export function parsePackages(value: unknown): DeclaredPackage[] {
  return list(value, "resources.packages", parsePackage, (item) => item.id);
}

/**
 * `packageTrust`. Managed defaults require npm integrity and full commit
 * SHAs and admit no local package path; personal defaults require npm
 * integrity only.
 */
export function parsePackageTrust(
  value: unknown,
  mode: DeploymentMode,
): PackageTrustConfig {
  const managed = mode === "managed";
  const trust = optionalRecord(value, "packageTrust", ["npm", "git", "local"]);
  const npm = optionalRecord(trust.npm, "packageTrust.npm", [
    "requireIntegrity",
  ]);
  const git = optionalRecord(trust.git, "packageTrust.git", [
    "hosts",
    "requireCommitSha",
  ]);
  const local = optionalRecord(trust.local, "packageTrust.local", ["paths"]);
  return {
    npm: {
      requireIntegrity: bool(
        npm.requireIntegrity,
        "packageTrust.npm.requireIntegrity",
        true,
      ),
    },
    git: {
      ...(git.hosts === undefined
        ? {}
        : {
            hosts: list(git.hosts, "packageTrust.git.hosts", (entry, at) => {
              const host = plainString(entry, at, 253);
              if (!HOST.test(host))
                fail(
                  at,
                  "Expected a lowercase host name without scheme or port",
                );
              return host;
            }),
          }),
      requireCommitSha: bool(
        git.requireCommitSha,
        "packageTrust.git.requireCommitSha",
        managed,
      ),
    },
    local:
      local.paths === undefined
        ? managed
          ? { paths: [] }
          : {}
        : {
            paths: list(local.paths, "packageTrust.local.paths", relativePath),
          },
  };
}
