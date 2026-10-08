// Pi packages (piship/v1alpha6): `resources.packages` and `packageTrust`.
// Parse level only: resolution, immutability of resolved results, and the
// release gates run when the lock is written.
import type { DeploymentMode } from "../access.js";
import {
  AGENT_FILE_MODES,
  DECLARABLE_RESOURCE_CLASSES,
  type DeclaredPackage,
  PACKAGE_RESOURCE_KINDS,
  PACKAGE_SOURCE_KINDS,
  type PackageAgentFile,
  type PackageEnvironmentValue,
  type PackageFilters,
  type PackageResourceKind,
  type PackageTrustConfig,
} from "../governance.js";
import {
  bool,
  conflict,
  envName,
  fail,
  isRecord,
  list,
  nonSecretValue,
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
  "environment",
  "agentFiles",
  "pretranspile",
  ...PACKAGE_RESOURCE_KINDS,
];
const SOURCE_FIELDS = {
  npm: ["package", "version", "registry"],
  git: ["repository", "ref"],
  local: ["path"],
} as const;

/**
 * A package's environment variable names: uppercase words joined by at least
 * one underscore (so never `PATH`, `HOME`, or `LANG`); `envName` also refuses
 * the credential-looking ones.
 */
const PACKAGE_ENVIRONMENT_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
/**
 * Names that PiShip, the process, or the network policy own. A package never
 * sets them: they change where Pi keeps its state, what PiShip itself reads,
 * how Node or the dynamic loader behaves, or which proxy and trust roots
 * every request uses.
 */
const RESERVED_ENVIRONMENT_NAME =
  /^(?:PISHIP_|PI_|NODE_|LD_|DYLD_|SSL_|CURL_|REQUESTS_|GIT_|SSH_|NPM_CONFIG_|PIP_|(?:HTTPS?|ALL|FTP|NO|SOCKS)_PROXY$|CARGO_HTTP_|DENO_CERT$|JAVA_TOOL_OPTIONS$|_JAVA_OPTIONS$|JDK_JAVA_OPTIONS$|ELECTRON_RUN_AS_NODE$|BASH_ENV$|ENV$|PROMPT_COMMAND$|XDG_.*_HOME$)/;
/** Names owned by known package code, tied to its declared npm identity. */
const PACKAGE_PI_PREFIXES: Readonly<Record<string, readonly string[]>> = {
  "pi-lens": ["PI_LENS_"],
  "pi-background-tasks": ["PI_BG_"],
};
const STATE_PATH_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const AGENT_FILE_PATH =
  /^extensions\/(?:[a-z0-9][a-z0-9._-]{0,63}\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json$/;
const MAX_AGENT_FILES = 8;
const MAX_AGENT_FILE_BYTES = 64 * 1024;

function environmentValue(
  value: unknown,
  path: string,
): PackageEnvironmentValue {
  if (typeof value === "number" || typeof value === "boolean")
    fail(path, "Environment values are strings; quote the value");
  if (!isRecord(value)) return nonSecretValue(value, path);
  const item = record(value, path, ["statePath"]);
  const text = plainString(item.statePath, `${path}.statePath`, 256);
  if (
    text.includes("\\") ||
    text.split("/").some((segment) => !STATE_PATH_SEGMENT.test(segment))
  )
    fail(
      `${path}.statePath`,
      "Expected a relative path of letters, digits, dots, hyphens, and underscores, without traversal",
    );
  return { statePath: text };
}

/** `environment`: variable names to non-secret values the launch sets. */
function parseEnvironment(
  value: unknown,
  path: string,
  npmPackage: unknown,
): Record<string, PackageEnvironmentValue> | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) fail(path, "Expected an object keyed by variable name");
  const output: Record<string, PackageEnvironmentValue> = {};
  for (const [name, entry] of Object.entries(value)) {
    const at = `${path}.${name}`;
    envName(name, at);
    if (!PACKAGE_ENVIRONMENT_NAME.test(name))
      fail(
        at,
        "Package variable names use uppercase words joined by underscores, such as PI_BG_FEATURES",
      );
    const packageOwned =
      typeof npmPackage === "string" &&
      (PACKAGE_PI_PREFIXES[npmPackage] ?? []).some((prefix) =>
        name.startsWith(prefix),
      );
    if (RESERVED_ENVIRONMENT_NAME.test(name) && !packageOwned)
      conflict(
        at,
        `${name} belongs to PiShip, the process, or the network policy; a package cannot set it`,
      );
    output[name] = environmentValue(entry, at);
  }
  if (!Object.keys(output).length)
    fail(path, "Declare at least one variable or omit the field");
  return output;
}

function agentFile(entry: unknown, path: string): PackageAgentFile {
  const item = record(entry, path, ["path", "mode", "json"]);
  const file = plainString(item.path, `${path}.path`, 256);
  if (!AGENT_FILE_PATH.test(file))
    fail(
      `${path}.path`,
      "Expected extensions/<file>.json or extensions/<name>/<file>.json, relative to Pi's agent directory",
    );
  if (!isRecord(item.json))
    fail(`${path}.json`, "Expected the JSON document as an object");
  if (JSON.stringify(item.json).length > MAX_AGENT_FILE_BYTES)
    fail(`${path}.json`, `Use at most ${MAX_AGENT_FILE_BYTES} bytes of JSON`);
  return {
    path: file,
    mode: oneOf(item.mode, `${path}.mode`, AGENT_FILE_MODES, "seed"),
    json: item.json,
  };
}

/** `agentFiles`: configuration files written into the agent directory. */
function parseAgentFiles(
  value: unknown,
  path: string,
): PackageAgentFile[] | undefined {
  if (value === undefined) return undefined;
  const files = list(value, path, agentFile, (item) => item.path);
  if (!files.length) fail(path, "Declare at least one file or omit the field");
  if (files.length > MAX_AGENT_FILES)
    fail(path, `Use at most ${MAX_AGENT_FILES} files`);
  return files;
}

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
  const environment = parseEnvironment(
    item.environment,
    `${path}.environment`,
    source === "npm" ? item.package : undefined,
  );
  const agentFiles = parseAgentFiles(item.agentFiles, `${path}.agentFiles`);
  const pretranspile = bool(item.pretranspile, `${path}.pretranspile`, false);
  const common = {
    id,
    class: cls,
    ...(certified ? { certified } : {}),
    filters: filters(item, path),
    ...(environment ? { environment } : {}),
    ...(agentFiles ? { agentFiles } : {}),
    ...(pretranspile ? { pretranspile: true as const } : {}),
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

/**
 * `resources.packages`: a list of packages with unique IDs. The environment
 * is one process's, and the files one directory's: two packages may share a
 * variable only at the same value, and no two may write the same file.
 */
export function parsePackages(value: unknown): DeclaredPackage[] {
  const packages = list(
    value,
    "resources.packages",
    parsePackage,
    (item) => item.id,
  );
  const variables = new Map<string, { value: string; owner: string }>();
  const files = new Map<string, string>();
  for (const [index, item] of packages.entries()) {
    const at = `resources.packages[${index}]`;
    for (const [name, declared] of Object.entries(item.environment ?? {})) {
      const text = JSON.stringify(declared);
      const earlier = variables.get(name);
      if (earlier && earlier.value !== text)
        conflict(
          `${at}.environment.${name}`,
          `${name} is already set to another value by package ${earlier.owner}`,
        );
      variables.set(name, { value: text, owner: item.id });
    }
    for (const file of item.agentFiles ?? []) {
      const earlier = files.get(file.path);
      if (earlier)
        conflict(
          `${at}.agentFiles`,
          `${file.path} is already written by package ${earlier}`,
        );
      files.set(file.path, item.id);
    }
  }
  return packages;
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
