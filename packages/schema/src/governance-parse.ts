// Parser for the piship/v1alpha3 governance sections: trust-classed
// resources, capabilities, policy, MCP, sandbox, and audit. Every field is
// validated strictly; unknown and secret-looking fields are rejected.
import {
  type AuditCapture,
  POLICY_ACTIONS,
  type PolicyEffect,
} from "@piship/contracts";
import { valid as validSemver } from "semver";
import {
  AccessFieldError,
  checkUrl,
  type DeploymentMode,
  parseDuration,
} from "./access.js";
import {
  type AuditConfig,
  type AuditSinkConfig,
  BUILTIN_EXTENSIONS,
  BUILTIN_PROVIDERS,
  type BuiltinExtension,
  CAPABILITY_CONTRACTS,
  type CapabilityConfig,
  type CapabilityModelRequirements,
  type CapabilityName,
  type CapabilityProviderRef,
  type CertifiedEvidence,
  DECLARABLE_RESOURCE_CLASSES,
  type DeclarableResourceClass,
  type DeclaredResource,
  type GovernanceManifest,
  type GovernanceResources,
  type McpConfig,
  type McpServerConfig,
  type PolicyConfig,
  type PolicyRule,
  PROJECT_TRUST_DIMENSIONS,
  type ProjectDimensionEffect,
  type ProjectDimensions,
  type ProjectMatcher,
  type ProjectResourceTrust,
  type ProjectTrustPolicy,
  PROVIDER_TRUST_CLASSES,
  type ProviderTrustClass,
  RESOURCE_KINDS,
  type ResourceKind,
  type SandboxConfig,
  type TrustSetting,
} from "./governance.js";
import {
  checkTemplate,
  checkVariableName,
  hasRuntimeReference,
  referencedVariables,
} from "./variables.js";

/** Top-level manifest sections added by piship/v1alpha3. */
export const GOVERNANCE_KEYS = [
  "capabilities",
  "policy",
  "mcp",
  "sandbox",
  "audit",
] as const;

/** Version reported for PiShip builtin capability providers. */
export const BUILTIN_PROVIDER_VERSION = "1.0.0";

/** Governance fields that accept `${NAME}` runtime references. */
export const GOVERNANCE_RUNTIME_REFERENCE_FIELDS = [
  "mcp.servers.<id>.url",
  "audit.sinks[<index>].url",
] as const;

export const DEFAULT_SANDBOX_READ_DENY = [
  "~/.ssh",
  "~/.aws",
  "~/.gnupg",
  "~/.config/gcloud",
  "~/.azure",
  "~/.kube",
  "~/.docker",
  "~/.netrc",
  "~/.npmrc",
  "~/.pi",
] as const;
export const DEFAULT_SANDBOX_WRITE_ALLOW = ["workspace", "tmp"] as const;
export const DEFAULT_SANDBOX_ENVIRONMENT = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TERM",
  "TZ",
  "SHELL",
  "TMPDIR",
] as const;

type Json = Record<string, unknown>;

// ----------------------------------------------------------------- helpers

function fail(field: string, message: string): never {
  throw new AccessFieldError("invalid field", field, message);
}
function unsafe(field: string, message: string): never {
  throw new AccessFieldError("unsafe path/name", field, message);
}
function conflict(field: string, message: string): never {
  throw new AccessFieldError("conflict", field, message);
}
function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** Field names that indicate secret material; never valid manifest keys. */
const SECRET_FIELD =
  /(secret|token|password|passwd|api_?key|private_?key|client_?key|bearer|authorization|cookie)/i;
function record(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Json {
  if (!isRecord(value)) fail(path, "Expected an object");
  for (const key of Object.keys(value))
    if (!allowed.includes(key)) {
      if (SECRET_FIELD.test(key))
        fail(`${path}.${key}`, "Secrets are never declared in piship.yaml");
      fail(`${path}.${key}`, "Unknown field");
    }
  return value;
}
function optionalRecord(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Json {
  return value === undefined ? {} : record(value, path, allowed);
}
function hasControl(value: string, allowNewlines = false): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    if (allowNewlines && (code === 10 || code === 9)) return false;
    return code < 32 || code === 127;
  });
}
function plainString(value: unknown, path: string, max = 256): string {
  if (typeof value !== "string" || value.trim() === "")
    fail(path, "Expected a non-empty string");
  if (hasRuntimeReference(value))
    fail(path, "Runtime references are not allowed in this field");
  if (hasControl(value)) fail(path, "Control characters are not allowed");
  if (value.length > max) fail(path, `Use at most ${max} characters`);
  return value;
}
function bool(value: unknown, path: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") fail(path, "Expected true or false");
  return value;
}
function positiveInteger(
  value: unknown,
  path: string,
  fallback: number,
  max: number,
): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0)
    fail(path, "Expected a positive integer");
  if (value > max) fail(path, `Expected at most ${max}`);
  return value;
}
function durationMs(value: unknown, path: string, fallback: string): number {
  const seconds = parseDuration(value ?? fallback, path);
  if (seconds <= 0) fail(path, "Expected a duration greater than zero");
  return seconds * 1000;
}
function list<T>(
  value: unknown,
  path: string,
  item: (entry: unknown, path: string) => T,
  key: (entry: T) => string = String,
): T[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) fail(path, "Expected a list");
  const output = value.map((entry, index) => item(entry, `${path}[${index}]`));
  const seen = new Set<string>();
  for (const [index, entry] of output.entries()) {
    const id = key(entry);
    if (seen.has(id))
      fail(`${path}[${index}]`, `Duplicate entry ${JSON.stringify(id)}`);
    seen.add(id);
  }
  return output;
}
function oneOf<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
  fallback?: T,
): T {
  if (value === undefined && fallback !== undefined) return fallback;
  if (
    typeof value !== "string" ||
    !(allowed as readonly string[]).includes(value)
  )
    fail(path, `Expected ${allowed.join(", ")}`);
  return value as T;
}
/** A `./` path inside the distribution repository, without traversal. */
function relativePath(value: unknown, path: string): string {
  const item = plainString(value, path, 1024);
  const segments = item.slice(2).split("/");
  if (
    !item.startsWith("./") ||
    item.includes("\\") ||
    segments.some((segment) => !segment || segment === "." || segment === "..")
  )
    unsafe(path, "Use a ./ relative path without traversal");
  return item;
}
function modulePath(value: unknown, path: string): string {
  const item = relativePath(value, path);
  if (!/\.(?:mjs|js)$/.test(item))
    fail(path, "Modules must be ECMAScript modules ending in .mjs or .js");
  return item;
}
function referenceUrl(
  value: unknown,
  path: string,
  variables: readonly string[],
): string {
  if (typeof value !== "string" || value.trim() === "")
    fail(path, "Expected a non-empty string");
  if (hasRuntimeReference(value) || value.includes("$")) {
    const problem = checkTemplate(value, variables);
    if (problem) fail(path, problem.message);
    return value;
  }
  const text = plainString(value, path, 2048);
  checkUrl(text, path);
  return text;
}
const SEMVER_PATTERN = /^[0-9]/;
function semver(value: unknown, path: string): string {
  const text = plainString(value, path, 128);
  if (!SEMVER_PATTERN.test(text) || validSemver(text) === null)
    fail(path, "Expected a SemVer version such as 1.2.0");
  return text;
}
function exactPiVersion(value: unknown, path: string): string {
  const text = plainString(value, path, 64);
  if (!/^\d+\.\d+\.\d+$/.test(text))
    fail(path, "Expected an exact Pi version such as 0.87.1");
  return text;
}
function envName(value: unknown, path: string): string {
  const name = plainString(value, path, 64);
  const problem = checkVariableName(name);
  if (problem)
    fail(
      path,
      problem.message.replace(/^Runtime variable/, "Environment variable"),
    );
  if (CREDENTIAL_VARIABLE.test(name))
    fail(
      path,
      `Environment variable ${name} looks like a credential; long-lived credentials are never passed to child processes`,
    );
  return name;
}
const CREDENTIAL_VARIABLE =
  /(?:^|_)(?:API_?KEY|ACCESS_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|AUTH|PAT)(?:_|$)/;
/** Common secret value shapes; a static manifest never carries these. */
const SECRET_VALUE = [
  /^(?:bearer|basic)\s/i,
  /\bsk-[A-Za-z0-9_-]{6,}/,
  /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\./,
  /\b(?:ghp|gho|ghs|ghu|github_pat|glpat|xox[abpsr])[-_][A-Za-z0-9_-]{8,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];
function nonSecretValue(value: unknown, path: string): string {
  const text = plainString(value, path, 1024);
  if (SECRET_VALUE.some((pattern) => pattern.test(text)))
    fail(
      path,
      "Value looks like secret material; secrets are never declared in piship.yaml",
    );
  return text;
}

// --------------------------------------------------------------- resources

const CERTIFIED_FIELDS = [
  "source",
  "integrity",
  "license",
  "pi",
  "platforms",
] as const;
const PLATFORMS = ["linux", "darwin", "win32"] as const;
const EVIDENCE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;

function evidence(
  item: Json,
  path: string,
  id: string,
  version: string,
): CertifiedEvidence {
  const source = plainString(item.source, `${path}.source`, 1024);
  if (source.includes("://")) checkUrl(source, `${path}.source`);
  const integrity = plainString(item.integrity, `${path}.integrity`, 128);
  if (!/^sha256-[0-9a-f]{64}$/.test(integrity))
    fail(
      `${path}.integrity`,
      "Expected sha256- followed by 64 lowercase hexadecimal characters",
    );
  const license = plainString(item.license, `${path}.license`, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9.+() -]*$/.test(license))
    fail(`${path}.license`, "Expected an SPDX license expression");
  const pi = list(item.pi, `${path}.pi`, exactPiVersion);
  if (!pi.length)
    fail(
      `${path}.pi`,
      "List the exact Pi versions the item was reviewed against",
    );
  const platforms = list(item.platforms, `${path}.platforms`, (entry, at) =>
    oneOf(entry, at, PLATFORMS),
  );
  return { id, version, source, integrity, license, pi, platforms };
}

function certifiedResource(entry: unknown, path: string, kind: ResourceKind) {
  const item = record(entry, path, [
    "path",
    "id",
    "version",
    ...CERTIFIED_FIELDS,
  ]);
  const id = plainString(item.id, `${path}.id`, 128);
  if (!EVIDENCE_ID.test(id))
    fail(`${path}.id`, "IDs use lowercase letters, digits, and . _ -");
  const resource: DeclaredResource = {
    kind,
    class: "certified",
    path: relativePath(item.path, `${path}.path`),
    certified: evidence(
      item,
      path,
      id,
      semver(item.version, `${path}.version`),
    ),
  };
  return resource;
}

function parseKind(
  kind: ResourceKind,
  value: unknown,
): { declared: DeclaredResource[]; builtin: BuiltinExtension[] } {
  const path = `resources.${kind}`;
  if (Array.isArray(value))
    fail(
      path,
      "piship/v1alpha3 and piship/v1alpha4 resources map a trust class (certified, company, user) to entries; run piship migrate to convert a flat list",
    );
  if (!isRecord(value)) fail(path, "Expected an object");
  for (const key of ["upstream", "project"])
    if (value[key] !== undefined)
      fail(
        `${path}.${key}`,
        key === "upstream"
          ? "upstream resources come from the pinned Pi package and cannot be declared"
          : "project resources are discovered in the workspace and governed by policy.projectTrust; they cannot be declared",
      );
  if (value.builtin !== undefined && kind !== "extensions")
    fail(
      `${path}.builtin`,
      "builtin entries are only valid under resources.extensions",
    );
  const section = record(value, path, [
    ...(kind === "extensions" ? ["builtin"] : []),
    ...DECLARABLE_RESOURCE_CLASSES,
  ]);
  const builtin = list(section.builtin, `${path}.builtin`, (entry, at) => {
    const name = plainString(entry, at, 64);
    if (!(BUILTIN_EXTENSIONS as readonly string[]).includes(name))
      fail(
        at,
        `Expected a builtin extension: ${BUILTIN_EXTENSIONS.join(", ")}`,
      );
    return name as BuiltinExtension;
  });
  const declared: DeclaredResource[] = [];
  const classes: DeclarableResourceClass[] = ["certified", "company", "user"];
  for (const trust of classes) {
    const at = `${path}.${trust}`;
    const entries =
      trust === "certified"
        ? list(
            section.certified,
            at,
            (entry, entryPath) => certifiedResource(entry, entryPath, kind),
            (entry) => entry.path,
          )
        : list(section[trust], at, relativePath).map(
            (item): DeclaredResource => ({ kind, class: trust, path: item }),
          );
    for (const [index, entry] of entries.entries()) {
      const entryPath =
        trust === "certified" ? `${at}[${index}].path` : `${at}[${index}]`;
      for (const other of declared) {
        if (other.path === entry.path)
          conflict(
            entryPath,
            `${entry.path} is already declared as ${other.class}; a path has exactly one trust class`,
          );
        if (
          entry.path.startsWith(`${other.path}/`) ||
          other.path.startsWith(`${entry.path}/`)
        )
          conflict(
            entryPath,
            `${entry.path} overlaps ${other.path} (${other.class}); nested roots cannot mix trust classes`,
          );
      }
      declared.push(entry);
    }
  }
  return { declared, builtin };
}

export function parseGovernanceResources(value: unknown): GovernanceResources {
  const resources = optionalRecord(
    value ?? undefined,
    "resources",
    RESOURCE_KINDS,
  );
  const declared: DeclaredResource[] = [];
  const builtin: BuiltinExtension[] = [];
  for (const kind of RESOURCE_KINDS) {
    if (resources[kind] === undefined || resources[kind] === null) continue;
    const parsed = parseKind(kind, resources[kind]);
    declared.push(...parsed.declared);
    builtin.push(...parsed.builtin);
  }
  return { declared, builtin };
}

// ------------------------------------------------------------ capabilities

const CAPABILITY_NAMES = Object.keys(CAPABILITY_CONTRACTS) as CapabilityName[];
const CONTRACT_ID =
  /^piship\.capability\/([a-z][a-z0-9-]*)\/v([1-9][0-9]{0,3})$/;
const PROVIDER_NAME = /^[a-z][a-z0-9-]{0,63}$/;

function contractName(contract: string): string {
  return contract.replace(/\/v[0-9]+$/, "");
}

function parseProvider(
  value: unknown,
  path: string,
  capability: CapabilityName,
): CapabilityProviderRef {
  if (!isRecord(value)) fail(path, "Expected an object");
  const id = plainString(value.id, `${path}.id`, 128);
  const [trust, name, ...rest] = id.split("/");
  if (
    rest.length ||
    trust === undefined ||
    name === undefined ||
    !(PROVIDER_TRUST_CLASSES as readonly string[]).includes(trust) ||
    !PROVIDER_NAME.test(name)
  )
    fail(
      `${path}.id`,
      `Expected <class>/<name> with class ${PROVIDER_TRUST_CLASSES.join(", ")} and a lowercase name`,
    );
  const providerClass = trust as ProviderTrustClass;
  const contract = CAPABILITY_CONTRACTS[capability];
  if (providerClass === "upstream")
    fail(`${path}.id`, "Pi ships no upstream capability providers");
  if (providerClass === "builtin") {
    for (const key of Object.keys(value))
      if (key !== "id")
        fail(
          `${path}.${key}`,
          SECRET_FIELD.test(key)
            ? "Secrets are never declared in piship.yaml"
            : "Builtin providers are defined by PiShip; declare only id",
        );
    const implemented = BUILTIN_PROVIDERS[id];
    if (!implemented)
      fail(
        `${path}.id`,
        `Unknown builtin provider; expected one of ${Object.keys(BUILTIN_PROVIDERS).join(", ")}`,
      );
    if (!implemented.includes(contract))
      conflict(`${path}.id`, `${id} does not implement ${contract}`);
    return {
      id,
      class: providerClass,
      version: BUILTIN_PROVIDER_VERSION,
      implements: [...implemented],
    };
  }
  const certified = providerClass === "certified";
  const item = record(value, path, [
    "id",
    "version",
    "implements",
    "path",
    ...(certified ? CERTIFIED_FIELDS : []),
  ]);
  const version = semver(item.version, `${path}.version`);
  if (item.implements === undefined)
    fail(
      `${path}.implements`,
      "List the capability contracts the provider implements",
    );
  const implemented = list(
    item.implements,
    `${path}.implements`,
    (entry, at) => {
      const text = plainString(entry, at, 128);
      if (!CONTRACT_ID.test(text))
        fail(
          at,
          "Expected a contract ID such as piship.capability/permissions/v1",
        );
      return text;
    },
  );
  if (
    !implemented.some((entry) => contractName(entry) === contractName(contract))
  )
    conflict(
      `${path}.implements`,
      `A ${capability} provider must implement ${contractName(contract)}/v<major>`,
    );
  if (item.path === undefined)
    fail(
      `${path}.path`,
      "Non-builtin providers need a ./ path to their extension",
    );
  return {
    id,
    class: providerClass,
    version,
    implements: implemented,
    path: relativePath(item.path, `${path}.path`),
    ...(certified ? { certified: evidence(item, path, id, version) } : {}),
  };
}

function parseSettings(value: unknown, path: string): Record<string, string> {
  if (value === undefined) return {};
  if (!isRecord(value)) fail(path, "Expected an object");
  const output: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    const at = `${path}.${key}`;
    if (!/^[a-z][A-Za-z0-9]{0,63}$/.test(key))
      fail(at, "Setting names use lowerCamelCase letters and digits");
    if (SECRET_FIELD.test(key))
      fail(at, "Secrets are never declared in piship.yaml");
    if (typeof entry !== "string" || entry.trim() === "")
      fail(at, "Expected a non-empty string");
    if (hasRuntimeReference(entry))
      fail(at, "Runtime references are not allowed in this field");
    if (hasControl(entry, true)) fail(at, "Control characters are not allowed");
    if (entry.length > 8192) fail(at, "Use at most 8192 characters");
    output[key] = entry;
  }
  return output;
}

const MODEL_INPUTS = ["text", "image"] as const;

function parseRequirements(
  value: unknown,
  path: string,
): CapabilityModelRequirements | undefined {
  if (value === undefined) return undefined;
  const item = record(value, path, [
    "tools",
    "structuredOutput",
    "minContextWindow",
    "input",
  ]);
  if (!Object.keys(item).length)
    fail(path, "Declare at least one model requirement or omit the field");
  const input =
    item.input === undefined
      ? undefined
      : list(item.input, `${path}.input`, (entry, at) =>
          oneOf(entry, at, MODEL_INPUTS),
        );
  if (input && !input.length)
    fail(`${path}.input`, "Expected at least one input modality");
  return {
    ...(item.tools === undefined
      ? {}
      : { tools: bool(item.tools, `${path}.tools`, false) }),
    ...(item.structuredOutput === undefined
      ? {}
      : {
          structuredOutput: bool(
            item.structuredOutput,
            `${path}.structuredOutput`,
            false,
          ),
        }),
    ...(item.minContextWindow === undefined
      ? {}
      : {
          minContextWindow: positiveInteger(
            item.minContextWindow,
            `${path}.minContextWindow`,
            1,
            100_000_000,
          ),
        }),
    ...(input ? { input } : {}),
  };
}

export function parseCapabilities(value: unknown): CapabilityConfig[] {
  const capabilities = optionalRecord(value, "capabilities", CAPABILITY_NAMES);
  return CAPABILITY_NAMES.map((name): CapabilityConfig => {
    const path = `capabilities.${name}`;
    const source = capabilities[name];
    if (source === undefined) {
      if (name === "permissions")
        return {
          name,
          enabled: true,
          provider: parseProvider({ id: "builtin/permissions" }, path, name),
          settings: {},
        };
      return { name, enabled: false, settings: {} };
    }
    const item = record(source, path, [
      "enabled",
      "provider",
      "settings",
      "requirements",
    ]);
    if (typeof item.enabled !== "boolean")
      fail(`${path}.enabled`, "Expected true or false");
    let provider: CapabilityProviderRef | undefined;
    if (item.provider !== undefined)
      provider = parseProvider(item.provider, `${path}.provider`, name);
    else if (item.enabled) {
      const builtin = Object.keys(BUILTIN_PROVIDERS).find((id) =>
        BUILTIN_PROVIDERS[id]?.includes(CAPABILITY_CONTRACTS[name]),
      );
      if (!builtin)
        fail(
          `${path}.provider`,
          `No builtin provider implements ${CAPABILITY_CONTRACTS[name]}; declare a provider`,
        );
      provider = parseProvider({ id: builtin }, `${path}.provider`, name);
    }
    const requirements = parseRequirements(
      item.requirements,
      `${path}.requirements`,
    );
    return {
      name,
      enabled: item.enabled,
      ...(provider ? { provider } : {}),
      settings: parseSettings(item.settings, `${path}.settings`),
      ...(requirements ? { requirements } : {}),
    };
  });
}

// ------------------------------------------------------------------ policy

const EFFECTS: readonly PolicyEffect[] = ["allow", "ask", "deny"];
const TRUST: readonly TrustSetting[] = ["allow", "deny"];
const RULE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const ACTION_PREFIXES = new Set(
  POLICY_ACTIONS.flatMap((action) => {
    const parts = action.split(".");
    return parts
      .slice(1)
      .map((_part, index) => parts.slice(0, index + 1).join("."));
  }),
);

function ruleAction(value: unknown, path: string): PolicyRule["action"] {
  const action = plainString(value, path, 128);
  if (action === "*") return action;
  if ((POLICY_ACTIONS as readonly string[]).includes(action))
    return action as PolicyRule["action"];
  if (action.endsWith(".*") && ACTION_PREFIXES.has(action.slice(0, -2)))
    return action as PolicyRule["action"];
  fail(
    path,
    `Expected a policy action (${POLICY_ACTIONS.join(", ")}), a known <prefix>.*, or *`,
  );
}

function resourceGlob(value: unknown, path: string): string {
  if (value === undefined) return "**";
  return plainString(value, path, 1024);
}

function parseRule(entry: unknown, path: string): PolicyRule {
  const rule = record(entry, path, [
    "id",
    "action",
    "resource",
    "effect",
    "reason",
  ]);
  const id = plainString(rule.id, `${path}.id`, 128);
  if (!RULE_ID.test(id))
    fail(
      `${path}.id`,
      "Rule IDs use lowercase letters, digits, and . _ - (at most 128)",
    );
  return {
    id,
    action: ruleAction(rule.action, `${path}.action`),
    resource: resourceGlob(rule.resource, `${path}.resource`),
    effect: oneOf(rule.effect, `${path}.effect`, EFFECTS),
    ...(rule.reason === undefined
      ? {}
      : { reason: plainString(rule.reason, `${path}.reason`, 240) }),
  };
}

type Dimensions = Record<
  (typeof PROJECT_TRUST_DIMENSIONS)[number],
  ProjectDimensionEffect
>;
function dimensions(
  base: ProjectDimensionEffect,
  overrides: Partial<Dimensions>,
): Dimensions {
  const output = {} as Dimensions;
  for (const dimension of PROJECT_TRUST_DIMENSIONS)
    output[dimension] = overrides[dimension] ?? base;
  return output;
}

export function defaultProjectDimensions(
  mode: DeploymentMode,
): Record<"company" | "external" | "unknown", ProjectDimensions> {
  if (mode === "managed")
    return {
      company: dimensions("deny", {
        passiveContext: "allow",
        instructions: "allow",
        skills: "allow",
        extensions: "company-approved",
        mcp: "company-approved",
      }),
      external: dimensions("deny", {
        passiveContext: "allow",
        instructions: "ask",
      }),
      unknown: dimensions("deny", { passiveContext: "allow" }),
    };
  return {
    company: dimensions("allow", { hooks: "deny" }),
    external: dimensions("allow", { hooks: "deny" }),
    unknown: dimensions("ask", { passiveContext: "allow", hooks: "deny" }),
  };
}

const DIMENSION_EFFECTS: readonly ProjectDimensionEffect[] = [
  "allow",
  "ask",
  "deny",
  "company-approved",
];

function matcher(entry: unknown, path: string): ProjectMatcher {
  const item = record(entry, path, ["remote", "path"]);
  if (item.remote === undefined && item.path === undefined)
    fail(path, "A matcher declares remote, path, or both");
  let remote: string | undefined;
  if (item.remote !== undefined) {
    remote = plainString(item.remote, `${path}.remote`, 512);
    if (
      remote.includes("://") ||
      remote.includes("@") ||
      /\s/.test(remote) ||
      remote.endsWith(".git") ||
      remote.startsWith("/")
    )
      fail(
        `${path}.remote`,
        "Use a normalized host/path glob without scheme, credentials, or .git suffix",
      );
  }
  if (item.path === undefined) return { remote: remote as string };
  const glob = plainString(item.path, `${path}.path`, 1024);
  if (
    !(glob.startsWith("/") || /^[A-Za-z]:\//.test(glob)) ||
    glob.includes("\\") ||
    glob.split("/").some((segment) => segment === "." || segment === "..")
  )
    unsafe(
      `${path}.path`,
      "Use an absolute POSIX-style path glob without . or .. segments",
    );
  // With both, the project must match both (the remote alone is a claim).
  return remote === undefined ? { path: glob } : { remote, path: glob };
}

function projectClass(
  value: unknown,
  path: string,
  defaults: ProjectDimensions,
  withMatch: boolean,
): { match: ProjectMatcher[]; dimensions: ProjectDimensions } {
  const item = optionalRecord(value, path, [
    ...(withMatch ? ["match"] : []),
    ...PROJECT_TRUST_DIMENSIONS,
  ]);
  const output = {} as Dimensions;
  for (const dimension of PROJECT_TRUST_DIMENSIONS)
    output[dimension] = oneOf(
      item[dimension],
      `${path}.${dimension}`,
      DIMENSION_EFFECTS,
      defaults[dimension],
    );
  return {
    match: withMatch
      ? list(item.match, `${path}.match`, matcher, (entry) =>
          JSON.stringify(entry),
        )
      : [],
    dimensions: output,
  };
}

function parseProjectTrust(
  value: unknown,
  mode: DeploymentMode,
): ProjectTrustPolicy {
  const trust = optionalRecord(value, "policy.projectTrust", [
    "company",
    "external",
    "unknown",
  ]);
  const defaults = defaultProjectDimensions(mode);
  const company = projectClass(
    trust.company,
    "policy.projectTrust.company",
    defaults.company,
    true,
  );
  const external = projectClass(
    trust.external,
    "policy.projectTrust.external",
    defaults.external,
    true,
  );
  const unknown = projectClass(
    trust.unknown,
    "policy.projectTrust.unknown",
    defaults.unknown,
    false,
  );
  return { company, external, unknown: { dimensions: unknown.dimensions } };
}

export function parsePolicy(
  value: unknown,
  mode: DeploymentMode,
  app: { readonly id: string },
): PolicyConfig {
  const policy = optionalRecord(value, "policy", [
    "id",
    "version",
    "default",
    "adapter",
    "resourceTrust",
    "providerTrust",
    "projectTrust",
    "enforced",
    "defaults",
  ]);
  const id =
    policy.id === undefined ? app.id : plainString(policy.id, "policy.id", 128);
  if (!RULE_ID.test(id))
    fail("policy.id", "Policy IDs use lowercase letters, digits, and . _ -");
  const managed = mode === "managed";
  const resourceTrust = optionalRecord(
    policy.resourceTrust,
    "policy.resourceTrust",
    ["upstream", "builtin", "certified", "company", "user", "project"],
  );
  const providerTrust = optionalRecord(
    policy.providerTrust,
    "policy.providerTrust",
    PROVIDER_TRUST_CLASSES,
  );
  const trustOf = (
    section: Json,
    key: string,
    at: string,
    fallback: TrustSetting,
  ) => oneOf(section[key], `${at}.${key}`, TRUST, fallback);
  const enforced = list(
    policy.enforced,
    "policy.enforced",
    parseRule,
    (rule) => rule.id,
  );
  const defaults = list(
    policy.defaults,
    "policy.defaults",
    parseRule,
    (rule) => rule.id,
  );
  for (const [index, rule] of defaults.entries())
    if (enforced.some((other) => other.id === rule.id))
      conflict(
        `policy.defaults[${index}].id`,
        `Rule ID ${rule.id} is already used in policy.enforced`,
      );
  return {
    id,
    version: positiveInteger(
      policy.version,
      "policy.version",
      1,
      1_000_000_000,
    ),
    default: oneOf(
      policy.default,
      "policy.default",
      EFFECTS,
      managed ? "ask" : "allow",
    ),
    enforced,
    defaults,
    ...(policy.adapter === undefined
      ? {}
      : { adapter: modulePath(policy.adapter, "policy.adapter") }),
    resourceTrust: {
      upstream: trustOf(
        resourceTrust,
        "upstream",
        "policy.resourceTrust",
        "allow",
      ),
      builtin: trustOf(
        resourceTrust,
        "builtin",
        "policy.resourceTrust",
        "allow",
      ),
      certified: trustOf(
        resourceTrust,
        "certified",
        "policy.resourceTrust",
        "allow",
      ),
      company: trustOf(
        resourceTrust,
        "company",
        "policy.resourceTrust",
        "allow",
      ),
      user: trustOf(
        resourceTrust,
        "user",
        "policy.resourceTrust",
        managed ? "deny" : "allow",
      ),
      project: oneOf<ProjectResourceTrust>(
        resourceTrust.project,
        "policy.resourceTrust.project",
        ["allow", "deny", "policy"],
        "policy",
      ),
    },
    providerTrust: {
      upstream: trustOf(
        providerTrust,
        "upstream",
        "policy.providerTrust",
        "allow",
      ),
      builtin: trustOf(
        providerTrust,
        "builtin",
        "policy.providerTrust",
        "allow",
      ),
      certified: trustOf(
        providerTrust,
        "certified",
        "policy.providerTrust",
        "allow",
      ),
      company: trustOf(
        providerTrust,
        "company",
        "policy.providerTrust",
        "allow",
      ),
      user: trustOf(
        providerTrust,
        "user",
        "policy.providerTrust",
        managed ? "deny" : "allow",
      ),
    },
    projectTrust: parseProjectTrust(policy.projectTrust, mode),
  };
}

// --------------------------------------------------------------------- MCP

const SERVER_ID = /^[a-z][a-z0-9-]{0,31}$/;
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const LEGACY_TRANSPORTS = ["sse", "http+sse", "http-sse"];

function toolName(value: unknown, path: string): string {
  const name = plainString(value, path, 128);
  if (!TOOL_NAME.test(name))
    fail(path, "Tool names use letters, digits, and _ . - (at most 128)");
  return name;
}

function parseServer(
  id: string,
  value: unknown,
  variables: readonly string[],
): McpServerConfig {
  const path = `mcp.servers.${id}`;
  if (!SERVER_ID.test(id))
    unsafe(
      path,
      "Server IDs use lowercase letters, digits, and hyphens (at most 32); start with a letter",
    );
  const server = record(value, path, [
    "transport",
    "module",
    "command",
    "args",
    "url",
    "env",
    "credential",
    "expectedServerName",
    "timeout",
    "startupTimeout",
    "retry",
    "required",
    "tools",
  ]);
  if (
    typeof server.transport === "string" &&
    LEGACY_TRANSPORTS.includes(server.transport)
  )
    fail(
      `${path}.transport`,
      "Legacy HTTP+SSE transport is not supported; use streamable-http",
    );
  const transport = oneOf(server.transport, `${path}.transport`, [
    "stdio",
    "streamable-http",
  ] as const);
  const credential = oneOf(
    server.credential,
    `${path}.credential`,
    ["none", "runtime"] as const,
    "none",
  );
  let launch: Pick<McpServerConfig, "module" | "command" | "url">;
  let args: string[] = [];
  let env: McpServerConfig["env"] = { allow: [], set: {} };
  if (transport === "stdio") {
    if (server.url !== undefined)
      conflict(`${path}.url`, "url applies only to streamable-http servers");
    if (credential === "runtime")
      conflict(
        `${path}.credential`,
        "credential runtime binds a bearer to streamable-http servers only; it is never placed in a stdio child environment",
      );
    if ((server.module === undefined) === (server.command === undefined))
      fail(path, "A stdio server declares exactly one of module or command");
    if (server.module !== undefined)
      launch = { module: modulePath(server.module, `${path}.module`) };
    else {
      const command = plainString(server.command, `${path}.command`, 128);
      if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(command))
        unsafe(
          `${path}.command`,
          "Use a bare executable name without path separators; use module for a ./ script",
        );
      launch = { command };
    }
    if (server.args !== undefined && !Array.isArray(server.args))
      fail(`${path}.args`, "Expected a list");
    args = ((server.args ?? []) as unknown[]).map((entry, index) =>
      nonSecretValue(entry, `${path}.args[${index}]`),
    );
    env = parseServerEnv(server.env, `${path}.env`);
  } else {
    for (const key of ["module", "command", "args", "env"])
      if (server[key] !== undefined)
        conflict(`${path}.${key}`, `${key} applies only to stdio servers`);
    if (server.url === undefined)
      fail(`${path}.url`, "A streamable-http server needs a url");
    launch = { url: referenceUrl(server.url, `${path}.url`, variables) };
  }
  const retry = optionalRecord(server.retry, `${path}.retry`, ["attempts"]);
  const tools = optionalRecord(server.tools, `${path}.tools`, [
    "allow",
    "deny",
  ]);
  const allow = list(tools.allow, `${path}.tools.allow`, toolName);
  const deny = list(tools.deny, `${path}.tools.deny`, toolName);
  for (const [index, name] of deny.entries())
    if (allow.includes(name))
      conflict(
        `${path}.tools.deny[${index}]`,
        `${name} is both allowed and denied`,
      );
  return {
    id,
    transport,
    ...launch,
    args,
    env,
    credential,
    ...(server.expectedServerName === undefined
      ? {}
      : {
          expectedServerName: plainString(
            server.expectedServerName,
            `${path}.expectedServerName`,
            128,
          ),
        }),
    timeoutMs: durationMs(server.timeout, `${path}.timeout`, "30s"),
    startupTimeoutMs: durationMs(
      server.startupTimeout,
      `${path}.startupTimeout`,
      "10s",
    ),
    retry: {
      attempts: positiveInteger(
        retry.attempts,
        `${path}.retry.attempts`,
        1,
        10,
      ),
    },
    required: bool(server.required, `${path}.required`, false),
    tools: { allow, deny },
  };
}

function parseServerEnv(value: unknown, path: string): McpServerConfig["env"] {
  const env = optionalRecord(value, path, ["allow", "set"]);
  const allow = list(env.allow, `${path}.allow`, envName);
  const set: Record<string, string> = {};
  if (env.set !== undefined) {
    if (!isRecord(env.set)) fail(`${path}.set`, "Expected an object");
    for (const [name, entry] of Object.entries(env.set)) {
      const at = `${path}.set.${name}`;
      envName(name, at);
      if (allow.includes(name))
        conflict(
          at,
          `${name} is both inherited through allow and set explicitly`,
        );
      set[name] = nonSecretValue(entry, at);
    }
  }
  return { allow, set };
}

export function parseMcp(
  value: unknown,
  mode: DeploymentMode,
  variables: readonly string[],
): McpConfig {
  const mcp = optionalRecord(value, "mcp", [
    "mode",
    "project",
    "user",
    "servers",
  ]);
  const managed = mode === "managed";
  if (managed && mcp.mode === "explicit")
    fail(
      "mcp.mode",
      "Managed mode admits only declared servers; expected off or allowlist",
    );
  const mcpMode = oneOf(
    mcp.mode,
    "mcp.mode",
    managed
      ? (["off", "allowlist"] as const)
      : (["off", "allowlist", "explicit"] as const),
    managed ? "allowlist" : "explicit",
  );
  const serversSource = mcp.servers === undefined ? {} : mcp.servers;
  if (!isRecord(serversSource))
    fail("mcp.servers", "Expected an object keyed by server ID");
  const servers = Object.entries(serversSource).map(([id, entry]) =>
    parseServer(id, entry, variables),
  );
  if (mcpMode === "off" && servers.length)
    conflict("mcp.servers", "mcp.mode off cannot declare servers");
  const fallback: TrustSetting = managed ? "deny" : "allow";
  return {
    mode: mcpMode,
    servers,
    project: oneOf(mcp.project, "mcp.project", TRUST, fallback),
    user: oneOf(mcp.user, "mcp.user", TRUST, fallback),
  };
}

// ----------------------------------------------------------------- sandbox

function sandboxPath(value: unknown, path: string): string {
  const item = plainString(value, path, 1024);
  const root = item.split("/")[0];
  const absolute = item.startsWith("/");
  if (
    !(absolute || root === "~" || root === "workspace" || root === "tmp") ||
    item.includes("\\") ||
    item
      .split("/")
      .slice(absolute ? 1 : 0)
      .some(
        (segment, index, all) =>
          segment === "." ||
          segment === ".." ||
          (!segment && index < all.length - 1),
      )
  )
    unsafe(
      path,
      "Use workspace, tmp, ~/..., or an absolute path without . or .. segments",
    );
  return item.length > 1 && item.endsWith("/") ? item.slice(0, -1) : item;
}

export function parseSandbox(value: unknown): SandboxConfig {
  const sandbox = optionalRecord(value, "sandbox", [
    "required",
    "filesystem",
    "network",
    "environment",
  ]);
  const required = bool(sandbox.required, "sandbox.required", false);
  const filesystem = optionalRecord(sandbox.filesystem, "sandbox.filesystem", [
    "read",
    "write",
  ]);
  const read = optionalRecord(filesystem.read, "sandbox.filesystem.read", [
    "deny",
  ]);
  const write = optionalRecord(filesystem.write, "sandbox.filesystem.write", [
    "allow",
  ]);
  const network = isRecord(sandbox.network) ? sandbox.network : {};
  const hostnames =
    "Hostname allowlists are not enforced at the sandbox boundary; use deny or allow (network.allowHosts governs PiShip-managed requests)";
  if (network.mode === "allowlist") fail("sandbox.network.mode", hostnames);
  for (const key of ["allow", "allowHosts", "hosts"])
    if (network[key] !== undefined) fail(`sandbox.network.${key}`, hostnames);
  const networkSection = optionalRecord(sandbox.network, "sandbox.network", [
    "mode",
  ]);
  const environment = optionalRecord(
    sandbox.environment,
    "sandbox.environment",
    ["allow"],
  );
  return {
    required,
    filesystem: {
      read: {
        deny:
          read.deny === undefined
            ? [...DEFAULT_SANDBOX_READ_DENY]
            : list(read.deny, "sandbox.filesystem.read.deny", sandboxPath),
      },
      write: {
        allow:
          write.allow === undefined
            ? [...DEFAULT_SANDBOX_WRITE_ALLOW]
            : list(write.allow, "sandbox.filesystem.write.allow", sandboxPath),
      },
    },
    network: {
      mode: oneOf(
        networkSection.mode,
        "sandbox.network.mode",
        ["deny", "allow"] as const,
        required ? "deny" : "allow",
      ),
    },
    environment: {
      allow:
        environment.allow === undefined
          ? [...DEFAULT_SANDBOX_ENVIRONMENT]
          : list(environment.allow, "sandbox.environment.allow", envName),
    },
  };
}

// ------------------------------------------------------------------- audit

const SINK_ID = /^[a-z][a-z0-9-]{0,31}$/;
const CAPTURE_KEYS = [
  "promptContent",
  "responseContent",
  "commandText",
  "sourceContent",
] as const;

function parseSink(
  entry: unknown,
  path: string,
  variables: readonly string[],
): AuditSinkConfig {
  const sink = record(entry, path, ["id", "type", "url", "required"]);
  const id = plainString(sink.id, `${path}.id`, 32);
  if (!SINK_ID.test(id))
    unsafe(
      `${path}.id`,
      "Sink IDs use lowercase letters, digits, and hyphens; start with a letter",
    );
  const type = oneOf(sink.type, `${path}.type`, ["file", "http"] as const);
  if (type === "file" && sink.url !== undefined)
    conflict(
      `${path}.url`,
      "File sinks write to the distribution state; url applies only to http sinks",
    );
  if (type === "http" && sink.url === undefined)
    fail(`${path}.url`, "An http sink needs a url");
  return {
    id,
    type,
    ...(type === "http"
      ? { url: referenceUrl(sink.url, `${path}.url`, variables) }
      : {}),
    required: bool(sink.required, `${path}.required`, false),
  };
}

export function parseAudit(
  value: unknown,
  mode: DeploymentMode,
  variables: readonly string[],
): AuditConfig {
  const audit = optionalRecord(value, "audit", [
    "enabled",
    "sinks",
    "buffer",
    "capture",
  ]);
  const enabled = bool(audit.enabled, "audit.enabled", mode === "managed");
  const sinks =
    audit.sinks === undefined
      ? enabled
        ? [{ id: "local", type: "file" as const, required: false }]
        : []
      : list(
          audit.sinks,
          "audit.sinks",
          (entry, at) => parseSink(entry, at, variables),
          (sink) => sink.id,
        );
  if (enabled && !sinks.length)
    fail("audit.sinks", "Enabled audit needs at least one sink");
  const buffer = optionalRecord(audit.buffer, "audit.buffer", [
    "maxEvents",
    "flushInterval",
  ]);
  const capture = optionalRecord(audit.capture, "audit.capture", CAPTURE_KEYS);
  const captured = {} as Record<(typeof CAPTURE_KEYS)[number], boolean>;
  for (const key of CAPTURE_KEYS)
    captured[key] = bool(capture[key], `audit.capture.${key}`, false);
  return {
    enabled,
    sinks,
    buffer: {
      maxEvents: positiveInteger(
        buffer.maxEvents,
        "audit.buffer.maxEvents",
        1000,
        1_000_000,
      ),
      flushIntervalMs: durationMs(
        buffer.flushInterval,
        "audit.buffer.flushInterval",
        "2s",
      ),
    },
    capture: captured satisfies AuditCapture,
  };
}

// -------------------------------------------------------------- governance

/**
 * Parse the piship/v1alpha3 governance sections of a manifest root.
 * `variables` are the declared runtime variable names; `app` supplies the
 * default policy ID. Throws AccessFieldError with the offending field path.
 */
export function parseGovernance(
  root: Readonly<Record<string, unknown>>,
  mode: DeploymentMode,
  variables: readonly string[],
  app: { readonly id: string },
): GovernanceManifest {
  return {
    resources: parseGovernanceResources(root.resources),
    capabilities: parseCapabilities(root.capabilities),
    policy: parsePolicy(root.policy, mode, app),
    mcp: parseMcp(root.mcp, mode, variables),
    sandbox: parseSandbox(root.sandbox),
    audit: parseAudit(root.audit, mode, variables),
  };
}

/** Runtime variables referenced by governance fields. */
export function governanceReferences(governance: GovernanceManifest): string[] {
  const names = new Set<string>();
  for (const server of governance.mcp.servers)
    if (server.url)
      for (const name of referencedVariables(server.url)) names.add(name);
  for (const sink of governance.audit.sinks)
    if (sink.url)
      for (const name of referencedVariables(sink.url)) names.add(name);
  return [...names];
}
