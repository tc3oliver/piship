// Parser for the piship/v1alpha4 lifecycle sections: signed update channels
// (`updates`) and release policy (`release`).
import { Buffer } from "node:buffer";
import { AccessFieldError } from "./access.js";
import {
  checkTemplate,
  hasRuntimeReference,
  referencedVariables,
} from "./variables.js";

/** Top-level manifest sections added by piship/v1alpha4. */
export const LIFECYCLE_KEYS = ["updates", "release"] as const;

/** Lifecycle fields that accept `${NAME}` runtime references. */
export const LIFECYCLE_RUNTIME_REFERENCE_FIELDS = ["updates.source"] as const;

export const RELEASE_CHANNELS = ["stable", "candidate", "dev"] as const;
export type ReleaseChannel = (typeof RELEASE_CHANNELS)[number];

export const RELEASE_TARGETS = [
  "linux-x64",
  "linux-arm64",
  "darwin-arm64",
  "darwin-x64",
  "win32-x64",
] as const;
export type ReleaseTarget = (typeof RELEASE_TARGETS)[number];

export const DEFAULT_RELEASE_TARGETS: readonly ReleaseTarget[] = [
  "linux-x64",
  "darwin-arm64",
  "win32-x64",
];
export const DEFAULT_PACKAGE_SOURCES: readonly string[] = [
  "https://registry.npmjs.org",
];

export const VULNERABILITY_SEVERITIES = [
  "low",
  "moderate",
  "high",
  "critical",
] as const;
export type VulnerabilitySeverity = (typeof VULNERABILITY_SEVERITIES)[number];

export interface UpdateTrustKey {
  /** Lowercase key id, `[a-z0-9][a-z0-9.-]*`. */
  readonly id: string;
  /** Base64 Ed25519 SubjectPublicKeyInfo DER (44 bytes). */
  readonly publicKey: string;
}
export interface UpdatesManifest {
  /** Default channel for new installs. */
  readonly channel: ReleaseChannel;
  /** Channels a user may select; always includes `channel`. */
  readonly channels: readonly ReleaseChannel[];
  /** Update metadata location: an https URL, loopback http URL, or `${NAME}` template. */
  readonly source?: string;
  /** Keep the previous known-good release for rollback. */
  readonly rollback: boolean;
  readonly trust: { readonly keys: readonly UpdateTrustKey[] };
}
export interface VulnerabilityException {
  readonly id: string;
  readonly reason: string;
  /** YYYY-MM-DD. */
  readonly expires: string;
}
export interface ReleaseManifest {
  readonly targets: readonly ReleaseTarget[];
  /** Approved npm package source origins, without a trailing slash. */
  readonly sources: readonly string[];
  readonly vulnerabilities: {
    readonly failOn: VulnerabilitySeverity;
    readonly allow: readonly VulnerabilityException[];
  };
}
export interface LifecycleManifest {
  readonly updates: UpdatesManifest;
  readonly release: ReleaseManifest;
}

type Json = Record<string, unknown>;

function fail(field: string, message: string): never {
  throw new AccessFieldError("invalid field", field, message);
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
function hasControl(value: string): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    return code < 32 || code === 127;
  });
}
function plainString(value: unknown, path: string, max: number): string {
  if (typeof value !== "string" || value.trim() === "")
    fail(path, "Expected a non-empty string");
  if (hasRuntimeReference(value))
    fail(path, "Runtime references are not allowed in this field");
  if (hasControl(value)) fail(path, "Control characters are not allowed");
  if (value.length > max) fail(path, `Expected at most ${max} characters`);
  return value;
}
function list(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) fail(path, "Expected a list");
  return value;
}
function unique<T>(values: readonly T[], path: string): void {
  if (new Set(values).size !== values.length)
    fail(path, "Duplicate entries are not allowed");
}
function oneOf<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (
    typeof value !== "string" ||
    !(allowed as readonly string[]).includes(value)
  )
    fail(path, `Expected ${allowed.join(", ")}`);
  return value as T;
}

// ----------------------------------------------------------------- updates

const KEY_ID = /^[a-z0-9][a-z0-9.-]*$/;
/** DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410). */
const ED25519_SPKI_PREFIX = "302a300506032b6570032100";

function keyId(value: unknown, path: string): string {
  const id = plainString(value, path, 64);
  if (!KEY_ID.test(id))
    fail(
      path,
      "Key ids use lowercase letters, digits, dots, and hyphens; start with a letter or digit",
    );
  return id;
}
function publicKey(value: unknown, path: string): string {
  const text = plainString(value, path, 128);
  const der = /^[A-Za-z0-9+/]+={0,2}$/.test(text)
    ? Buffer.from(text, "base64")
    : undefined;
  if (
    !der ||
    der.toString("base64") !== text ||
    der.length !== 44 ||
    der.subarray(0, 12).toString("hex") !== ED25519_SPKI_PREFIX
  )
    fail(
      path,
      "Expected a base64 Ed25519 public key (SubjectPublicKeyInfo DER, 44 bytes)",
    );
  return text;
}
const LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]"];
const UPDATE_SOURCE_FORMS = `Expected an https URL, an http URL on 127.0.0.1, localhost, or [::1], or a \${NAME} runtime reference (which may also resolve to an absolute local directory)`;
function updateSource(
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
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    fail(path, UPDATE_SOURCE_FORMS);
  }
  if (url.username || url.password)
    fail(path, "URLs must not embed credentials");
  if (url.search || url.hash)
    fail(path, "URLs must not contain query strings or fragments");
  if (
    url.protocol !== "https:" &&
    !(url.protocol === "http:" && LOOPBACK_HOSTS.includes(url.hostname))
  )
    fail(path, UPDATE_SOURCE_FORMS);
  return text;
}
function parseUpdates(
  value: unknown,
  variables: readonly string[],
): UpdatesManifest {
  if (value === undefined)
    fail(
      "updates",
      "piship/v1alpha4 requires an updates section; run piship migrate to add one",
    );
  const updates = record(value, "updates", [
    "channel",
    "channels",
    "source",
    "rollback",
    "trust",
  ]);
  const channel =
    updates.channel === undefined
      ? "stable"
      : oneOf(updates.channel, "updates.channel", RELEASE_CHANNELS);
  const channels =
    updates.channels === undefined
      ? [channel]
      : list(updates.channels, "updates.channels").map((entry, index) =>
          oneOf(entry, `updates.channels[${index}]`, RELEASE_CHANNELS),
        );
  unique(channels, "updates.channels");
  if (!channels.includes(channel))
    fail("updates.channels", `Must include the default channel ${channel}`);
  if (updates.rollback !== undefined && typeof updates.rollback !== "boolean")
    fail("updates.rollback", "Expected true or false");
  const trust = optionalRecord(updates.trust, "updates.trust", ["keys"]);
  const keys =
    trust.keys === undefined
      ? []
      : list(trust.keys, "updates.trust.keys").map((entry, index) => {
          const at = `updates.trust.keys[${index}]`;
          const key = record(entry, at, ["id", "publicKey"]);
          return {
            id: keyId(key.id, `${at}.id`),
            publicKey: publicKey(key.publicKey, `${at}.publicKey`),
          } satisfies UpdateTrustKey;
        });
  for (const [index, key] of keys.entries())
    if (keys.findIndex((other) => other.id === key.id) !== index)
      fail(
        `updates.trust.keys[${index}].id`,
        `Duplicate key id ${key.id}; key ids are unique`,
      );
  return {
    channel,
    channels,
    ...(updates.source === undefined
      ? {}
      : { source: updateSource(updates.source, "updates.source", variables) }),
    rollback: updates.rollback ?? true,
    trust: { keys },
  };
}

// ----------------------------------------------------------------- release

function packageSource(value: unknown, path: string): string {
  const text = plainString(value, path, 2048);
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    fail(path, "Expected an https origin such as https://registry.npmjs.org");
  }
  if (url.protocol !== "https:") fail(path, "Package sources must use https");
  if (url.username || url.password)
    fail(path, "URLs must not embed credentials");
  if (
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    text.includes("?") ||
    text.includes("#")
  )
    fail(
      path,
      "Package sources are origins without a path, query string, or fragment",
    );
  return url.origin;
}
const ADVISORY_ID = /^[A-Za-z0-9._:-]+$/;
function expiryDate(value: unknown, path: string): string {
  const text =
    value instanceof Date && !Number.isNaN(value.getTime())
      ? value.toISOString().slice(0, 10)
      : value;
  if (typeof text !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(text))
    fail(path, "Expected a date in YYYY-MM-DD form");
  const [year, month, day] = text.split("-").map(Number) as [
    number,
    number,
    number,
  ];
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  )
    fail(path, "Expected a valid calendar date in YYYY-MM-DD form");
  return text;
}
function parseRelease(value: unknown): ReleaseManifest {
  const release = optionalRecord(value, "release", [
    "targets",
    "sources",
    "vulnerabilities",
  ]);
  const targets =
    release.targets === undefined
      ? [...DEFAULT_RELEASE_TARGETS]
      : list(release.targets, "release.targets").map((entry, index) =>
          oneOf(entry, `release.targets[${index}]`, RELEASE_TARGETS),
        );
  if (targets.length === 0)
    fail("release.targets", "Expected at least one target");
  unique(targets, "release.targets");
  const sources =
    release.sources === undefined
      ? [...DEFAULT_PACKAGE_SOURCES]
      : list(release.sources, "release.sources").map((entry, index) =>
          packageSource(entry, `release.sources[${index}]`),
        );
  if (sources.length === 0)
    fail("release.sources", "Expected at least one package source");
  unique(sources, "release.sources");
  const vulnerabilities = optionalRecord(
    release.vulnerabilities,
    "release.vulnerabilities",
    ["failOn", "allow"],
  );
  const failOn =
    vulnerabilities.failOn === undefined
      ? "high"
      : oneOf(
          vulnerabilities.failOn,
          "release.vulnerabilities.failOn",
          VULNERABILITY_SEVERITIES,
        );
  const allow =
    vulnerabilities.allow === undefined
      ? []
      : list(vulnerabilities.allow, "release.vulnerabilities.allow").map(
          (entry, index) => {
            const at = `release.vulnerabilities.allow[${index}]`;
            const item = record(entry, at, ["id", "reason", "expires"]);
            const id = plainString(item.id, `${at}.id`, 128);
            if (!ADVISORY_ID.test(id))
              fail(
                `${at}.id`,
                "Advisory ids use letters, digits, and . _ : - characters",
              );
            return {
              id,
              reason: plainString(item.reason, `${at}.reason`, 240),
              expires: expiryDate(item.expires, `${at}.expires`),
            } satisfies VulnerabilityException;
          },
        );
  for (const [index, entry] of allow.entries())
    if (allow.findIndex((other) => other.id === entry.id) !== index)
      fail(
        `release.vulnerabilities.allow[${index}].id`,
        `Duplicate advisory id ${entry.id}`,
      );
  return { targets, sources, vulnerabilities: { failOn, allow } };
}

// --------------------------------------------------------------- lifecycle

/**
 * Parse the piship/v1alpha4 lifecycle sections of a manifest root.
 * `variables` are the declared runtime variable names. Throws
 * AccessFieldError with the offending field path.
 */
export function parseLifecycle(
  root: Readonly<Record<string, unknown>>,
  variables: readonly string[],
): LifecycleManifest {
  return {
    updates: parseUpdates(root.updates, variables),
    release: parseRelease(root.release),
  };
}

/** Runtime variables referenced by lifecycle fields. */
export function lifecycleReferences(lifecycle: LifecycleManifest): string[] {
  return lifecycle.updates.source
    ? referencedVariables(lifecycle.updates.source)
    : [];
}
