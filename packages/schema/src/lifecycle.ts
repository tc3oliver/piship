// Parser for the piship/v1alpha4 and v1alpha5 lifecycle sections: signed update channels
// (`updates`) and release policy (`release`).
import { Buffer } from "node:buffer";
import { isPrivateNetworkHost } from "@piship/contracts";
import { AccessFieldError } from "./access.js";
import { PRIVATE_HOSTS } from "./http-transport.js";
import {
  checkTemplate,
  hasRuntimeReference,
  referencedVariables,
} from "./variables.js";

/** Top-level manifest sections added by piship/v1alpha4 (kept by v1alpha5). */
export const LIFECYCLE_KEYS = ["updates", "release"] as const;

/** Lifecycle fields that accept `${NAME}` runtime references. */
export const LIFECYCLE_RUNTIME_REFERENCE_FIELDS = ["updates.source"] as const;

/**
 * How the update channel may be reached (piship/v1alpha5
 * `updates.transport`): `https` (the default) keeps plain HTTP to loopback
 * only; `http-allowed` also permits plain HTTP to a private or internal
 * update host. It covers the update channel, its root metadata, and release
 * downloads only, never another endpoint.
 */
export const UPDATE_TRANSPORTS = ["https", "http-allowed"] as const;
export type UpdateTransport = (typeof UPDATE_TRANSPORTS)[number];

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
/** The signing roles of an update root. */
export const UPDATE_ROLES = ["root", "channel"] as const;
export type UpdateRoleName = (typeof UPDATE_ROLES)[number];
export interface UpdateRole {
  /** Ids of `keys` entries that may sign for this role, without duplicates. */
  readonly keyIds: readonly string[];
  /** Signatures required, from 1 to the number of `keyIds`. */
  readonly threshold: number;
}
/**
 * An update root: the trusted keys and the root / channel role thresholds.
 * The piship/v1alpha5 `updates.trust.bootstrap` is the root a fresh
 * installation starts from; hosted `piship-update-root/v1` metadata carries
 * the same body plus `schema` and `distribution`.
 */
export interface UpdateRoot {
  /** Root version, an integer from 1. */
  readonly version: number;
  /** UTC timestamp, `YYYY-MM-DDTHH:MM:SS[.fraction]Z`. */
  readonly expires: string;
  readonly keys: readonly UpdateTrustKey[];
  readonly roles: { readonly [role in UpdateRoleName]: UpdateRole };
}
/** piship/v1alpha4 update trust: any one listed key signs channels. */
export interface LegacyUpdateTrust {
  readonly keys: readonly UpdateTrustKey[];
}
/**
 * piship/v1alpha5 update trust. Without `bootstrap` the distribution is
 * update-disabled.
 */
export interface BootstrapUpdateTrust {
  readonly bootstrap?: UpdateRoot;
}
export type UpdatesTrust = LegacyUpdateTrust | BootstrapUpdateTrust;
export interface UpdatesManifest {
  /** Default channel for new installs. */
  readonly channel: ReleaseChannel;
  /** Channels a user may select; always includes `channel`. */
  readonly channels: readonly ReleaseChannel[];
  /**
   * Update metadata location: an https URL, loopback http URL (or, with
   * `transport: http-allowed`, an http URL on a private or internal host),
   * or `${NAME}` template.
   */
  readonly source?: string;
  /** piship/v1alpha5 only; absent means `https`. */
  readonly transport?: UpdateTransport;
  /** Keep the previous known-good release for rollback. */
  readonly rollback: boolean;
  /** `keys` for piship/v1alpha4; an optional `bootstrap` root for piship/v1alpha5. */
  readonly trust: UpdatesTrust;
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
    /**
     * piship/v1alpha6: the registry `npm audit` asks for advisories, when it
     * is not the configured registry.
     */
    readonly registry?: string;
  };
  /**
   * piship/v1alpha6: reviewed npm lifecycle scripts in Pi package closures,
   * as `pi-packages/<id>/node_modules/<name>@<version>`. Each one lets that
   * exact dependency through the install-script gate; PiShip never runs it.
   */
  readonly installScripts?: readonly string[];
  /**
   * piship/v1alpha6: strip JS source maps and TypeScript declaration files
   * from the payload before its inventory is computed. Roughly halves the
   * file count a managed Windows machine extracts and scans on first install.
   */
  readonly strip?: boolean;
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
/**
 * What `updates.transport: http-allowed` accepts as a plain-HTTP update host:
 * the same hosts as every `httpTransport: http-allowed` endpoint.
 */
export const PRIVATE_UPDATE_HOSTS = PRIVATE_HOSTS;

/**
 * Whether `updates.transport` lets the update channel use plain HTTP to
 * `url`: always for loopback, and with `http-allowed` for a private or
 * internal host. Only the URL text is judged, never DNS.
 */
export function plainHttpUpdateAllowed(
  url: URL,
  transport: UpdateTransport | undefined,
): boolean {
  return (
    url.protocol === "http:" &&
    (LOOPBACK_HOSTS.includes(url.hostname) ||
      (transport === "http-allowed" && isPrivateNetworkHost(url.hostname)))
  );
}

function updateSource(
  value: unknown,
  path: string,
  variables: readonly string[],
  transport: UpdateTransport | undefined,
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
    transport === "http-allowed" &&
    url.protocol === "http:" &&
    !plainHttpUpdateAllowed(url, transport)
  )
    fail(
      path,
      `updates.transport: http-allowed permits plain HTTP only to a private or internal host (${PRIVATE_UPDATE_HOSTS}); ${url.hostname} is public, so serve it over https`,
    );
  if (url.protocol !== "https:" && !plainHttpUpdateAllowed(url, transport))
    fail(path, UPDATE_SOURCE_FORMS);
  return text;
}
// Bounds that keep a root small enough to read and verify in one step.
const MAX_ROOT_KEYS = 32;
const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;

function timestamp(value: unknown, path: string): string {
  const match = typeof value === "string" ? TIMESTAMP.exec(value) : null;
  if (!match)
    fail(path, "Expected a UTC timestamp such as 2027-10-01T00:00:00Z");
  const [year, month, day, hour, minute, second] = match
    .slice(1, 7)
    .map(Number) as [number, number, number, number, number, number];
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second
  )
    fail(path, "Expected a valid UTC timestamp such as 2027-10-01T00:00:00Z");
  return match[0];
}
function integer(value: unknown, path: string, min: number, max?: number) {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < min ||
    (max !== undefined && value > max)
  )
    fail(
      path,
      max === undefined
        ? `Expected an integer of at least ${min}`
        : `Expected an integer from ${min} to ${max}`,
    );
  return value;
}
function trustKeys(value: unknown, path: string): UpdateTrustKey[] {
  const keys = list(value, path).map((entry, index) => {
    const at = `${path}[${index}]`;
    const key = record(entry, at, ["id", "publicKey"]);
    return {
      id: keyId(key.id, `${at}.id`),
      publicKey: publicKey(key.publicKey, `${at}.publicKey`),
    } satisfies UpdateTrustKey;
  });
  for (const [index, key] of keys.entries()) {
    const first = keys.findIndex((other) => other.id === key.id);
    if (first !== index)
      fail(
        `${path}[${index}].id`,
        keys[first]?.publicKey === key.publicKey
          ? `Duplicate key id ${key.id}; key ids are unique`
          : `Duplicate key id ${key.id}; key ids are unique, and one id cannot name two different public keys`,
      );
  }
  return keys;
}
function role(
  value: unknown,
  path: string,
  keys: readonly UpdateTrustKey[],
): UpdateRole {
  const entry = record(value, path, ["keyIds", "threshold"]);
  const keyIds = list(entry.keyIds, `${path}.keyIds`).map((item, index) => {
    const at = `${path}.keyIds[${index}]`;
    const id = keyId(item, at);
    if (!keys.some((key) => key.id === id))
      fail(at, `Key id ${id} is not listed in keys`);
    return id;
  });
  if (keyIds.length === 0)
    fail(`${path}.keyIds`, "Expected at least one key id");
  unique(keyIds, `${path}.keyIds`);
  return {
    keyIds,
    threshold: integer(entry.threshold, `${path}.threshold`, 1, keyIds.length),
  };
}

/**
 * Validate an update root body: `version`, `expires`, `keys`, and the root
 * and channel `roles`. Every role key id must be listed in `keys`, each
 * threshold is an integer from 1 to the role's key count, key ids are
 * unique, and one public key is listed under one id only (so a threshold
 * counts distinct keys). `extraKeys` names additional top-level fields the
 * caller validates itself, such as `schema` and `distribution` of hosted
 * `piship-update-root/v1` metadata; they are not part of the result.
 * Throws AccessFieldError naming the offending field under `path`.
 */
export function parseUpdateRoot(
  value: unknown,
  path: string,
  extraKeys: readonly string[] = [],
): UpdateRoot {
  const root = record(value, path, [
    ...extraKeys,
    "version",
    "expires",
    "keys",
    "roles",
  ]);
  const version = integer(root.version, `${path}.version`, 1);
  const expires = timestamp(root.expires, `${path}.expires`);
  const keys = trustKeys(root.keys, `${path}.keys`);
  if (keys.length === 0) fail(`${path}.keys`, "Expected at least one key");
  if (keys.length > MAX_ROOT_KEYS)
    fail(`${path}.keys`, `Expected at most ${MAX_ROOT_KEYS} keys`);
  for (const [index, key] of keys.entries()) {
    const first = keys.findIndex((other) => other.publicKey === key.publicKey);
    if (first !== index)
      fail(
        `${path}.keys[${index}].publicKey`,
        `The public key of ${key.id} is already listed as ${keys[first]?.id}; list each key once and name it in every role it signs for`,
      );
  }
  const roles = record(root.roles, `${path}.roles`, UPDATE_ROLES);
  return {
    version,
    expires,
    keys,
    roles: {
      root: role(roles.root, `${path}.roles.root`, keys),
      channel: role(roles.channel, `${path}.roles.channel`, keys),
    },
  };
}

/** The keys of one role of an update root, in `keyIds` order. */
export function updateRoleKeys(
  root: UpdateRoot,
  name: UpdateRoleName,
): UpdateTrustKey[] {
  return root.roles[name].keyIds.flatMap((id) =>
    root.keys.filter((key) => key.id === id),
  );
}

/**
 * Key ids the root and channel roles share. Each listed public key has one
 * id, so these are exactly the public keys both roles reuse.
 */
export function sharedRoleKeyIds(root: UpdateRoot): string[] {
  return root.roles.root.keyIds.filter((id) =>
    root.roles.channel.keyIds.includes(id),
  );
}

/**
 * The keys that sign update channels: the channel role of a piship/v1alpha5
 * bootstrap, or every piship/v1alpha4 key. Empty when updates are disabled.
 */
export function channelTrustKeys(
  updates: UpdatesManifest | undefined,
): readonly UpdateTrustKey[] {
  const trust = updates?.trust;
  if (!trust) return [];
  if ("keys" in trust) return trust.keys;
  return trust.bootstrap ? updateRoleKeys(trust.bootstrap, "channel") : [];
}

/**
 * Owner-facing piship/v1alpha5 update trust warnings: an update source
 * without bootstrap trust (update fails closed), and a managed distribution
 * whose root and channel roles reuse a public key, as the compatibility
 * trust set of a migrated v1alpha4 manifest does. `piship release` refuses
 * both for a managed distribution.
 */
export function updateTrustWarnings(
  mode: "personal" | "managed",
  updates: UpdatesManifest,
): { path: string; message: string }[] {
  const warnings: { path: string; message: string }[] = [];
  if ("keys" in updates.trust) return warnings;
  const bootstrap = updates.trust.bootstrap;
  if (!bootstrap && updates.source !== undefined)
    warnings.push({
      path: "updates.trust.bootstrap",
      message:
        "updates.source is set without bootstrap trust, so update fails closed and piship release refuses the distribution; add updates.trust.bootstrap or remove updates.source",
    });
  const shared = bootstrap ? sharedRoleKeyIds(bootstrap) : [];
  if (mode === "managed" && shared.length)
    warnings.push({
      path: "updates.trust.bootstrap.roles",
      message: `the root and channel roles share ${shared.join(", ")}; a managed distribution needs distinct root and channel keys (an offline root key), and piship release refuses it until the roles are split`,
    });
  return warnings;
}

function parseUpdates(
  value: unknown,
  variables: readonly string[],
  bootstrap: boolean,
): UpdatesManifest {
  if (value === undefined)
    fail(
      "updates",
      `${bootstrap ? "piship/v1alpha5" : "piship/v1alpha4"} requires an updates section; run piship migrate to add one`,
    );
  const updates = record(value, "updates", [
    "channel",
    "channels",
    "source",
    ...(bootstrap ? ["transport"] : []),
    "rollback",
    "trust",
  ]);
  const transport =
    updates.transport === undefined
      ? undefined
      : oneOf(updates.transport, "updates.transport", UPDATE_TRANSPORTS);
  // Plain HTTP leaves integrity to the update signatures alone, so it needs
  // a bootstrap root to verify them.
  if (
    transport === "http-allowed" &&
    !(isRecord(updates.trust) && updates.trust.bootstrap !== undefined)
  )
    fail(
      "updates.transport",
      "http-allowed requires updates.trust.bootstrap: over plain HTTP, update integrity rests on the signed update metadata alone",
    );
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
  if (bootstrap && isRecord(updates.trust) && "keys" in updates.trust)
    fail(
      "updates.trust.keys",
      "piship/v1alpha5 replaces updates.trust.keys with updates.trust.bootstrap (version, expires, keys, and root and channel roles); run piship migrate on the v1alpha4 manifest",
    );
  const trust = optionalRecord(updates.trust, "updates.trust", [
    bootstrap ? "bootstrap" : "keys",
  ]);
  return {
    channel,
    channels,
    ...(updates.source === undefined
      ? {}
      : {
          source: updateSource(
            updates.source,
            "updates.source",
            variables,
            transport,
          ),
        }),
    // Present only when declared, so a manifest without it locks unchanged.
    ...(transport === undefined ? {} : { transport }),
    rollback: updates.rollback ?? true,
    trust: bootstrap
      ? trust.bootstrap === undefined
        ? {}
        : {
            bootstrap: parseUpdateRoot(
              trust.bootstrap,
              "updates.trust.bootstrap",
            ),
          }
      : {
          keys:
            trust.keys === undefined
              ? []
              : trustKeys(trust.keys, "updates.trust.keys"),
        },
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
function parseRelease(value: unknown, v6: boolean): ReleaseManifest {
  const release = optionalRecord(value, "release", [
    "targets",
    "sources",
    "vulnerabilities",
    ...(v6 ? ["installScripts", "strip"] : []),
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
    ["failOn", "allow", ...(v6 ? ["registry"] : [])],
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
  const registry =
    vulnerabilities.registry === undefined
      ? undefined
      : auditRegistry(
          vulnerabilities.registry,
          "release.vulnerabilities.registry",
        );
  const installScripts =
    release.installScripts === undefined
      ? undefined
      : list(release.installScripts, "release.installScripts").map(
          (entry, index) => {
            const at = `release.installScripts[${index}]`;
            const text = plainString(entry, at, 512);
            if (!INSTALL_SCRIPT_KEY.test(text))
              fail(
                at,
                "Expected pi-packages/<id>/node_modules/<name>@<exact version>",
              );
            return text;
          },
        );
  if (installScripts) unique(installScripts, "release.installScripts");
  let strip: boolean | undefined;
  if (release.strip !== undefined) {
    if (typeof release.strip !== "boolean")
      fail("release.strip", "Expected a boolean");
    strip = release.strip === true;
  }
  return {
    targets,
    sources,
    vulnerabilities: {
      failOn,
      allow,
      ...(registry === undefined ? {} : { registry }),
    },
    ...(installScripts === undefined ? {} : { installScripts }),
    ...(strip === undefined ? {} : { strip }),
  };
}

const NPM_SEGMENT = "(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*";
/** `pi-packages/<id>/node_modules/<name>[/node_modules/<name>...]@<semver>`. */
const INSTALL_SCRIPT_KEY = new RegExp(
  `^pi-packages/[a-z][a-z0-9-]{0,63}/node_modules/${NPM_SEGMENT}(?:/node_modules/${NPM_SEGMENT})*@\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?$`,
);

/** An https registry URL without credentials, query, or fragment. */
function auditRegistry(value: unknown, path: string): string {
  const text = plainString(value, path, 2048);
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    fail(path, "Expected an https registry URL");
  }
  if (url.protocol !== "https:") fail(path, "Expected an https registry URL");
  if (url.username || url.password)
    fail(path, "URLs must not embed credentials");
  if (url.search || url.hash || text.includes("?") || text.includes("#"))
    fail(path, "URLs must not carry a query or fragment");
  return text;
}

// --------------------------------------------------------------- lifecycle

/**
 * Parse the piship/v1alpha4 or piship/v1alpha5 lifecycle sections of a
 * manifest root. `variables` are the declared runtime variable names;
 * `bootstrap` selects v1alpha5 update trust (`updates.trust.bootstrap`)
 * instead of v1alpha4 `updates.trust.keys`. Throws AccessFieldError with the
 * offending field path.
 */
export function parseLifecycle(
  root: Readonly<Record<string, unknown>>,
  variables: readonly string[],
  bootstrap = false,
  /** piship/v1alpha6 and later: `release.vulnerabilities.registry`. */
  v6 = false,
): LifecycleManifest {
  return {
    updates: parseUpdates(root.updates, variables, bootstrap),
    release: parseRelease(root.release, v6),
  };
}

/** Runtime variables referenced by lifecycle fields. */
export function lifecycleReferences(lifecycle: LifecycleManifest): string[] {
  return lifecycle.updates.source
    ? referencedVariables(lifecycle.updates.source)
    : [];
}
