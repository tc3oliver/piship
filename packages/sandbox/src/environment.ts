// Environment and diagnostic hygiene for governed child processes.
import { join } from "node:path";
import {
  type ApprovedNetworkEnvironment,
  DEFAULT_NETWORK_POLICY,
  isNetworkEnvironmentName,
  PiShipError,
  redact,
  sanitizeManagedEnvironment,
} from "@piship/contracts";

/**
 * Whether a variable name looks like a long-lived credential. Delegates to the
 * managed-runtime sanitizer so both boundaries strip exactly the same names.
 */
export function isCredentialName(name: string): boolean {
  const probe: NodeJS.ProcessEnv = { [name]: "x" };
  return sanitizeManagedEnvironment(probe, DEFAULT_NETWORK_POLICY).length > 0;
}

/** Whether a value has a known token shape or is a registered secret value. */
export function looksLikeSecret(value: string): boolean {
  return redact(value) !== value;
}

function lookup(
  env: NodeJS.ProcessEnv,
  caseInsensitive: boolean,
): (name: string) => [string, string] | undefined {
  if (!caseInsensitive)
    return (name) => {
      const value = env[name];
      return value === undefined ? undefined : [name, value];
    };
  const byUpper = new Map<string, [string, string]>();
  for (const [key, value] of Object.entries(env))
    if (value !== undefined) byUpper.set(key.toUpperCase(), [key, value]);
  return (name) => byUpper.get(name.toUpperCase());
}

/**
 * Build a child environment from an allowlist. Anything not allowed is
 * dropped, credential-looking names are always dropped even when allowed, and
 * explicitly set values must not be credentials (fails with CONFIG_INVALID).
 */
export function filterEnvironment(
  env: NodeJS.ProcessEnv,
  allow: readonly string[],
  set: Readonly<Record<string, string>> = {},
  platform: NodeJS.Platform = process.platform,
): Record<string, string> {
  const find = lookup(env, platform === "win32");
  const output: Record<string, string> = {};
  for (const name of allow) {
    if (isCredentialName(name)) continue;
    const entry = find(name);
    if (entry) output[entry[0]] = entry[1];
  }
  for (const [name, value] of Object.entries(set)) {
    if (isCredentialName(name) || looksLikeSecret(value))
      throw new PiShipError(
        "CONFIG_INVALID",
        `Environment variable ${name} looks like a credential and cannot be set for a governed child process`,
        {
          component: "sandbox",
          userAction:
            "Pass credentials through a runtime credential binding, not through child environment settings",
        },
      );
    output[name] = value;
  }
  return output;
}

/** Remove credential-looking names from an already approved environment. */
export function stripCredentials(
  env: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(env))
    if (value !== undefined && !isCredentialName(name)) output[name] = value;
  return output;
}

/**
 * Give a child environment the approved network environment and no other:
 * every proxy, CA, and TLS-verification variable it holds is dropped (an
 * allowlisted `HTTPS_PROXY` included), then the approved variables are added.
 * Without a network environment (no policy was applied to this process) the
 * environment is returned unchanged.
 */
export function withApprovedNetwork(
  env: Readonly<Record<string, string | undefined>>,
  network: ApprovedNetworkEnvironment | undefined,
): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(env))
    if (
      value !== undefined &&
      !(network && isNetworkEnvironmentName(name, value))
    )
      output[name] = value;
  return network ? { ...output, ...network.variables } : output;
}

export const STDERR_TRUNCATION_MARKER = "[stderr truncated: ";

/**
 * Cache directories of the common package tools, relative to the session's
 * `cache` directory inside the writable session temp. A contained command
 * cannot write `~/.npm` or `~/.cache`, so without these the first
 * `npm install` or `pip install` fails on a read-only cache. All are pure
 * caches (content-addressed or integrity-checked), so a fresh directory only
 * costs a download. `CARGO_HOME` and `GOMODCACHE` are left out on purpose:
 * Cargo's home also holds configuration and registry credentials a command
 * would silently stop seeing, and Go makes its module cache read-only, which
 * would stop the session's temp directory from being removed.
 */
export const CACHE_VARIABLES: Readonly<Record<string, string>> = {
  XDG_CACHE_HOME: "",
  npm_config_cache: "npm",
  PIP_CACHE_DIR: "pip",
  GOCACHE: "go-build",
};

/**
 * Point the package tools' caches into `tmpDir` (the session's writable temp)
 * for each variable the environment does not already set. A value the user
 * allowed through is respected, whatever it names.
 */
export function withCacheEnvironment(
  env: Readonly<Record<string, string>>,
  tmpDir: string,
): Record<string, string> {
  const set = new Set(Object.keys(env).map((name) => name.toLowerCase()));
  const root = join(tmpDir, "cache");
  const output: Record<string, string> = { ...env };
  for (const [name, directory] of Object.entries(CACHE_VARIABLES))
    if (!set.has(name.toLowerCase()))
      output[name] = directory ? join(root, directory) : root;
  return output;
}

/**
 * Redact and bound child stderr before it can reach logs or model context.
 * Redaction runs first so truncation can never expose part of a secret; the
 * tail is kept because the last lines usually carry the error.
 */
export function sanitizeStderr(text: string, maxBytes = 8192): string {
  const redacted = redact(text);
  const bytes = Buffer.from(redacted, "utf8");
  if (bytes.length <= maxBytes) return redacted;
  let start = bytes.length - Math.max(0, maxBytes);
  // Skip UTF-8 continuation bytes so the kept tail starts on a character.
  while (start < bytes.length && ((bytes[start] ?? 0) & 0xc0) === 0x80) start++;
  return `${STDERR_TRUNCATION_MARKER}${start} bytes omitted]\n${bytes.subarray(start).toString("utf8")}`;
}
