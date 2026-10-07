// Shared field validators for the piship/v1alpha3 governance parsers. Every
// field is validated strictly; unknown and secret-looking fields are rejected.
import { valid as validSemver } from "semver";
import {
  AccessFieldError,
  checkUrl,
  failUnknown,
  parseDuration,
} from "../access.js";
import {
  checkTemplate,
  checkVariableName,
  hasRuntimeReference,
} from "../variables.js";

export type Json = Record<string, unknown>;

export function fail(field: string, message: string): never {
  throw new AccessFieldError("invalid field", field, message);
}
export function unsafe(field: string, message: string): never {
  throw new AccessFieldError("unsafe path/name", field, message);
}
export function conflict(field: string, message: string): never {
  throw new AccessFieldError("conflict", field, message);
}
export function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** Field names that indicate secret material; never valid manifest keys. */
export const SECRET_FIELD =
  /(secret|token|password|passwd|api_?key|private_?key|client_?key|bearer|authorization|cookie)/i;
export function record(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Json {
  if (!isRecord(value)) fail(path, "Expected an object");
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) failUnknown(path, unknown, allowed, SECRET_FIELD);
  return value;
}
export function optionalRecord(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Json {
  return value === undefined ? {} : record(value, path, allowed);
}
export function hasControl(value: string, allowNewlines = false): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    if (allowNewlines && (code === 10 || code === 9)) return false;
    return code < 32 || code === 127;
  });
}
export function plainString(value: unknown, path: string, max = 256): string {
  if (typeof value !== "string" || value.trim() === "")
    fail(path, "Expected a non-empty string");
  if (hasRuntimeReference(value))
    fail(path, "Runtime references are not allowed in this field");
  if (hasControl(value)) fail(path, "Control characters are not allowed");
  if (value.length > max) fail(path, `Use at most ${max} characters`);
  return value;
}
export function bool(value: unknown, path: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") fail(path, "Expected true or false");
  return value;
}
export function positiveInteger(
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
export function durationMs(
  value: unknown,
  path: string,
  fallback: string,
): number {
  const seconds = parseDuration(value ?? fallback, path);
  if (seconds <= 0) fail(path, "Expected a duration greater than zero");
  return seconds * 1000;
}
export function list<T>(
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
export function oneOf<T extends string>(
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
export function relativePath(value: unknown, path: string): string {
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
export function modulePath(value: unknown, path: string): string {
  const item = relativePath(value, path);
  if (!/\.(?:mjs|js)$/.test(item))
    fail(path, "Modules must be ECMAScript modules ending in .mjs or .js");
  return item;
}
/**
 * An endpoint URL or `${NAME}` reference. With `plainHttp` (the endpoint's
 * `httpTransport: http-allowed`) plain HTTP to a private or internal host is
 * accepted too; a reference is checked the same way once it resolves.
 */
export function referenceUrl(
  value: unknown,
  path: string,
  variables: readonly string[],
  plainHttp = false,
): string {
  if (typeof value !== "string" || value.trim() === "")
    fail(path, "Expected a non-empty string");
  if (hasRuntimeReference(value) || value.includes("$")) {
    const problem = checkTemplate(value, variables);
    if (problem) fail(path, problem.message);
    return value;
  }
  const text = plainString(value, path, 2048);
  checkUrl(text, path, plainHttp);
  return text;
}
const SEMVER_PATTERN = /^[0-9]/;
export function semver(value: unknown, path: string): string {
  const text = plainString(value, path, 128);
  if (!SEMVER_PATTERN.test(text) || validSemver(text) === null)
    fail(path, "Expected a SemVer version such as 1.2.0");
  return text;
}
export function exactPiVersion(value: unknown, path: string): string {
  const text = plainString(value, path, 64);
  if (!/^\d+\.\d+\.\d+$/.test(text))
    fail(path, "Expected an exact Pi version such as 1.0.0");
  return text;
}
export function envName(value: unknown, path: string): string {
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
export function nonSecretValue(value: unknown, path: string): string {
  const text = plainString(value, path, 1024);
  if (SECRET_VALUE.some((pattern) => pattern.test(text)))
    fail(
      path,
      "Value looks like secret material; secrets are never declared in piship.yaml",
    );
  return text;
}
