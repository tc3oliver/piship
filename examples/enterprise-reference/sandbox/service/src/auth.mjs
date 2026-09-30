// Caller authentication: an API key the organization issued to one user. The
// registry holds only the SHA-256 of each key, so reading it (or a backup of
// it) yields nothing a caller can present. A key names its user, and a
// sandbox belongs to the user whose key created it.
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

export const REGISTRY_SCHEMA = "piship-reference-sandbox-registry/v1";
const USER_ID = /^[a-z0-9][a-z0-9_.-]{0,40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
// PiShip stores 8 to 4096 visible ASCII characters and sends them as is.
const TOKEN = /^[\x21-\x7e]{8,4096}$/;

const digest = (value) => createHash("sha256").update(value, "utf8").digest();

/** Read and check the registry. Throws without echoing any of its content. */
export function loadRegistry(path) {
  let raw;
  try {
    if (!statSync(path).isFile()) throw new Error("not a file");
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("SANDBOX_REGISTRY is not a readable JSON file");
  }
  if (raw?.schema !== REGISTRY_SCHEMA || !Array.isArray(raw.keys))
    throw new Error(`SANDBOX_REGISTRY must have schema ${REGISTRY_SCHEMA}`);
  const seen = new Set();
  const keys = raw.keys.map((entry) => {
    if (
      typeof entry?.id !== "string" ||
      !USER_ID.test(entry.id) ||
      typeof entry.sha256 !== "string" ||
      !HEX_64.test(entry.sha256)
    )
      throw new Error("SANDBOX_REGISTRY has an entry that is not {id, sha256}");
    if (seen.has(entry.id))
      throw new Error("SANDBOX_REGISTRY names a user twice");
    seen.add(entry.id);
    return { id: entry.id, hash: Buffer.from(entry.sha256, "hex") };
  });
  if (keys.length === 0) throw new Error("SANDBOX_REGISTRY has no keys");
  return keys;
}

/**
 * The user a request's Authorization header names, or undefined. Missing,
 * malformed, and unknown credentials are the same answer, and every entry is
 * compared, so the time taken does not say which entry (if any) matched.
 */
export function authenticate(keys, header) {
  if (typeof header !== "string") return undefined;
  const match = /^Bearer ([\x21-\x7e]+)$/i.exec(header);
  const token = match?.[1];
  if (token === undefined || !TOKEN.test(token)) return undefined;
  const presented = digest(token);
  let user;
  for (const key of keys)
    if (timingSafeEqual(presented, key.hash)) user = key.id;
  return user;
}

export const sha256Hex = (value) => digest(value).toString("hex");
