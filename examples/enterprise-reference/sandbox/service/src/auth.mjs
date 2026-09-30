// Caller authentication: an API key the organization issued to one user. The
// registry holds only the SHA-256 of each key, so reading it (or a backup of
// it) yields nothing a caller can present. A key names its user, and a
// sandbox belongs to the user whose key created it.
//
// A key is also bound to what it may mount. Commands run as the owner of the
// workspace, so a key that could name any workspace under the service's roots
// could mount another user's project read-write as that user. Each entry
// therefore names the host user (`uid`) whose workspaces it may mount, and may
// narrow the directories further (`roots`); an entry that says neither is
// refused, unless it says `unbound: true`, the explicit opt-in for a single-
// user setup, where any key may mount any non-root workspace under the roots.
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

export const REGISTRY_SCHEMA = "piship-reference-sandbox-registry/v1";
const USER_ID = /^[a-z0-9][a-z0-9_.-]{0,40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
// PiShip stores 8 to 4096 visible ASCII characters and sends them as is.
const TOKEN = /^[\x21-\x7e]{8,4096}$/;
const MAX_UID = 4_294_967_294;

const digest = (value) => createHash("sha256").update(value, "utf8").digest();

/** An entry's key names, for a message that never repeats a value. */
const entryError = (id, problem) =>
  new Error(`SANDBOX_REGISTRY entry ${id}: ${problem}`);

/** The directories an entry's `roots` names, resolved; each must exist. */
function entryRoots(id, roots) {
  if (roots === undefined) return undefined;
  if (
    !Array.isArray(roots) ||
    roots.length === 0 ||
    roots.length > 16 ||
    !roots.every((root) => typeof root === "string" && isAbsolute(root))
  )
    throw entryError(id, "roots must be a short list of absolute paths");
  return roots.map((root) => {
    try {
      const real = realpathSync(root);
      if (!statSync(real).isDirectory() || real === "/") throw new Error();
      return real;
    } catch {
      throw entryError(id, "roots names a directory that does not exist");
    }
  });
}

/**
 * Read and check the registry. Throws without echoing any of its content.
 * Each entry is `{id, sha256, uid}` or `{id, sha256, unbound: true}`, and may
 * add `roots`.
 */
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
    const { uid, unbound } = entry;
    if (uid !== undefined && unbound !== undefined)
      throw entryError(entry.id, "uid and unbound are exclusive");
    if (unbound !== undefined && unbound !== true)
      throw entryError(entry.id, "unbound must be true, or absent");
    if (
      uid !== undefined &&
      !(Number.isInteger(uid) && uid >= 1 && uid <= MAX_UID)
    )
      throw entryError(entry.id, "uid must be a non-root user ID");
    if (uid === undefined && unbound === undefined)
      throw entryError(
        entry.id,
        "name the host user whose workspaces this key may mount (uid), or say unbound: true",
      );
    return {
      id: entry.id,
      hash: Buffer.from(entry.sha256, "hex"),
      // Absent for an unbound entry: any non-root owner.
      uid: unbound === true ? undefined : uid,
      unbound: unbound === true,
      roots: entryRoots(entry.id, entry.roots),
    };
  });
  if (keys.length === 0) throw new Error("SANDBOX_REGISTRY has no keys");
  return keys;
}

/**
 * The registry entry a request's Authorization header names, or undefined.
 * Missing, malformed, and unknown credentials are the same answer, and every
 * entry is compared, so the time taken does not say which entry (if any)
 * matched.
 */
export function authenticate(keys, header) {
  if (typeof header !== "string") return undefined;
  const match = /^Bearer ([\x21-\x7e]+)$/i.exec(header);
  const token = match?.[1];
  if (token === undefined || !TOKEN.test(token)) return undefined;
  const presented = digest(token);
  let user;
  for (const key of keys) if (timingSafeEqual(presented, key.hash)) user = key;
  return user;
}

export const sha256Hex = (value) => digest(value).toString("hex");
