import { spawnSync } from "node:child_process";
import {
  type KeyObject,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { existsSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";

/** A release key a distribution trusts: base64 of the 44-byte Ed25519 SPKI DER. */
export interface TrustedKey {
  readonly id: string;
  readonly publicKey: string;
}
export interface SigningKeyPair {
  readonly id: string;
  readonly privateKeyPem: string;
  readonly publicKey: string;
}
export const SIGNATURE_SCHEMA = "piship-signature/v1";
export interface SignatureEnvelope {
  readonly schema: typeof SIGNATURE_SCHEMA;
  readonly keyId: string;
  readonly algorithm: "ed25519";
  readonly signature: string;
}

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const KEY_ID = /^[a-z0-9][a-z0-9.-]*$/;

function fail(message: string): never {
  throw new PiShipError("INTEGRITY_FAILED", message, { component: "signing" });
}

function checkKeyId(id: string): void {
  if (typeof id !== "string" || !KEY_ID.test(id))
    fail(
      "Signing key id must be lowercase letters, digits, dots, or hyphens and start with a letter or digit",
    );
}

function strictBase64(value: unknown, label: string): Buffer {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  )
    fail(`${label} is not valid base64`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) fail(`${label} is not valid base64`);
  return bytes;
}

function publicKeyDer(publicKey: string): Buffer {
  const der = strictBase64(publicKey, "Ed25519 public key");
  if (der.length !== 44 || !der.subarray(0, 12).equals(SPKI_PREFIX))
    fail("Public key is not a base64 Ed25519 SPKI key (44 bytes)");
  return der;
}

function ed25519PrivateKey(privateKeyPem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    fail("Signing key is not a readable PEM private key");
  }
  if (key.asymmetricKeyType !== "ed25519")
    fail(
      `Signing key must be Ed25519, not ${key.asymmetricKeyType ?? "unknown"}`,
    );
  return key;
}

/** Create a new Ed25519 release signing key. */
export function generateSigningKey(id: string): SigningKeyPair {
  checkKeyId(id);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    id,
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
    publicKey: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64"),
  };
}

/** Where a private key would land relative to a git work tree. */
export type KeyLocation = "outside" | "ignored" | "tracked-worktree";

function git(args: readonly string[], cwd: string) {
  const env = { ...process.env };
  // Answer for the directory itself, not an inherited repository.
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"])
    delete env[name];
  return spawnSync("git", args, {
    cwd,
    env,
    encoding: "utf8",
    shell: false,
    timeout: 10_000,
    windowsHide: true,
  });
}

/**
 * Classify a private-key output path: outside any git work tree, inside one
 * but git-ignored, or inside one where `git add` would pick it up. Without a
 * usable git, a `.git` entry in any ancestor counts as a work tree whose
 * ignore rules are unknown.
 */
export function privateKeyLocation(path: string): KeyLocation {
  const target = resolve(path);
  const parent = existsSync(dirname(target))
    ? realpathSync(dirname(target))
    : dirname(target);
  const file = join(parent, basename(target));
  const inside = git(["rev-parse", "--is-inside-work-tree"], parent);
  if (!inside.error) {
    if (inside.status !== 0 || inside.stdout.trim() !== "true")
      return "outside";
    const ignored = git(["check-ignore", "--quiet", "--", file], parent);
    return !ignored.error && ignored.status === 0
      ? "ignored"
      : "tracked-worktree";
  }
  for (let dir = parent; ; dir = dirname(dir)) {
    if (existsSync(join(dir, ".git"))) return "tracked-worktree";
    if (dirname(dir) === dir) return "outside";
  }
}

/**
 * Write a new private key (mode 0600, never overwriting). A path inside a git
 * work tree that is not git-ignored is refused unless `forceInWorktree`, so
 * the key is not committed by accident.
 */
export function writePrivateKey(
  path: string,
  privateKeyPem: string,
  options: { readonly forceInWorktree?: boolean } = {},
): KeyLocation {
  const location = privateKeyLocation(path);
  if (location === "tracked-worktree" && !options.forceInWorktree)
    throw new PiShipError(
      "CONFIG_INVALID",
      `Refusing to write a private key to ${path}: it is inside a git work tree and not git-ignored`,
      {
        component: "signing",
        userAction:
          "Write the key outside the repository, add the path to .gitignore, or pass --force-in-worktree",
      },
    );
  writeFileSync(path, privateKeyPem, { mode: 0o600, flag: "wx" });
  return location;
}

/** The base64 SPKI DER public key for an Ed25519 PEM private key. */
export function publicKeyFromPrivate(privateKeyPem: string): string {
  return createPublicKey(ed25519PrivateKey(privateKeyPem))
    .export({ type: "spki", format: "der" })
    .toString("base64");
}

/** Sign bytes with an Ed25519 private key and wrap the result in an envelope. */
export function signBytes(
  bytes: Uint8Array,
  privateKeyPem: string,
  keyId: string,
): SignatureEnvelope {
  checkKeyId(keyId);
  const key = ed25519PrivateKey(privateKeyPem);
  return {
    schema: SIGNATURE_SCHEMA,
    keyId,
    algorithm: "ed25519",
    signature: sign(null, bytes, key).toString("base64"),
  };
}

/** Returns the key id that verified; throws PiShipError("INTEGRITY_FAILED") otherwise. */
export function verifySignature(
  bytes: Uint8Array,
  envelope: unknown,
  trusted: readonly TrustedKey[],
): string {
  if (trusted.length === 0)
    fail("Signature cannot be verified: no trusted release keys configured");
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope))
    fail("Signature envelope is not an object");
  const value = envelope as Record<string, unknown>;
  if (value.schema !== SIGNATURE_SCHEMA)
    fail(`Signature envelope schema must be ${SIGNATURE_SCHEMA}`);
  if (value.algorithm !== "ed25519")
    fail("Signature algorithm must be ed25519");
  const ids = trusted.map((key) => key.id).join(", ");
  if (typeof value.keyId !== "string") fail("Signature envelope has no key id");
  const candidates = trusted.filter((key) => key.id === value.keyId);
  if (candidates.length === 0)
    fail(`Signature key ${value.keyId} is not trusted; trusted keys: ${ids}`);
  const signature = strictBase64(value.signature, "Signature");
  if (signature.length !== 64) fail("Signature must be 64 bytes");
  for (const candidate of candidates) {
    const key = createPublicKey({
      key: publicKeyDer(candidate.publicKey),
      format: "der",
      type: "spki",
    });
    if (verify(null, bytes, key, signature)) return candidate.id;
  }
  return fail(`Signature does not verify with trusted key ${value.keyId}`);
}

/** "sha256:<hex>" of the public key's DER bytes. */
export function keyFingerprint(publicKey: string): string {
  return `sha256:${createHash("sha256").update(publicKeyDer(publicKey)).digest("hex")}`;
}
