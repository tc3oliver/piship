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
import { PiShipError, systemError } from "@piship/contracts";

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
/** One key's signature: the top-level form, or an entry of `signatures`. */
export interface SignatureEntry {
  readonly keyId: string;
  readonly algorithm: "ed25519";
  readonly signature: string;
}
export interface SignatureEnvelope extends SignatureEntry {
  readonly schema: typeof SIGNATURE_SCHEMA;
  /**
   * Every signature over the same bytes, the top-level one included. v0.7
   * verifiers ignore it and check the top-level signature only.
   */
  readonly signatures?: readonly SignatureEntry[];
}

/**
 * Produces Ed25519 signatures with one key. A PEM file implements it today;
 * a KMS or HSM adapter can later without changing how signatures verify.
 */
export interface Signer {
  readonly keyId: string;
  readonly algorithm: "ed25519";
  sign(data: Uint8Array): Promise<Uint8Array>;
}
/** A signer whose public key is known, so its output is checked before use. */
export interface KeyedSigner extends Signer {
  /** Base64 of the 44-byte Ed25519 SPKI DER. */
  readonly publicKey: string;
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

/** Whether a PEM private key needs a passphrase. */
export function isEncryptedPrivateKey(privateKeyPem: string): boolean {
  return /-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type: *4,ENCRYPTED/.test(
    privateKeyPem,
  );
}

// Node's own error is never forwarded: it can quote key material.
function ed25519PrivateKey(
  privateKeyPem: string,
  passphrase?: string,
): KeyObject {
  const encrypted = isEncryptedPrivateKey(privateKeyPem);
  if (encrypted && !passphrase)
    throw new PiShipError(
      "CREDENTIAL_REQUIRED",
      "Signing key is encrypted and no passphrase was given",
      {
        component: "signing",
        userAction:
          "Enter the passphrase at the prompt, or name an environment variable that holds it with --passphrase-env <NAME>",
      },
    );
  let key: KeyObject;
  try {
    key = encrypted
      ? createPrivateKey({ key: privateKeyPem, format: "pem", passphrase })
      : createPrivateKey(privateKeyPem);
  } catch {
    fail(
      encrypted
        ? "Signing key could not be decrypted: the passphrase is wrong or the key is damaged"
        : "Signing key is not a readable PEM private key",
    );
  }
  if (key.asymmetricKeyType !== "ed25519")
    fail(
      `Signing key must be Ed25519, not ${key.asymmetricKeyType ?? "unknown"}`,
    );
  return key;
}

/**
 * Create a new Ed25519 release signing key; with a passphrase its PKCS#8 PEM
 * is encrypted (AES-256-CBC).
 */
export function generateSigningKey(
  id: string,
  options: { readonly passphrase?: string } = {},
): SigningKeyPair {
  checkKeyId(id);
  if (options.passphrase === "")
    throw new PiShipError(
      "CONFIG_INVALID",
      "A signing key passphrase cannot be empty",
      { component: "signing" },
    );
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    id,
    privateKeyPem: privateKey
      .export(
        options.passphrase
          ? {
              type: "pkcs8",
              format: "pem",
              cipher: "aes-256-cbc",
              passphrase: options.passphrase,
            }
          : { type: "pkcs8", format: "pem" },
      )
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
 * but git-ignored, or inside one where `git add` would pick it up. When git
 * is missing or exits with an error, a `.git` entry in any ancestor counts
 * as a work tree whose ignore rules are unknown.
 */
export function privateKeyLocation(path: string): KeyLocation {
  const target = resolve(path);
  const parent = existsSync(dirname(target))
    ? realpathSync(dirname(target))
    : dirname(target);
  const file = join(parent, basename(target));
  const inside = git(["rev-parse", "--is-inside-work-tree"], parent);
  if (!inside.error && inside.status === 0) {
    const answer = inside.stdout.trim();
    if (answer === "false") return "outside";
    if (answer === "true") {
      const ignored = git(["check-ignore", "--quiet", "--", file], parent);
      return !ignored.error && ignored.status === 0
        ? "ignored"
        : "tracked-worktree";
    }
  }
  // Git is missing or could not answer (not a repository, dubious ownership,
  // GIT_CEILING_DIRECTORIES, ...): fail closed on any .git above the path.
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
  try {
    writeFileSync(path, privateKeyPem, { mode: 0o600, flag: "wx" });
  } catch (error) {
    throw (
      systemError(
        error,
        path,
        (error as NodeJS.ErrnoException).code === "EEXIST"
          ? "keygen never overwrites a key: write the new key to another file, or move the existing key away first if you mean to replace it"
          : undefined,
      ) ?? error
    );
  }
  return location;
}

/** The base64 SPKI DER public key for an Ed25519 PEM private key. */
export function publicKeyFromPrivate(
  privateKeyPem: string,
  passphrase?: string,
): string {
  return createPublicKey(ed25519PrivateKey(privateKeyPem, passphrase))
    .export({ type: "spki", format: "der" })
    .toString("base64");
}

/**
 * A signer backed by a plaintext or encrypted PKCS#8 PEM Ed25519 key. The
 * key is decrypted here, so a wrong passphrase fails before any work; only
 * the key object is kept, never the PEM text or the passphrase.
 */
export function pemSigner(options: {
  readonly keyId: string;
  readonly privateKeyPem: string;
  readonly passphrase?: string;
}): KeyedSigner {
  checkKeyId(options.keyId);
  const key = ed25519PrivateKey(options.privateKeyPem, options.passphrase);
  return {
    keyId: options.keyId,
    algorithm: "ed25519",
    publicKey: createPublicKey(key)
      .export({ type: "spki", format: "der" })
      .toString("base64"),
    sign: async (data) => new Uint8Array(sign(null, data, key)),
  };
}

/**
 * Sign `bytes` and verify the result with the signer's public key, so a
 * faulty signer is caught before anything is published. A signer's own error
 * is not forwarded unless it is a PiShipError: it may quote secrets.
 */
export async function signVerified(
  signer: KeyedSigner,
  bytes: Uint8Array,
): Promise<SignatureEntry> {
  checkKeyId(signer.keyId);
  if (signer.algorithm !== "ed25519") fail("Signer algorithm must be ed25519");
  const key = createPublicKey({
    key: publicKeyDer(signer.publicKey),
    format: "der",
    type: "spki",
  });
  let output: unknown;
  try {
    output = await signer.sign(bytes);
  } catch (error) {
    if (error instanceof PiShipError) throw error;
    fail(`Signer ${signer.keyId} failed to sign`);
  }
  const signature =
    output instanceof Uint8Array ? Buffer.from(output) : Buffer.alloc(0);
  if (signature.length !== 64 || !verify(null, bytes, key, signature))
    fail(
      `Signer ${signer.keyId} produced a signature that does not verify with its public key; refusing to publish it`,
    );
  return {
    keyId: signer.keyId,
    algorithm: "ed25519",
    signature: signature.toString("base64"),
  };
}

/**
 * A `piship-signature/v1` envelope over one or more signatures of the same
 * bytes. The top-level signature is `primaryKeyId`'s (default: the first
 * entry) and also appears in `signatures`. A single signature keeps the
 * legacy form without `signatures` unless `multi` asks for it.
 */
export function buildSignatureEnvelope(
  entries: readonly SignatureEntry[],
  options: { readonly primaryKeyId?: string; readonly multi?: boolean } = {},
): SignatureEnvelope {
  if (entries.length === 0) fail("A signature envelope needs a signature");
  const ids = new Set<string>();
  for (const entry of entries) {
    checkKeyId(entry.keyId);
    if (entry.algorithm !== "ed25519")
      fail("Signature algorithm must be ed25519");
    if (ids.has(entry.keyId))
      fail(`Signature key ${entry.keyId} appears more than once`);
    ids.add(entry.keyId);
  }
  const primary =
    options.primaryKeyId === undefined
      ? entries[0]
      : entries.find((entry) => entry.keyId === options.primaryKeyId);
  if (!primary)
    fail(`Primary signature key ${options.primaryKeyId} has no signature`);
  const top: SignatureEnvelope = {
    schema: SIGNATURE_SCHEMA,
    keyId: primary.keyId,
    algorithm: primary.algorithm,
    signature: primary.signature,
  };
  if (entries.length === 1 && !options.multi) return top;
  return {
    ...top,
    signatures: entries.map((entry) => ({
      keyId: entry.keyId,
      algorithm: entry.algorithm,
      signature: entry.signature,
    })),
  };
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

/** More signature entries than any root may list keys; larger is refused. */
const MAX_SIGNATURE_ENTRIES = 64;

/**
 * Verify a `piship-signature/v1` envelope against a role: `threshold`
 * distinct `trusted` keys must each contribute a valid signature over
 * `bytes`. Without `signatures` the top-level signature is the one entry;
 * with it, the top-level signature must equal one of its entries, and a key
 * id may appear only once. Entries of unknown keys, other algorithms, or
 * malformed or invalid signatures do not count, and one public key counts
 * once however many ids name it. Returns the ids of the keys that counted,
 * in envelope order; throws PiShipError("INTEGRITY_FAILED") otherwise.
 */
export function verifyThreshold(
  bytes: Uint8Array,
  envelope: unknown,
  trusted: readonly TrustedKey[],
  threshold: number,
): string[] {
  if (trusted.length === 0)
    fail("Signature cannot be verified: no trusted release keys configured");
  if (
    !Number.isSafeInteger(threshold) ||
    threshold < 1 ||
    threshold > trusted.length
  )
    fail(
      `Signature threshold ${threshold} is not between 1 and the ${trusted.length} trusted key(s)`,
    );
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope))
    fail("Signature envelope is not an object");
  const value = envelope as Record<string, unknown>;
  if (value.schema !== SIGNATURE_SCHEMA)
    fail(`Signature envelope schema must be ${SIGNATURE_SCHEMA}`);
  if (typeof value.keyId !== "string") fail("Signature envelope has no key id");
  if (value.algorithm !== "ed25519")
    fail("Signature algorithm must be ed25519");
  if (typeof value.signature !== "string")
    fail("Signature envelope has no signature");
  let entries: Record<string, unknown>[];
  if (value.signatures === undefined) entries = [value];
  else {
    if (!Array.isArray(value.signatures))
      fail("Signature envelope signatures is not a list");
    if (value.signatures.length > MAX_SIGNATURE_ENTRIES)
      fail(
        `Signature envelope lists more than ${MAX_SIGNATURE_ENTRIES} signatures`,
      );
    // A malformed entry does not count, but cannot hide a duplicate id.
    entries = value.signatures.filter(
      (entry): entry is Record<string, unknown> =>
        !!entry && typeof entry === "object" && !Array.isArray(entry),
    );
    const ids = entries
      .map((entry) => entry.keyId)
      .filter((id) => typeof id === "string");
    const duplicate = ids.find((id, index) => ids.indexOf(id) !== index);
    if (duplicate !== undefined)
      fail(`Signature key ${duplicate} appears more than once`);
    if (
      !entries.some(
        (entry) =>
          entry.keyId === value.keyId &&
          entry.algorithm === value.algorithm &&
          entry.signature === value.signature,
      )
    )
      fail(
        "Signature envelope's top-level signature is not one of its signatures",
      );
  }
  const counted: string[] = [];
  const keys = new Set<string>();
  const invalid: string[] = [];
  for (const entry of entries) {
    if (typeof entry.keyId !== "string" || entry.algorithm !== "ed25519")
      continue;
    const candidates = trusted.filter((key) => key.id === entry.keyId);
    if (candidates.length === 0) continue;
    let signature: Buffer;
    try {
      signature = strictBase64(entry.signature, "Signature");
    } catch {
      invalid.push(entry.keyId);
      continue;
    }
    const match =
      signature.length === 64
        ? candidates.find((candidate) =>
            verify(
              null,
              bytes,
              createPublicKey({
                key: publicKeyDer(candidate.publicKey),
                format: "der",
                type: "spki",
              }),
              signature,
            ),
          )
        : undefined;
    if (!match) {
      invalid.push(entry.keyId);
      continue;
    }
    if (keys.has(match.publicKey)) continue;
    keys.add(match.publicKey);
    counted.push(entry.keyId);
  }
  if (counted.length >= threshold) return counted;
  const signers = entries
    .map((entry) => entry.keyId)
    .filter((id) => typeof id === "string");
  const ids = [...new Set(trusted.map((key) => key.id))].join(", ");
  // The single-signature messages verifySignature has always given.
  if (threshold === 1 && entries.length === 1) {
    if (invalid.length)
      fail(`Signature does not verify with trusted key ${invalid[0]}`);
    fail(
      `Signature key ${String(signers[0])} is not trusted; trusted keys: ${ids}`,
    );
  }
  return fail(
    `Signatures meet ${counted.length} of the ${threshold} required from trusted keys ${ids} (signed by ${signers.join(", ") || "no key"}${invalid.length ? `; does not verify with trusted key ${invalid.join(", ")}` : ""})`,
  );
}

/** "sha256:<hex>" of the public key's DER bytes. */
export function keyFingerprint(publicKey: string): string {
  return `sha256:${createHash("sha256").update(publicKeyDer(publicKey)).digest("hex")}`;
}
