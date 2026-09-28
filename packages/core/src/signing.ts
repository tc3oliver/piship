import {
  type KeyObject,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
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
