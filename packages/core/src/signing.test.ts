import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  generateSigningKey,
  keyFingerprint,
  publicKeyFromPrivate,
  signBytes,
  verifySignature,
} from "./signing.js";

const bytes = new TextEncoder().encode('{"channel":"stable"}\n');

describe("signing", () => {
  const key = generateSigningKey("acme-release-2026");
  const trusted = [{ id: key.id, publicKey: key.publicKey }];

  it("round trips with a 44-byte SPKI public key", () => {
    const der = Buffer.from(key.publicKey, "base64");
    expect(der).toHaveLength(44);
    expect(der.subarray(0, 12).toString("hex")).toBe(
      "302a300506032b6570032100",
    );
    expect(publicKeyFromPrivate(key.privateKeyPem)).toBe(key.publicKey);
    const envelope = signBytes(bytes, key.privateKeyPem, key.id);
    expect(envelope).toMatchObject({
      schema: "piship-signature/v1",
      keyId: key.id,
      algorithm: "ed25519",
    });
    expect(verifySignature(bytes, envelope, trusted)).toBe(key.id);
    expect(keyFingerprint(key.publicKey)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects tampered bytes and the wrong key", () => {
    const envelope = signBytes(bytes, key.privateKeyPem, key.id);
    const tampered = Uint8Array.from(bytes);
    tampered[0] ^= 1;
    expect(() => verifySignature(tampered, envelope, trusted)).toThrow(
      /does not verify/,
    );
    const other = generateSigningKey("acme-release-2026");
    expect(() =>
      verifySignature(bytes, envelope, [
        { id: key.id, publicKey: other.publicKey },
      ]),
    ).toThrow(/does not verify/);
  });

  it("names trusted ids for an unknown key id", () => {
    const envelope = signBytes(bytes, key.privateKeyPem, "rogue");
    expect(() => verifySignature(bytes, envelope, trusted)).toThrow(
      "Signature key rogue is not trusted; trusted keys: acme-release-2026",
    );
    expect(() => verifySignature(bytes, envelope, [])).toThrow(
      /no trusted release keys configured/,
    );
  });

  it("rejects wrong algorithms and malformed envelopes", () => {
    const envelope = signBytes(bytes, key.privateKeyPem, key.id);
    for (const bad of [
      null,
      "signature",
      [],
      { ...envelope, algorithm: "rsa" },
      { ...envelope, schema: "other/v1" },
      { ...envelope, keyId: undefined },
      { ...envelope, signature: "not base64!" },
      { ...envelope, signature: "AAAA" },
    ])
      expect(() => verifySignature(bytes, bad, trusted)).toThrow(
        expect.objectContaining({ code: "INTEGRITY_FAILED" }),
      );
    expect(() =>
      verifySignature(bytes, envelope, [{ id: key.id, publicKey: "AAAA" }]),
    ).toThrow(/Ed25519 SPKI/);
  });

  it("rejects non-Ed25519 private keys and invalid key ids", () => {
    const ecdsa = generateKeyPairSync("ec", { namedCurve: "P-256" })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    expect(() => signBytes(bytes, ecdsa, "acme")).toThrow(/must be Ed25519/);
    expect(() => publicKeyFromPrivate(ecdsa)).toThrow(/must be Ed25519/);
    expect(() => signBytes(bytes, "nope", "acme")).toThrow(/PEM/);
    expect(() => generateSigningKey("Bad Id")).toThrow(/key id/);
  });
});
