import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  generateSigningKey,
  keyFingerprint,
  privateKeyLocation,
  publicKeyFromPrivate,
  signBytes,
  verifySignature,
  writePrivateKey,
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

describe("private key location", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0))
      rmSync(root, { recursive: true, force: true });
  });
  const repo = () => {
    const root = mkdtempSync(join(tmpdir(), "piship-keygen-"));
    roots.push(root);
    const init = spawnSync("git", ["init", "--quiet", root]);
    if (init.status !== 0) throw new Error("git init failed");
    writeFileSync(join(root, ".gitignore"), "secret/\n");
    mkdirSync(join(root, "secret"));
    mkdirSync(join(root, "src"));
    return root;
  };
  const pem = generateSigningKey("acme-release-2026").privateKeyPem;

  it("refuses a key inside a work tree unless it is ignored or forced", () => {
    const root = repo();
    expect(() => writePrivateKey(join(root, "src", "k.pem"), pem)).toThrow(
      /inside a git work tree and not git-ignored/,
    );
    expect(existsSync(join(root, "src", "k.pem"))).toBe(false);
    expect(writePrivateKey(join(root, "secret", "k.pem"), pem)).toBe("ignored");
    expect(
      writePrivateKey(join(root, "src", "k.pem"), pem, {
        forceInWorktree: true,
      }),
    ).toBe("tracked-worktree");
    if (process.platform !== "win32")
      expect(statSync(join(root, "src", "k.pem")).mode & 0o777).toBe(0o600);
    // It still never overwrites.
    expect(() => writePrivateKey(join(root, "secret", "k.pem"), pem)).toThrow(
      /EEXIST/,
    );
    const outside = mkdtempSync(join(tmpdir(), "piship-keygen-out-"));
    roots.push(outside);
    expect(privateKeyLocation(join(outside, "k.pem"))).toBe("outside");
  });

  it("falls back to finding .git when git is unavailable", () => {
    const root = repo();
    const path = process.env.PATH;
    process.env.PATH = "";
    try {
      expect(privateKeyLocation(join(root, "secret", "k.pem"))).toBe(
        "tracked-worktree",
      );
      const outside = mkdtempSync(join(tmpdir(), "piship-keygen-out-"));
      roots.push(outside);
      expect(privateKeyLocation(join(outside, "k.pem"))).toBe("outside");
    } finally {
      process.env.PATH = path;
    }
  });
});
