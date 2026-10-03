// The Signer boundary: plaintext and encrypted PEM keys, a signature checked
// before it is used, the v1 envelope with additive `signatures`, and a
// passphrase that never reaches an error, a log, or a command line.
import { inspect } from "node:util";
import { PiShipError, formatError } from "@piship/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readSigningPassphrase } from "./signing-passphrase.js";
import {
  type KeyedSigner,
  buildSignatureEnvelope,
  generateSigningKey,
  isEncryptedPrivateKey,
  pemSigner,
  publicKeyFromPrivate,
  signBytes,
  signVerified,
  verifySignature,
} from "./signing.js";

const bytes = new TextEncoder().encode('{"channel":"stable"}\n');
const PASSPHRASE = "correct-horse-passphrase-sentinel-0451";
const plain = generateSigningKey("acme-release-2026");
const encrypted = generateSigningKey("acme-release-2027", {
  passphrase: PASSPHRASE,
});
const trusted = [
  { id: plain.id, publicKey: plain.publicKey },
  { id: encrypted.id, publicKey: encrypted.publicKey },
];

/** Every way an error could be shown: message, stack, JSON, inspection. */
function surfaces(error: unknown): string {
  return [
    formatError(error),
    error instanceof Error ? `${error.message}\n${error.stack}` : "",
    JSON.stringify(error),
    inspect(error, { depth: 5 }),
  ].join("\n");
}
/** The base64 body lines of a PEM, any of which would leak key material. */
const pemLines = (pem: string) =>
  pem.split("\n").filter((line) => line && !line.startsWith("-----"));

function thrown(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("expected a throw");
}
async function rejected(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected a rejection");
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PEM signer", () => {
  it("keeps plaintext PKCS#8 PEM keys working, matching signBytes", async () => {
    expect(isEncryptedPrivateKey(plain.privateKeyPem)).toBe(false);
    const signer = pemSigner({
      keyId: plain.id,
      privateKeyPem: plain.privateKeyPem,
    });
    expect(signer).toMatchObject({
      keyId: plain.id,
      algorithm: "ed25519",
      publicKey: plain.publicKey,
    });
    const entry = await signVerified(signer, bytes);
    const envelope = buildSignatureEnvelope([entry]);
    // Ed25519 is deterministic: the Signer path writes the legacy envelope.
    expect(envelope).toEqual(signBytes(bytes, plain.privateKeyPem, plain.id));
    expect(verifySignature(bytes, envelope, trusted)).toBe(plain.id);
  });

  it("signs with an encrypted PKCS#8 PEM key and its passphrase", async () => {
    expect(encrypted.privateKeyPem).toMatch(
      /^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/,
    );
    expect(isEncryptedPrivateKey(encrypted.privateKeyPem)).toBe(true);
    expect(publicKeyFromPrivate(encrypted.privateKeyPem, PASSPHRASE)).toBe(
      encrypted.publicKey,
    );
    const signer = pemSigner({
      keyId: encrypted.id,
      privateKeyPem: encrypted.privateKeyPem,
      passphrase: PASSPHRASE,
    });
    expect(signer.publicKey).toBe(encrypted.publicKey);
    const envelope = buildSignatureEnvelope([
      await signVerified(signer, bytes),
    ]);
    expect(verifySignature(bytes, envelope, trusted)).toBe(encrypted.id);
  });

  it("fails closed on a missing or wrong passphrase", () => {
    const missing = thrown(() =>
      pemSigner({
        keyId: encrypted.id,
        privateKeyPem: encrypted.privateKeyPem,
      }),
    );
    expect(missing).toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    expect((missing as Error).message).toMatch(/encrypted/);
    for (const passphrase of ["wrong-passphrase", `${PASSPHRASE}x`]) {
      const wrong = thrown(() =>
        pemSigner({
          keyId: encrypted.id,
          privateKeyPem: encrypted.privateKeyPem,
          passphrase,
        }),
      );
      expect(wrong).toBeInstanceOf(PiShipError);
      expect(wrong).toMatchObject({ code: "INTEGRITY_FAILED" });
      expect((wrong as Error).message).toBe(
        "Signing key could not be decrypted: the passphrase is wrong or the key is damaged",
      );
    }
    expect(() =>
      signBytes(bytes, encrypted.privateKeyPem, encrypted.id),
    ).toThrow(expect.objectContaining({ code: "CREDENTIAL_REQUIRED" }));
  });

  it("never puts the passphrase or key material in errors or output", async () => {
    const written: string[] = [];
    const capture = (chunk: unknown) => {
      written.push(String(chunk));
      return true;
    };
    vi.spyOn(process.stdout, "write").mockImplementation(capture);
    vi.spyOn(process.stderr, "write").mockImplementation(capture);
    for (const method of ["log", "info", "warn", "error", "debug"] as const)
      vi.spyOn(console, method).mockImplementation((...args) => {
        written.push(args.map(String).join(" "));
      });
    const wrongPassphrase = `${PASSPHRASE}-wrong`;
    const damaged = encrypted.privateKeyPem.replace(
      pemLines(encrypted.privateKeyPem)[1] as string,
      "A".repeat(64),
    );
    const errors = [
      thrown(() =>
        pemSigner({
          keyId: encrypted.id,
          privateKeyPem: encrypted.privateKeyPem,
          passphrase: wrongPassphrase,
        }),
      ),
      thrown(() =>
        pemSigner({
          keyId: encrypted.id,
          privateKeyPem: damaged,
          passphrase: PASSPHRASE,
        }),
      ),
      thrown(() =>
        pemSigner({
          keyId: plain.id,
          privateKeyPem: plain.privateKeyPem.replace("PRIVATE", "PUBLIC"),
        }),
      ),
      await rejected(
        signVerified(
          {
            keyId: plain.id,
            algorithm: "ed25519",
            publicKey: plain.publicKey,
            sign: async () => {
              throw new Error(
                `HSM refused: passphrase ${PASSPHRASE} key ${plain.privateKeyPem}`,
              );
            },
          },
          bytes,
        ),
      ),
    ];
    const text = `${errors.map(surfaces).join("\n")}\n${written.join("\n")}`;
    for (const secret of [
      PASSPHRASE,
      wrongPassphrase,
      ...pemLines(encrypted.privateKeyPem),
      ...pemLines(plain.privateKeyPem),
    ])
      expect(text).not.toContain(secret);
    expect(errors.map((error) => (error as PiShipError).code)).toEqual([
      "INTEGRITY_FAILED",
      "INTEGRITY_FAILED",
      "INTEGRITY_FAILED",
      "INTEGRITY_FAILED",
    ]);
    // Inspecting a signer shows no key either.
    const signer = pemSigner({
      keyId: encrypted.id,
      privateKeyPem: encrypted.privateKeyPem,
      passphrase: PASSPHRASE,
    });
    const shown = `${inspect(signer, { depth: 5 })}${JSON.stringify(signer)}`;
    expect(shown).not.toContain(PASSPHRASE);
    for (const line of pemLines(encrypted.privateKeyPem))
      expect(shown).not.toContain(line);
  });
});

describe("signature self-verification", () => {
  const good = pemSigner({
    keyId: plain.id,
    privateKeyPem: plain.privateKeyPem,
  });
  const faulty = (output: () => unknown): KeyedSigner => ({
    keyId: plain.id,
    algorithm: "ed25519",
    publicKey: plain.publicKey,
    sign: async () => output() as Uint8Array,
  });

  it("rejects a signature that does not verify with the signer's key", async () => {
    const other = pemSigner({
      keyId: "someone-else",
      privateKeyPem: generateSigningKey("someone-else").privateKeyPem,
    });
    for (const signer of [
      faulty(() => new Uint8Array(64)),
      faulty(() => new Uint8Array(63)),
      faulty(() => "not bytes"),
      faulty(() => undefined),
      // A key that does not match the public key the signer claims.
      { ...other, keyId: plain.id, publicKey: plain.publicKey },
      // A good signature over different bytes.
      faulty(() =>
        Buffer.from(
          signBytes(new Uint8Array([1]), plain.privateKeyPem, plain.id)
            .signature,
          "base64",
        ),
      ),
    ]) {
      const error = await rejected(signVerified(signer, bytes));
      expect(error).toMatchObject({ code: "INTEGRITY_FAILED" });
      expect((error as Error).message).toMatch(
        /does not verify with its public key; refusing to publish it/,
      );
    }
    await expect(signVerified(good, bytes)).resolves.toMatchObject({
      keyId: plain.id,
    });
  });

  it("forwards a signer's PiShipError but not other errors", async () => {
    const own = new PiShipError("CREDENTIAL_REQUIRED", "token expired");
    await expect(
      signVerified(
        faulty(() => {
          throw own;
        }),
        bytes,
      ),
    ).rejects.toBe(own);
    const error = await rejected(
      signVerified(
        faulty(() => {
          throw new Error("raw detail");
        }),
        bytes,
      ),
    );
    expect((error as Error).message).toBe(`Signer ${plain.id} failed to sign`);
  });

  it("refuses a malformed signer", async () => {
    await expect(
      signVerified({ ...good, keyId: "Bad Id" }, bytes),
    ).rejects.toThrow(/key id/);
    await expect(
      signVerified(
        { ...good, algorithm: "rsa" } as unknown as KeyedSigner,
        bytes,
      ),
    ).rejects.toThrow(/ed25519/);
    await expect(
      signVerified({ ...good, publicKey: "AAAA" }, bytes),
    ).rejects.toThrow(/Ed25519 SPKI/);
  });
});

describe("signature envelope", () => {
  const sign = (key: typeof plain, passphrase?: string) =>
    signVerified(
      pemSigner({
        keyId: key.id,
        privateKeyPem: key.privateKeyPem,
        ...(passphrase ? { passphrase } : {}),
      }),
      bytes,
    );

  it("keeps the legacy single form and adds signatures[] for several", async () => {
    const first = await sign(plain);
    const second = await sign(encrypted, PASSPHRASE);
    expect(buildSignatureEnvelope([first])).toEqual({
      schema: "piship-signature/v1",
      ...first,
    });
    expect(buildSignatureEnvelope([first], { multi: true })).toEqual({
      schema: "piship-signature/v1",
      ...first,
      signatures: [first],
    });
    const both = buildSignatureEnvelope([first, second], {
      primaryKeyId: encrypted.id,
    });
    expect(both).toEqual({
      schema: "piship-signature/v1",
      ...second,
      signatures: [first, second],
    });
    // The top-level signature equals one entry, and a v0.7 verifier that
    // reads only the top level still accepts it.
    expect(both.signatures).toContainEqual({
      keyId: both.keyId,
      algorithm: both.algorithm,
      signature: both.signature,
    });
    expect(verifySignature(bytes, both, trusted)).toBe(encrypted.id);
    expect(buildSignatureEnvelope([first, second]).keyId).toBe(plain.id);
  });

  it("refuses an empty, duplicated, or unmatched set", async () => {
    const first = await sign(plain);
    expect(() => buildSignatureEnvelope([])).toThrow(/needs a signature/);
    expect(() => buildSignatureEnvelope([first, first])).toThrow(
      /appears more than once/,
    );
    expect(() =>
      buildSignatureEnvelope([first], { primaryKeyId: "missing" }),
    ).toThrow(/Primary signature key missing has no signature/);
    expect(() =>
      buildSignatureEnvelope([{ ...first, algorithm: "rsa" as "ed25519" }]),
    ).toThrow(/ed25519/);
  });
});

describe("signing passphrase input", () => {
  const read = (...answers: string[]) =>
    vi.fn(async () => answers.shift() ?? "");

  it("reads a named environment variable, never echoing the name or value", async () => {
    const env = { PISHIP_SIGNING_PASSPHRASE: PASSPHRASE };
    await expect(
      readSigningPassphrase(
        "Passphrase",
        { env: "PISHIP_SIGNING_PASSPHRASE" },
        { env, isTTY: false },
      ),
    ).resolves.toBe(PASSPHRASE);
    const unset = await rejected(
      readSigningPassphrase(
        "Passphrase",
        { env: "PISHIP_UNSET_PASSPHRASE" },
        { env, isTTY: false },
      ),
    );
    expect(unset).toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    expect(surfaces(unset)).not.toContain("PISHIP_UNSET_PASSPHRASE");
    // A passphrase passed where the variable name belongs is not echoed.
    const value = await rejected(
      readSigningPassphrase("Passphrase", { env: "s3cret pass!" }, { env }),
    );
    expect(value).toMatchObject({ code: "CONFIG_INVALID" });
    expect(surfaces(value)).not.toContain("s3cret pass!");
  });

  it("reads standard input or a hidden prompt, confirming a new passphrase", async () => {
    await expect(
      readSigningPassphrase(
        "Passphrase",
        { stdin: true },
        { isTTY: false, read: read(PASSPHRASE) },
      ),
    ).resolves.toBe(PASSPHRASE);
    await expect(
      readSigningPassphrase(
        "Passphrase",
        { confirm: true },
        { isTTY: true, read: read(PASSPHRASE, PASSPHRASE) },
      ),
    ).resolves.toBe(PASSPHRASE);
    const mismatch = await rejected(
      readSigningPassphrase(
        "Passphrase",
        { confirm: true },
        { isTTY: true, read: read(PASSPHRASE, "other") },
      ),
    );
    expect((mismatch as Error).message).toBe("The passphrases do not match");
    await expect(
      readSigningPassphrase("Passphrase", {}, { isTTY: true, read: read("") }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
  });

  it("fails closed without a terminal or a named channel", async () => {
    const prompt = read(PASSPHRASE);
    await expect(
      readSigningPassphrase("Passphrase", {}, { isTTY: false, read: prompt }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    expect(prompt).not.toHaveBeenCalled();
    await expect(
      readSigningPassphrase("Passphrase", { env: "X", stdin: true }),
    ).rejects.toThrow(/Choose one passphrase source/);
  });
});
