// Update trust: threshold signatures, hosted root metadata, the sequential
// root refresh, the installation trust state, and the owner's root tooling.
// No release is built, so these run on every target; the update-path tests
// that install and activate releases are in lifecycle.test.ts.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { UpdateRoot } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  advanceTrustState,
  initialTrustState,
  LEGACY_ROOT_EXPIRES,
  readTrustState,
  trustStatePath,
  writeTrustState,
} from "./install/trust-state.js";
import {
  hostedRootText,
  initTrustRoot,
  MAX_ROOT_BYTES,
  MAX_ROOT_TRANSITIONS,
  nextTrustRoot,
  readChannel,
  refreshRoot,
  rootDigest,
} from "./release/index.js";
import {
  buildSignatureEnvelope,
  generateSigningKey,
  type KeyedSigner,
  keyFingerprint,
  pemSigner,
  type SignatureEntry,
  type SigningKeyPair,
  signBytes,
  signVerified,
  verifySignature,
  verifyThreshold,
} from "./signing.js";

const ROOT_A = generateSigningKey("root-a");
const ROOT_B = generateSigningKey("root-b");
const CHANNEL_A = generateSigningKey("channel-a");
const CHANNEL_B = generateSigningKey("channel-b");
const STRANGER = generateSigningKey("stranger");
const ID = "acmepi";
const NOW = new Date("2026-10-01T00:00:00Z");

const pub = (key: SigningKeyPair) => ({ id: key.id, publicKey: key.publicKey });
const signer = (key: SigningKeyPair): KeyedSigner =>
  pemSigner({ keyId: key.id, privateKeyPem: key.privateKeyPem });
const entry = async (key: SigningKeyPair, bytes: Uint8Array) =>
  signVerified(signer(key), bytes);

function root(
  version: number,
  rootKeys: readonly SigningKeyPair[],
  channelKeys: readonly SigningKeyPair[],
  options: {
    expires?: string;
    rootThreshold?: number;
    channelThreshold?: number;
  } = {},
): UpdateRoot {
  const keys = [...rootKeys, ...channelKeys].filter(
    (key, index, all) =>
      all.findIndex((other) => other.id === key.id) === index,
  );
  return {
    version,
    expires: options.expires ?? "2099-01-01T00:00:00Z",
    keys: keys.map(pub),
    roles: {
      root: {
        keyIds: rootKeys.map((key) => key.id),
        threshold: options.rootThreshold ?? 1,
      },
      channel: {
        keyIds: channelKeys.map((key) => key.id),
        threshold: options.channelThreshold ?? 1,
      },
    },
  };
}

const roots: string[] = [];
let savedHome: string | undefined;
beforeEach(() => {
  savedHome = process.env.PISHIP_INSTALL_HOME;
  process.env.PISHIP_INSTALL_HOME = join(temp(), "install");
});
afterEach(() => {
  if (savedHome === undefined) delete process.env.PISHIP_INSTALL_HOME;
  else process.env.PISHIP_INSTALL_HOME = savedHome;
  for (const dir of roots.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-update-trust-"));
  roots.push(dir);
  return dir;
}

/** Publish `root/<version>.json` and its signature as `trust-root next` lays them out. */
async function publishRoot(
  dir: string,
  body: UpdateRoot,
  signers: readonly SigningKeyPair[],
  distribution = ID,
): Promise<Buffer> {
  const text = Buffer.from(hostedRootText(distribution, body));
  const entries: SignatureEntry[] = [];
  for (const key of signers) entries.push(await entry(key, text));
  const path = join(dir, "root", `${body.version}.json`);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  writeFileSync(`${path}.sig`, JSON.stringify(buildSignatureEnvelope(entries)));
  return text;
}

function refresh(source: string, current: UpdateRoot, fetcher?: typeof fetch) {
  const accepted: number[] = [];
  return refreshRoot({
    source,
    distribution: ID,
    current,
    accept: (next) => accepted.push(next.version),
    ...(fetcher ? { fetcher } : {}),
  }).then((result) => ({ ...result, accepted }));
}

// ------------------------------------------------------------- signatures

describe("threshold signatures", () => {
  const bytes = Buffer.from("channel metadata\n");

  it("accepts a legacy single signature", () => {
    const envelope = signBytes(bytes, CHANNEL_A.privateKeyPem, CHANNEL_A.id);
    expect(verifyThreshold(bytes, envelope, [pub(CHANNEL_A)], 1)).toEqual([
      CHANNEL_A.id,
    ]);
    // The single-signature verifier existing callers use still agrees.
    expect(verifySignature(bytes, envelope, [pub(CHANNEL_A)])).toBe(
      CHANNEL_A.id,
    );
  });

  it("counts distinct valid trusted signatures toward the threshold", async () => {
    const envelope = buildSignatureEnvelope([
      await entry(CHANNEL_A, bytes),
      await entry(CHANNEL_B, bytes),
    ]);
    const trusted = [pub(CHANNEL_A), pub(CHANNEL_B)];
    expect(verifyThreshold(bytes, envelope, trusted, 2)).toEqual([
      CHANNEL_A.id,
      CHANNEL_B.id,
    ]);
    // One trusted key is not two.
    expect(() =>
      verifyThreshold(
        bytes,
        buildSignatureEnvelope([entrySync(CHANNEL_A, bytes)], { multi: true }),
        trusted,
        2,
      ),
    ).toThrow(/meet 1 of the 2 required/);
    // A threshold above the trusted key count is a configuration error.
    expect(() => verifyThreshold(bytes, envelope, trusted, 3)).toThrow(
      /threshold 3 is not between 1 and the 2/,
    );
  });

  it("requires the top-level signature to be one of signatures[]", async () => {
    const a = await entry(CHANNEL_A, bytes);
    const b = await entry(CHANNEL_B, bytes);
    const envelope = { ...buildSignatureEnvelope([a]), signatures: [b] };
    expect(() =>
      verifyThreshold(bytes, envelope, [pub(CHANNEL_A), pub(CHANNEL_B)], 1),
    ).toThrow(/top-level signature is not one of its signatures/);
    // Same key id, different signature bytes: still not the same entry.
    const other = await entry(CHANNEL_A, Buffer.from("other bytes"));
    expect(() =>
      verifyThreshold(
        bytes,
        { ...buildSignatureEnvelope([a]), signatures: [other, b] },
        [pub(CHANNEL_A), pub(CHANNEL_B)],
        1,
      ),
    ).toThrow(/top-level signature is not one of its signatures/);
  });

  it("rejects duplicate key ids", async () => {
    const a = await entry(CHANNEL_A, bytes);
    const envelope = { ...buildSignatureEnvelope([a]), signatures: [a, a] };
    expect(() => verifyThreshold(bytes, envelope, [pub(CHANNEL_A)], 1)).toThrow(
      /Signature key channel-a appears more than once/,
    );
  });

  it("does not count unknown, malformed, or invalid signatures", async () => {
    const a = await entry(CHANNEL_A, bytes);
    const stranger = await entry(STRANGER, bytes);
    const forged = {
      keyId: CHANNEL_B.id,
      algorithm: "ed25519" as const,
      signature: (await entry(STRANGER, bytes)).signature,
    };
    const envelope = {
      ...buildSignatureEnvelope([a]),
      signatures: [
        a,
        stranger,
        forged,
        { keyId: "channel-c", algorithm: "ed25519", signature: "not base64!" },
        { keyId: "channel-d", algorithm: "rsa", signature: a.signature },
        "not an entry",
        null,
      ],
    };
    const trusted = [pub(CHANNEL_A), pub(CHANNEL_B)];
    expect(verifyThreshold(bytes, envelope, trusted, 1)).toEqual([
      CHANNEL_A.id,
    ]);
    expect(() => verifyThreshold(bytes, envelope, trusted, 2)).toThrow(
      /meet 1 of the 2 required .*does not verify with trusted key channel-b/,
    );
    // A key listed under two ids counts once.
    expect(() =>
      verifyThreshold(
        bytes,
        buildSignatureEnvelope([a, { ...a, keyId: "alias" }]),
        [pub(CHANNEL_A), { id: "alias", publicKey: CHANNEL_A.publicKey }],
        2,
      ),
    ).toThrow(/meet 1 of the 2 required/);
  });

  // Bytes and envelope exactly as PiShip v0.7 published them: a legacy
  // top-level signature, no signatures[]. The key is fixed, not secret.
  it("verifies a legacy v0.7 channel fixture", () => {
    const metadata = `${JSON.stringify(
      {
        schema: "piship-channel/v1",
        distribution: "acmepi",
        channel: "stable",
        sequence: 7,
        expires: "2027-01-01T00:00:00.000Z",
        releases: [
          {
            version: "1.1.0",
            target: "linux-x64",
            archive: "acmepi-1.1.0-linux-x64.tar.gz",
            sha256: "b".repeat(64),
            bytes: 1234,
            pi: "0.87.1",
            piship: "0.7.1",
            lockSha256: "c".repeat(64),
          },
        ],
      },
      null,
      2,
    )}\n`;
    const envelope = JSON.parse(
      '{"schema":"piship-signature/v1","keyId":"acme-release-2026","algorithm":"ed25519","signature":"HmeBFdGcKbVB2B1otnK8uhN5fDinAJe5ydOBSbYhwalo/OMlwLAiiDd7qjzEupkDVgE1ldkyt/ydYHzqGiWyAg=="}',
    );
    const legacy = {
      id: "acme-release-2026",
      publicKey: "MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=",
    };
    expect(
      verifyThreshold(Buffer.from(metadata), envelope, [legacy], 1),
    ).toEqual([legacy.id]);
    expect(() =>
      verifyThreshold(
        Buffer.from(metadata.replace('"sequence": 7', '"sequence": 8')),
        envelope,
        [legacy],
        1,
      ),
    ).toThrow(/does not verify with trusted key acme-release-2026/);
  });

  // §11: top-level = the legacy key v0.7 clients pin; signatures[] = the
  // legacy key and the v0.8 channel role key.
  it("bridges v0.7 and v0.8 clients with one envelope", async () => {
    const legacy = generateSigningKey("acme-release-2026");
    const envelope = buildSignatureEnvelope([
      await entry(legacy, bytes),
      await entry(CHANNEL_A, bytes),
    ]);
    expect(envelope.keyId).toBe(legacy.id);
    // A v0.7 client checks the top-level signature against its pinned keys
    // and ignores signatures[].
    expect(verifySignature(bytes, envelope, [pub(legacy)])).toBe(legacy.id);
    // A v0.8 client checks the set against the current channel role.
    expect(verifyThreshold(bytes, envelope, [pub(CHANNEL_A)], 1)).toEqual([
      CHANNEL_A.id,
    ]);
  });
});

/** A signature entry, made synchronously. */
function entrySync(key: SigningKeyPair, bytes: Buffer): SignatureEntry {
  const envelope = signBytes(bytes, key.privateKeyPem, key.id);
  return {
    keyId: envelope.keyId,
    algorithm: envelope.algorithm,
    signature: envelope.signature,
  };
}

// ------------------------------------------------------------ root refresh

describe("root refresh", () => {
  const one = root(1, [ROOT_A], [CHANNEL_A]);

  it("accepts N -> N+1 and ends at an absent N+2", async () => {
    const dir = temp();
    await publishRoot(dir, root(2, [ROOT_A], [CHANNEL_B]), [ROOT_A]);
    const result = await refresh(dir, one);
    expect(result.root.version).toBe(2);
    expect(result.root.roles.channel.keyIds).toEqual([CHANNEL_B.id]);
    expect(result.accepted).toEqual([2]);
    // No root directory at all is "nothing newer", too.
    expect((await refresh(temp(), one)).transitions).toBe(0);
  });

  it("rejects a skipped version and a mismatched version field", async () => {
    const dir = temp();
    await publishRoot(dir, root(3, [ROOT_A], [CHANNEL_B]), [ROOT_A]);
    // root/2.json is absent: 3 is never fetched.
    expect((await refresh(dir, one)).root.version).toBe(1);
    // A root 3 body served as root/2.json.
    const text = readFileSync(join(dir, "root", "3.json"));
    writeFileSync(join(dir, "root", "2.json"), text);
    writeFileSync(
      join(dir, "root", "2.json.sig"),
      readFileSync(join(dir, "root", "3.json.sig")),
    );
    await expect(refresh(dir, one)).rejects.toThrow(
      /root\/2\.json records version 3/,
    );
  });

  it("requires both the trusted and the new root-role thresholds", async () => {
    const two = root(2, [ROOT_B], [CHANNEL_A]);
    const dir = temp();
    // Only the new root key: the trusted root 1 did not authorize it.
    await publishRoot(dir, two, [ROOT_B]);
    await expect(refresh(dir, one)).rejects.toMatchObject({
      code: "INTEGRITY_FAILED",
      message: expect.stringMatching(
        /Root 2 is not signed by the root role of the trusted root 1/,
      ),
    });
    // Only the old root key: the new root's own keys did not accept it.
    await publishRoot(dir, two, [ROOT_A]);
    await expect(refresh(dir, one)).rejects.toThrow(
      /Root 2 is not signed by the root role of the new root 2/,
    );
    // A channel key cannot sign a root.
    await publishRoot(dir, two, [CHANNEL_A, ROOT_B]);
    await expect(refresh(dir, one)).rejects.toThrow(/trusted root 1/);
    await publishRoot(dir, two, [ROOT_A, ROOT_B]);
    expect((await refresh(dir, one)).root.roles.root.keyIds).toEqual([
      ROOT_B.id,
    ]);
    // A 2-of-2 root needs both keys; each key counts once.
    const strict = root(2, [ROOT_A, ROOT_B], [CHANNEL_A], { rootThreshold: 2 });
    await publishRoot(dir, strict, [ROOT_A]);
    await expect(refresh(dir, one)).rejects.toThrow(/new root 2/);
    await publishRoot(dir, strict, [ROOT_A, ROOT_B]);
    expect((await refresh(dir, one)).root.roles.root.threshold).toBe(2);
  });

  it("catches up sequentially, through expired intermediate roots", async () => {
    const dir = temp();
    await publishRoot(
      dir,
      root(2, [ROOT_A], [CHANNEL_A], { expires: "2020-01-01T00:00:00Z" }),
      [ROOT_A],
    );
    await publishRoot(
      dir,
      root(3, [ROOT_B], [CHANNEL_B], { expires: "2020-06-01T00:00:00Z" }),
      [ROOT_A, ROOT_B],
    );
    await publishRoot(dir, root(4, [ROOT_B], [CHANNEL_B]), [ROOT_B]);
    const result = await refresh(dir, one);
    expect(result.accepted).toEqual([2, 3, 4]);
    expect(result.root.version).toBe(4);
  });

  it("fails on a root without its signature, of another distribution, or malformed", async () => {
    const dir = temp();
    await publishRoot(dir, root(2, [ROOT_A], [CHANNEL_A]), [ROOT_A]);
    rmSync(join(dir, "root", "2.json.sig"));
    await expect(refresh(dir, one)).rejects.toThrow(
      /has root\/2\.json but no root\/2\.json\.sig/,
    );
    await publishRoot(dir, root(2, [ROOT_A], [CHANNEL_A]), [ROOT_A], "otherpi");
    await expect(refresh(dir, one)).rejects.toThrow(
      /is for otherpi, not acmepi/,
    );
    writeFileSync(join(dir, "root", "2.json"), "{");
    await expect(refresh(dir, one)).rejects.toThrow(/is not valid JSON/);
    await publishRoot(
      dir,
      {
        ...root(2, [ROOT_A], [CHANNEL_A]),
        roles: {
          root: { keyIds: ["nobody"], threshold: 1 },
          channel: { keyIds: [CHANNEL_A.id], threshold: 1 },
        },
      },
      [ROOT_A],
    );
    await expect(refresh(dir, one)).rejects.toThrow(
      /root\/2\.json is invalid: .*not listed in keys/,
    );
  });

  it("enforces the metadata, signature, and transition bounds", async () => {
    const dir = temp();
    await publishRoot(dir, root(2, [ROOT_A], [CHANNEL_A]), [ROOT_A]);
    const path = join(dir, "root", "2.json");
    writeFileSync(path, Buffer.alloc(MAX_ROOT_BYTES + 1, 32));
    await expect(refresh(dir, one)).rejects.toThrow(/exceeds 65536 bytes/);
    await publishRoot(dir, root(2, [ROOT_A], [CHANNEL_A]), [ROOT_A]);
    writeFileSync(`${path}.sig`, Buffer.alloc(64 * 1024 + 1, 32));
    await expect(refresh(dir, one)).rejects.toThrow(/\.sig .*exceeds 65536/);
    // 65 new versions: 64 are accepted (and persisted), then the attempt stops.
    const chain = temp();
    for (let version = 2; version <= MAX_ROOT_TRANSITIONS + 2; version += 1)
      await publishRoot(chain, root(version, [ROOT_A], [CHANNEL_A]), [ROOT_A]);
    const accepted: number[] = [];
    await expect(
      refreshRoot({
        source: chain,
        distribution: ID,
        current: one,
        accept: (next) => accepted.push(next.version),
      }),
    ).rejects.toMatchObject({
      code: "UPDATE_FAILED",
      retryable: true,
      message: expect.stringMatching(/more than 64 new root versions/),
    });
    expect(accepted).toHaveLength(MAX_ROOT_TRANSITIONS);
    // The next attempt continues from the accepted root.
    const rest = await refresh(chain, root(65, [ROOT_A], [CHANNEL_A]));
    expect(rest.root.version).toBe(MAX_ROOT_TRANSITIONS + 2);
  });

  describe("over HTTP", () => {
    let server: Server;
    let base: string;
    const routes = new Map<string, { status: number; body?: Buffer }>();
    const requested: string[] = [];
    beforeEach(async () => {
      routes.clear();
      requested.length = 0;
      server = createServer((request, response) => {
        requested.push(request.url ?? "");
        const route = routes.get(request.url ?? "") ?? { status: 404 };
        response.writeHead(route.status);
        response.end(route.body ?? "");
      });
      await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/acmepi`;
    });
    afterEach(async () => {
      await new Promise<void>((done) => server.close(() => done()));
    });
    async function serveRoot(body: UpdateRoot, signers: SigningKeyPair[]) {
      const dir = temp();
      await publishRoot(dir, body, signers);
      for (const name of [`${body.version}.json`, `${body.version}.json.sig`])
        routes.set(`/acmepi/root/${name}`, {
          status: 200,
          body: readFileSync(join(dir, "root", name)),
        });
    }

    it("treats 404 as the end of the chain", async () => {
      await serveRoot(root(2, [ROOT_A], [CHANNEL_B]), [ROOT_A]);
      const result = await refresh(base, one);
      expect(result.root.version).toBe(2);
      expect(requested).toEqual([
        "/acmepi/root/2.json",
        "/acmepi/root/2.json.sig",
        "/acmepi/root/3.json",
      ]);
    });

    it("fails on a server error, a missing signature, or a dead connection", async () => {
      routes.set("/acmepi/root/2.json", { status: 503 });
      await expect(refresh(base, one)).rejects.toMatchObject({
        code: "UPDATE_FAILED",
        message: expect.stringMatching(/HTTP 503 for root\/2\.json/),
      });
      routes.set("/acmepi/root/2.json", { status: 403 });
      await expect(refresh(base, one)).rejects.toThrow(/HTTP 403/);
      await serveRoot(root(2, [ROOT_A], [CHANNEL_B]), [ROOT_A]);
      routes.delete("/acmepi/root/2.json.sig");
      await expect(refresh(base, one)).rejects.toThrow(/no root\/2\.json\.sig/);
      routes.set("/acmepi/root/2.json.sig", { status: 500 });
      await expect(refresh(base, one)).rejects.toThrow(/HTTP 500/);
      // Transport failure (TLS, proxy, connection refused) is not "absent".
      const refused = (async () => {
        throw new TypeError("fetch failed");
      }) as typeof fetch;
      await expect(refresh(base, one, refused)).rejects.toThrow(/fetch failed/);
    });
  });
});

// ------------------------------------------------------------ trust state

describe("installation trust state", () => {
  const bootstrap = root(1, [ROOT_A], [CHANNEL_A]);

  it("starts from a v1alpha5 bootstrap and writes an owner-only file", () => {
    const state = initialTrustState(
      {
        updates: {
          channel: "stable",
          channels: ["stable"],
          rollback: true,
          trust: { bootstrap },
        },
      },
      ID,
      NOW,
    );
    expect(state).toMatchObject({
      schema: "piship-update-trust/v1",
      distribution: ID,
      origin: "bootstrap",
      root: bootstrap,
      digest: rootDigest(bootstrap),
      removedKeys: [],
    });
    writeTrustState(state as NonNullable<typeof state>);
    expect(readTrustState(ID)).toEqual(state);
    if (process.platform !== "win32")
      expect(statSync(trustStatePath(ID)).mode & 0o777).toBe(0o600);
  });

  it("takes v1alpha4 keys as both roles of root 1, minus retired keys", () => {
    const updates = {
      channel: "stable" as const,
      channels: ["stable" as const],
      rollback: true,
      trust: {
        keys: [
          pub(CHANNEL_A),
          pub(CHANNEL_B),
          { ...pub(CHANNEL_A), id: "alias" },
        ],
      },
    };
    const state = initialTrustState({ updates }, ID, NOW, [
      keyFingerprint(CHANNEL_B.publicKey),
    ]);
    expect(state).toMatchObject({
      origin: "legacy",
      root: {
        version: 1,
        expires: LEGACY_ROOT_EXPIRES,
        keys: [pub(CHANNEL_A)],
        roles: {
          root: { keyIds: [CHANNEL_A.id], threshold: 1 },
          channel: { keyIds: [CHANNEL_A.id], threshold: 1 },
        },
      },
    });
    // Update-disabled: no trust to start from.
    expect(
      initialTrustState(
        { updates: { ...updates, trust: { keys: [] } } },
        ID,
        NOW,
      ),
    ).toBeUndefined();
    expect(
      initialTrustState({ updates: { ...updates, trust: {} } }, ID, NOW),
    ).toBeUndefined();
  });

  it("refuses a malformed lock bootstrap or lock key instead of trusting it", () => {
    const updates = {
      channel: "stable" as const,
      channels: ["stable" as const],
      rollback: true,
    };
    const malformed: unknown[] = [
      { bootstrap: { ...bootstrap, version: 0 } },
      {
        bootstrap: {
          ...bootstrap,
          roles: { ...bootstrap.roles, channel: { keyIds: [], threshold: 1 } },
        },
      },
      { bootstrap: { ...bootstrap, keys: [] } },
      { keys: [{ id: "bad", publicKey: "not a key" }] },
      { keys: [pub(CHANNEL_A), { ...pub(CHANNEL_B), id: CHANNEL_A.id }] },
    ];
    for (const trust of malformed)
      expect(() =>
        initialTrustState({ updates: { ...updates, trust } as never }, ID, NOW),
      ).toThrow(
        expect.objectContaining({
          code: "LOCK_INVALID",
          message: expect.stringMatching(/records invalid update trust/),
        }),
      );
  });

  // A migrated v0.7 installation (legacy root 1) and a fresh v0.8 install
  // (bootstrap root 1) both accept one root 2 signed by the legacy key and
  // the new root key.
  it("moves a legacy installation onto a split root with one signed root 2", async () => {
    const legacy = generateSigningKey("acme-release-2026");
    const legacyState = initialTrustState(
      {
        updates: {
          channel: "stable",
          channels: ["stable"],
          rollback: true,
          trust: { keys: [pub(legacy)] },
        },
      },
      ID,
      NOW,
    );
    const dir = temp();
    await publishRoot(dir, root(2, [ROOT_A], [CHANNEL_A]), [legacy, ROOT_A]);
    const migrated = await refresh(dir, legacyState?.root as UpdateRoot);
    expect(migrated.root.roles.channel.keyIds).toEqual([CHANNEL_A.id]);
    const fresh = await refresh(dir, bootstrap);
    expect(fresh.root.version).toBe(2);
    const advanced = advanceTrustState(
      legacyState as NonNullable<typeof legacyState>,
      migrated.root,
      NOW,
    );
    expect(advanced.origin).toBe("remote");
    expect(advanced.removedKeys).toEqual([
      {
        id: legacy.id,
        fingerprint: keyFingerprint(legacy.publicKey),
        role: "root",
        version: 2,
      },
      {
        id: legacy.id,
        fingerprint: keyFingerprint(legacy.publicKey),
        role: "channel",
        version: 2,
      },
    ]);
  });

  it("fails closed on a damaged state and never rebuilds it", () => {
    const state = initialTrustState(
      {
        updates: {
          channel: "stable",
          channels: ["stable"],
          rollback: true,
          trust: { bootstrap },
        },
      },
      ID,
      NOW,
    ) as NonNullable<ReturnType<typeof initialTrustState>>;
    const path = trustStatePath(ID);
    const cases: [string, RegExp][] = [
      ["{", /is damaged/],
      ["[]", /is not an object/],
      [JSON.stringify({ ...state, schema: "x" }), /has schema x/],
      [
        JSON.stringify({ ...state, distribution: "otherpi" }),
        /does not record distribution acmepi/,
      ],
      [
        JSON.stringify({ ...state, root: { ...bootstrap, version: 0 } }),
        /invalid root/,
      ],
      // A root changed without its digest: an added channel key.
      [
        JSON.stringify({
          ...state,
          root: root(1, [ROOT_A], [CHANNEL_A, STRANGER]),
        }),
        /does not match its digest/,
      ],
      [
        JSON.stringify({ ...state, removedKeys: [{ id: "x" }] }),
        /invalid removed keys/,
      ],
    ];
    for (const [content, problem] of cases) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
      let error: (Error & { code?: string; userAction?: string }) | undefined;
      try {
        readTrustState(ID);
      } catch (caught) {
        error = caught as typeof error;
      }
      expect(error?.code).toBe("INTEGRITY_FAILED");
      expect(error?.message).toMatch(problem);
      expect(error?.userAction).toMatch(
        /piship uninstall acmepi .*then piship install <release archive> --sha256/,
      );
      // Reading never repairs or replaces it.
      expect(readFileSync(path, "utf8")).toBe(content);
    }
    rmSync(path);
    expect(readTrustState(ID)).toBeUndefined();
  });

  it("an interrupted write leaves the previous state whole", () => {
    const state = initialTrustState(
      {
        updates: {
          channel: "stable",
          channels: ["stable"],
          rollback: true,
          trust: { bootstrap },
        },
      },
      ID,
      NOW,
    ) as NonNullable<ReturnType<typeof initialTrustState>>;
    writeTrustState(state);
    // A writer killed before its rename leaves only a temporary sibling.
    const path = trustStatePath(ID);
    writeFileSync(
      `${path}.p999999-abcdef012345.tmp`,
      '{"schema":"piship-update-trust/v1","root":',
    );
    expect(readTrustState(ID)).toEqual(state);
    expect(
      readdirSync(dirname(path)).filter((name) => name.endsWith(".json")),
    ).toEqual([`${ID}.json`]);
  });
});

// ------------------------------------------------------------ owner tooling

describe("trust-root owner tooling", () => {
  function manifest(dir: string, trust: UpdateRoot): string {
    mkdirSync(join(dir, "resources"), { recursive: true });
    writeFileSync(join(dir, "resources", "AGENTS.md"), "# AcmePi\n");
    const described = initTrustRoot({
      keys: trust.keys,
      rootKeyIds: trust.roles.root.keyIds,
      channelKeyIds: trust.roles.channel.keyIds,
      rootThreshold: trust.roles.root.threshold,
      channelThreshold: trust.roles.channel.threshold,
      expires: trust.expires,
      now: () => NOW,
    });
    const path = join(dir, "piship.yaml");
    writeFileSync(
      path,
      `schema: piship/v1alpha5
app:
  id: ${ID}
  name: AcmePi
  command: ${ID}
  version: 1.0.0
runtime:
  pi: "1.0.2"
deployment:
  mode: personal
resources:
  instructions:
    user: [./resources/AGENTS.md]
${described.yaml.replace("updates:\n", "updates:\n  channel: stable\n  rollback: true\n")}`,
    );
    return path;
  }

  it("init prints a bootstrap that a manifest accepts, and flags shared roles", () => {
    const described = initTrustRoot({
      keys: [pub(ROOT_A), pub(CHANNEL_A)],
      rootKeyIds: [ROOT_A.id],
      channelKeyIds: [CHANNEL_A.id],
      expiresDays: 365,
      now: () => NOW,
    });
    expect(described.root).toMatchObject({
      version: 1,
      expires: "2027-10-01T00:00:00Z",
    });
    expect(described.yaml).toContain("    bootstrap:\n      version: 1\n");
    expect(described.fingerprints).toEqual([
      { id: ROOT_A.id, fingerprint: keyFingerprint(ROOT_A.publicKey) },
      { id: CHANNEL_A.id, fingerprint: keyFingerprint(CHANNEL_A.publicKey) },
    ]);
    expect(described.warnings).toEqual([]);
    expect(
      initTrustRoot({
        keys: [pub(ROOT_A)],
        rootKeyIds: [ROOT_A.id],
        channelKeyIds: [ROOT_A.id],
        expiresDays: 30,
        now: () => NOW,
      }).warnings,
    ).toEqual([expect.stringMatching(/share root-a/)]);
    expect(() =>
      initTrustRoot({
        keys: [pub(ROOT_A)],
        rootKeyIds: [ROOT_A.id],
        channelKeyIds: ["missing"],
        expiresDays: 30,
        now: () => NOW,
      }),
    ).toThrow(/not listed in keys/);
    expect(() =>
      initTrustRoot({
        keys: [pub(ROOT_A)],
        rootKeyIds: [ROOT_A.id],
        channelKeyIds: [ROOT_A.id],
        expires: "2020-01-01T00:00:00Z",
        now: () => NOW,
      }),
    ).toThrow(/is not in the future/);
  });

  it("next publishes exactly N+1, verified against old and new thresholds", async () => {
    const project = temp();
    const path = manifest(project, root(1, [ROOT_A], [CHANNEL_A]));
    const repository = join(project, "updates");
    const first = await nextTrustRoot({
      repository,
      manifest: path,
      addKeys: [pub(CHANNEL_B)],
      removeKeys: [CHANNEL_A.id],
      channelKeyIds: [CHANNEL_B.id],
      expiresDays: 90,
      signers: [signer(ROOT_A)],
      now: () => NOW,
    });
    expect(first.root.version).toBe(2);
    expect(first.root.roles.channel.keyIds).toEqual([CHANNEL_B.id]);
    expect(first.root.keys.map((key) => key.id)).toEqual([
      ROOT_A.id,
      CHANNEL_B.id,
    ]);
    // What it wrote is what a client accepts.
    const client = await refresh(repository, root(1, [ROOT_A], [CHANNEL_A]));
    expect(client.root).toEqual(first.root);
    // Root-key rotation: the old key alone cannot hand over to a new one.
    const before = readdirSync(join(repository, "root")).sort();
    await expect(
      nextTrustRoot({
        repository,
        manifest: path,
        addKeys: [pub(ROOT_B)],
        removeKeys: [ROOT_A.id],
        rootKeyIds: [ROOT_B.id],
        expiresDays: 90,
        signers: [signer(ROOT_A)],
        now: () => NOW,
      }),
    ).rejects.toThrow(/new root 3.*nothing was written/);
    expect(readdirSync(join(repository, "root")).sort()).toEqual(before);
    const rotated = await nextTrustRoot({
      repository,
      manifest: path,
      addKeys: [pub(ROOT_B)],
      removeKeys: [ROOT_A.id],
      rootKeyIds: [ROOT_B.id],
      expiresDays: 90,
      signers: [signer(ROOT_A), signer(ROOT_B)],
      now: () => NOW,
    });
    expect(rotated.root.version).toBe(3);
    expect(rotated.signedBy).toEqual([ROOT_A.id, ROOT_B.id]);
    expect(
      (await refresh(repository, root(1, [ROOT_A], [CHANNEL_A]))).root.version,
    ).toBe(3);
  });

  it("a failing or faulty signer changes no files", async () => {
    const project = temp();
    const path = manifest(project, root(1, [ROOT_A], [CHANNEL_A]));
    const repository = join(project, "updates");
    const failing: KeyedSigner = {
      ...signer(ROOT_A),
      sign: async () => {
        throw new Error("token unplugged: secret-pin-1234");
      },
    };
    const faulty: KeyedSigner = {
      ...signer(ROOT_A),
      sign: async () => new Uint8Array(64),
    };
    for (const bad of [failing, faulty]) {
      const error = await nextTrustRoot({
        repository,
        manifest: path,
        expiresDays: 30,
        signers: [bad],
        now: () => NOW,
      }).catch((caught: Error) => caught);
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).not.toContain("secret-pin");
      expect(existsSync(repository)).toBe(false);
    }
  });
});

// The channel role of the newest root decides; readChannel takes it as keys
// and a threshold.
describe("channel role threshold", () => {
  it("requires the channel role threshold from distinct keys", async () => {
    const dir = temp();
    const text = Buffer.from(
      `${JSON.stringify(
        {
          schema: "piship-channel/v1",
          distribution: ID,
          channel: "stable",
          sequence: 1,
          expires: "2099-01-01T00:00:00.000Z",
          releases: [],
        },
        null,
        2,
      )}\n`,
    );
    writeFileSync(join(dir, "stable.json"), text);
    const read = (threshold: number) =>
      readChannel(dir, "stable", {
        distribution: ID,
        trusted: [pub(CHANNEL_A), pub(CHANNEL_B)],
        threshold,
        now: () => NOW,
      });
    writeFileSync(
      join(dir, "stable.json.sig"),
      JSON.stringify(buildSignatureEnvelope([await entry(CHANNEL_A, text)])),
    );
    expect((await read(1)).keyIds).toEqual([CHANNEL_A.id]);
    await expect(read(2)).rejects.toThrow(/meet 1 of the 2 required/);
    writeFileSync(
      join(dir, "stable.json.sig"),
      JSON.stringify(
        buildSignatureEnvelope([
          await entry(CHANNEL_A, text),
          await entry(CHANNEL_B, text),
        ]),
      ),
    );
    expect((await read(2)).keyIds).toEqual([CHANNEL_A.id, CHANNEL_B.id]);
  });
});
