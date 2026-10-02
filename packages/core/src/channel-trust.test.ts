// Channel trust root: what a client accepts from signed channel metadata
// across key rotation, retirement, substitution, tampering, a half-published
// channel, and replay. Keys are generated per run; no key material is stored.
// These tests build no release, so they run on every target; the build-backed
// channel and update tests are in release.test.ts and lifecycle.test.ts.
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CHANNEL_SCHEMA,
  type ChannelRelease,
  downloadArchive,
  readChannel,
} from "./release/index.js";
import {
  generateSigningKey,
  keyFingerprint,
  signBytes,
  type TrustedKey,
} from "./signing.js";

const OLD = generateSigningKey("acme-release-2026");
const NEW = generateSigningKey("acme-release-2027");
const trust = (...keys: (typeof OLD)[]): TrustedKey[] =>
  keys.map(({ id, publicKey }) => ({ id, publicKey }));
const NOW = () => new Date("2026-06-02T00:00:00Z");

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-channel-trust-"));
  roots.push(dir);
  return dir;
}

const ARCHIVE = Buffer.from("not a real archive, only its digest matters\n");
const entry: ChannelRelease = {
  version: "1.1.0",
  target: "linux-x64",
  archive: "acmepi-1.1.0-linux-x64.tar.gz",
  sha256: createHash("sha256").update(ARCHIVE).digest("hex"),
  bytes: ARCHIVE.length,
  pi: "1.0.0",
  piship: "0.7.0",
  lockSha256: "a".repeat(64),
};

function metadataBytes(sequence: number, channel = "stable"): Buffer {
  const metadata = {
    schema: CHANNEL_SCHEMA,
    distribution: "acmepi",
    channel,
    sequence,
    expires: "2026-07-01T00:00:00.000Z",
    releases: [entry],
  };
  return Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`);
}

/** Publish `<channel>.json` and its signature, as `sign-channel` lays them out. */
function publish(
  dir: string,
  key: typeof OLD,
  sequence: number,
  options: { keyId?: string; channel?: string } = {},
): Buffer {
  const channel = options.channel ?? "stable";
  const bytes = metadataBytes(sequence, channel);
  writeFileSync(join(dir, `${channel}.json`), bytes);
  writeFileSync(
    join(dir, `${channel}.json.sig`),
    JSON.stringify(
      signBytes(bytes, key.privateKeyPem, options.keyId ?? key.id),
    ),
  );
  return bytes;
}

const read = (
  dir: string,
  trusted: TrustedKey[],
  minSequence?: number,
  channel = "stable",
) =>
  readChannel(dir, channel, {
    distribution: "acmepi",
    trusted,
    now: NOW,
    ...(minSequence === undefined ? {} : { minSequence }),
  });

describe("channel trust root", () => {
  it("accepts metadata signed by any pinned key and names the key that verified", async () => {
    const dir = temp();
    publish(dir, NEW, 1);
    const { metadata, keyId } = await read(dir, trust(OLD, NEW));
    expect(keyId).toBe(NEW.id);
    expect(metadata).toMatchObject({ sequence: 1, releases: [entry] });
  });

  // Rotation is release-bound: the trusted set is the active release's
  // locked updates.trust.keys, so the overlap window is the span of releases
  // that pin both keys (lifecycle.test.ts walks it through real updates).
  it("rotation: both keys verify while both are pinned, the retired key does not after", async () => {
    const dir = temp();
    const before = trust(OLD);
    const overlap = trust(OLD, NEW);
    const after = trust(NEW);
    publish(dir, OLD, 1);
    expect((await read(dir, before)).keyId).toBe(OLD.id);
    expect((await read(dir, overlap)).keyId).toBe(OLD.id);
    await expect(read(dir, after)).rejects.toMatchObject({
      code: "INTEGRITY_FAILED",
      message: expect.stringMatching(
        /Signature key acme-release-2026 is not trusted; trusted keys: acme-release-2027/,
      ),
    });
    publish(dir, NEW, 2);
    await expect(read(dir, before)).rejects.toThrow(
      /Signature key acme-release-2027 is not trusted/,
    );
    expect((await read(dir, overlap)).keyId).toBe(NEW.id);
    expect((await read(dir, after)).keyId).toBe(NEW.id);
  });

  it("refuses a revoked key however the signature names it", async () => {
    const dir = temp();
    // The compromised private key signs under its own id ...
    publish(dir, OLD, 2);
    await expect(read(dir, trust(NEW), 1)).rejects.toThrow(/is not trusted/);
    // ... under the id of the key that replaced it ...
    publish(dir, OLD, 2, { keyId: NEW.id });
    await expect(read(dir, trust(NEW), 1)).rejects.toThrow(
      /does not verify with trusted key acme-release-2027/,
    );
    // ... or under its old id after a new key was pinned with that id.
    publish(dir, OLD, 2);
    await expect(
      read(dir, [{ id: OLD.id, publicKey: NEW.publicKey }], 1),
    ).rejects.toThrow(/does not verify with trusted key acme-release-2026/);
  });

  // A rollback re-activates a lock that may still pin a key a newer release
  // dropped; the installation's retired keys stay refused.
  it("refuses a retired key that the active lock still pins", async () => {
    const dir = temp();
    const retired = [
      {
        id: OLD.id,
        fingerprint: keyFingerprint(OLD.publicKey),
        release: "2.0.0",
      },
    ];
    publish(dir, OLD, 2);
    await expect(
      readChannel(dir, "stable", {
        distribution: "acmepi",
        trusted: trust(OLD, NEW),
        retired,
        now: NOW,
      }),
    ).rejects.toMatchObject({
      code: "INTEGRITY_FAILED",
      message: expect.stringMatching(
        /Signature key acme-release-2026 was retired by the 2\.0\.0 release of this installation/,
      ),
    });
    // Signed under another pinned key's id, it still does not verify.
    publish(dir, OLD, 2, { keyId: NEW.id });
    await expect(
      readChannel(dir, "stable", {
        distribution: "acmepi",
        trusted: trust(OLD, NEW),
        retired,
        now: NOW,
      }),
    ).rejects.toThrow(/does not verify with trusted key acme-release-2027/);
    // A pinned key that was not retired is accepted.
    publish(dir, NEW, 3);
    const accepted = await readChannel(dir, "stable", {
      distribution: "acmepi",
      trusted: trust(OLD, NEW),
      retired,
      now: NOW,
    });
    expect(accepted.keyId).toBe(NEW.id);
    // Retirement follows the public key, not the id: a new key pinned under
    // the retired id is trusted.
    const reused = generateSigningKey(OLD.id);
    publish(dir, reused, 4);
    const fresh = await readChannel(dir, "stable", {
      distribution: "acmepi",
      trusted: trust(reused),
      retired,
      now: NOW,
    });
    expect(fresh.keyId).toBe(OLD.id);
    // Only retired keys pinned: nothing can verify.
    publish(dir, OLD, 5);
    await expect(
      readChannel(dir, "stable", {
        distribution: "acmepi",
        trusted: trust(OLD),
        retired,
        now: NOW,
      }),
    ).rejects.toThrow(/was retired by the 2\.0\.0 release/);
  });

  it("refuses unknown keys and an empty trust root (no trust on first use)", async () => {
    const dir = temp();
    publish(dir, generateSigningKey("someone-else"), 1);
    await expect(read(dir, trust(OLD, NEW))).rejects.toThrow(
      /Signature key someone-else is not trusted; trusted keys: acme-release-2026, acme-release-2027/,
    );
    publish(dir, OLD, 1);
    await expect(read(dir, [])).rejects.toThrow(/no trusted release keys/);
  });

  it("refuses metadata changed by one byte", async () => {
    const dir = temp();
    const bytes = publish(dir, OLD, 1);
    const changed = Buffer.from(bytes);
    const at = changed.indexOf(entry.sha256);
    changed[at] = changed[at] === 0x61 ? 0x62 : 0x61;
    writeFileSync(join(dir, "stable.json"), changed);
    await expect(read(dir, trust(OLD))).rejects.toMatchObject({
      code: "INTEGRITY_FAILED",
      message: expect.stringMatching(/does not verify/),
    });
  });

  it("never accepts a half-published channel", async () => {
    const dir = temp();
    publish(dir, OLD, 1);
    const sig1 = join(dir, "stable.json.sig");
    const oldSignature = Buffer.from(
      JSON.stringify(signBytes(metadataBytes(1), OLD.privateKeyPem, OLD.id)),
    );
    // New metadata already in place, its signature not yet.
    writeFileSync(join(dir, "stable.json"), metadataBytes(2));
    writeFileSync(sig1, oldSignature);
    await expect(read(dir, trust(OLD))).rejects.toThrow(/does not verify/);
    // A truncated metadata or signature upload.
    const full = metadataBytes(2);
    writeFileSync(join(dir, "stable.json"), full.subarray(0, full.length / 2));
    await expect(read(dir, trust(OLD))).rejects.toThrow(/does not verify/);
    publish(dir, OLD, 2);
    writeFileSync(sig1, oldSignature.subarray(0, oldSignature.length / 2));
    await expect(read(dir, trust(OLD))).rejects.toThrow(/not valid JSON/);
    // A signature file without its metadata.
    rmSync(join(dir, "stable.json"));
    await expect(read(dir, trust(OLD))).rejects.toThrow(
      /Update source has no stable.json/,
    );
  });

  it("refuses another channel's signed metadata served under this channel", async () => {
    const dir = temp();
    // The dev metadata and its valid signature, served as stable.
    const dev = metadataBytes(5, "dev");
    writeFileSync(join(dir, "stable.json"), dev);
    writeFileSync(
      join(dir, "stable.json.sig"),
      JSON.stringify(signBytes(dev, OLD.privateKeyPem, OLD.id)),
    );
    await expect(read(dir, trust(OLD))).rejects.toThrow(
      /is for acmepi\/dev, not acmepi\/stable/,
    );
  });

  it("rollback protection: refuses a lower sequence, accepts the same or a higher one", async () => {
    const dir = temp();
    publish(dir, OLD, 3);
    expect((await read(dir, trust(OLD), 3)).metadata.sequence).toBe(3);
    await expect(read(dir, trust(OLD), 4)).rejects.toMatchObject({
      code: "INTEGRITY_FAILED",
      message: expect.stringMatching(
        /sequence 3 is older than the 4 already seen; refusing a replayed channel/,
      ),
    });
    // Rotating the signing key does not reset the floor.
    publish(dir, NEW, 3);
    await expect(read(dir, trust(OLD, NEW), 4)).rejects.toThrow(
      /refusing a replayed channel/,
    );
    publish(dir, NEW, 4);
    expect((await read(dir, trust(OLD, NEW), 4)).keyId).toBe(NEW.id);
  });

  it("refuses an archive whose digest or size differs from the signed entry", async () => {
    const dir = temp();
    writeFileSync(join(dir, entry.archive), ARCHIVE);
    const out = temp();
    await downloadArchive(dir, entry, join(out, "ok.tar.gz"));
    await expect(
      downloadArchive(
        dir,
        { ...entry, sha256: "0".repeat(64) },
        join(out, "digest.tar.gz"),
      ),
    ).rejects.toMatchObject({
      code: "INTEGRITY_FAILED",
      message: expect.stringMatching(/does not match the signed channel/),
    });
    const changed = Buffer.from(ARCHIVE);
    changed[0] = (changed[0] as number) ^ 0xff;
    writeFileSync(join(dir, entry.archive), changed);
    await expect(
      downloadArchive(dir, entry, join(out, "tampered.tar.gz")),
    ).rejects.toThrow(/does not match the signed channel/);
    writeFileSync(join(dir, entry.archive), ARCHIVE.subarray(1));
    await expect(
      downloadArchive(dir, entry, join(out, "short.tar.gz")),
    ).rejects.toThrow(/does not match the signed channel/);
    writeFileSync(join(dir, entry.archive), Buffer.concat([ARCHIVE, ARCHIVE]));
    await expect(
      downloadArchive(dir, entry, join(out, "long.tar.gz")),
    ).rejects.toThrow(/exceeds 44 bytes/);
  });
});
