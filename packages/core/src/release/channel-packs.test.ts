import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { validChannel as validForV0130 } from "../../../../tests/fixtures/channel-v0.13.0.js";
import { generateSigningKey, signBytes } from "../signing.js";
import { CHANNEL_SCHEMA, readChannel } from "./index.js";

const KEY = generateSigningKey("acme-release");
const NOW = () => new Date("2026-06-02T00:00:00Z");
const hex = (seed: string) => createHash("sha256").update(seed).digest("hex");

const release = {
  version: "1.0.0",
  target: "linux-x64",
  archive: "acmepi-1.0.0-linux-x64.tar.gz",
  sha256: hex("release"),
  bytes: 10,
  pi: "1.1.0",
  piship: "0.13.0",
  lockSha256: hex("lock"),
};
const pack = {
  version: "1.1.0",
  archive: "acmepi-1.1.0-pack.tar.gz",
  sha256: hex("pack"),
  bytes: 10,
  pi: "1.1.0",
  piship: "0.13.0",
  lockSha256: hex("lock-2"),
  runtimes: {
    "linux-x64": {
      archive: "piship-runtime-0.13.0-linux-x64.tar.gz",
      sha256: hex("runtime"),
      bytes: 20,
    },
  },
};
const channel = (extra: Record<string, unknown>) => ({
  schema: CHANNEL_SCHEMA,
  distribution: "acmepi",
  channel: "stable",
  sequence: 1,
  expires: "2026-07-01T00:00:00.000Z",
  releases: [release],
  ...extra,
});

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

/** Publish signed metadata the way sign-channel lays it out, and read it back as a client does. */
async function read(metadata: unknown) {
  const dir = mkdtempSync(join(tmpdir(), "piship-channel-packs-"));
  roots.push(dir);
  const bytes = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`);
  writeFileSync(join(dir, "stable.json"), bytes);
  writeFileSync(
    join(dir, "stable.json.sig"),
    JSON.stringify(signBytes(bytes, KEY.privateKeyPem, KEY.id)),
  );
  return readChannel(dir, "stable", {
    distribution: "acmepi",
    trusted: [{ id: KEY.id, publicKey: KEY.publicKey }],
    now: NOW,
  });
}

describe("channel packs", () => {
  it("is read by this client with the packs it carries", async () => {
    const { metadata } = await read(channel({ packs: [pack] }));
    expect(metadata.packs).toEqual([pack]);
    expect(metadata.releases).toEqual([release]);
  });

  it("is still read when it carries no packs", async () => {
    expect((await read(channel({}))).metadata.packs).toBeUndefined();
  });

  it("refuses malformed packs", async () => {
    for (const bad of [
      { ...pack, sha256: "short" },
      { ...pack, archive: "../escape.tar.gz" },
      { ...pack, runtimes: { "plan9-x64": pack.runtimes["linux-x64"] } },
      { ...pack, runtimes: { "linux-x64": { archive: "x.tar.gz" } } },
      { ...pack, version: "one" },
      "pack",
    ])
      await expect(read(channel({ packs: [bad] }))).rejects.toThrow(
        /invalid fields/,
      );
    await expect(read(channel({ packs: {} }))).rejects.toThrow(
      /invalid fields/,
    );
  });

  // The v0.13.0 validator, copied from that tag, rejects a releases[] entry
  // for an unknown target or with missing fields, and looks at nothing else:
  // packs are top-level so that an installed client keeps reading the channel.
  it("is accepted by the v0.13.0 channel validator, which ignores packs", () => {
    expect(validForV0130(channel({}))).toBe(true);
    expect(validForV0130(channel({ packs: [pack] }))).toBe(true);
    expect(
      validForV0130(channel({ packs: [pack, { anything: "else" }] })),
    ).toBe(true);
  });

  it("would be refused by the v0.13.0 validator if a pack were a releases[] entry", () => {
    expect(
      validForV0130(
        channel({ releases: [release, { ...pack, target: "pack" }] }),
      ),
    ).toBe(false);
  });
});
