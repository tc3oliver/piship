import { generateKeyPairSync } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readManifest } from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";
import {
  channelTrustFromLock,
  diffLocks,
  formatDiff,
  LOCK_SCHEMA_V1ALPHA4,
  LOCK_SCHEMA_V1ALPHA5,
  lockManifest,
  requireCurrentLock,
  resolveLock,
} from "./index.js";
import { manifestDigest } from "./lock.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function ed25519Key(): string {
  return generateKeyPairSync("ed25519")
    .publicKey.export({ type: "spki", format: "der" })
    .toString("base64");
}
const ROOT = ed25519Key();
const CHANNEL = ed25519Key();

const BOOTSTRAP = {
  version: 3,
  expires: "2027-10-01T00:00:00Z",
  keys: [
    { id: "acme-root", publicKey: ROOT },
    { id: "acme-channel", publicKey: CHANNEL },
  ],
  roles: {
    root: { keyIds: ["acme-root"], threshold: 1 },
    channel: { keyIds: ["acme-channel"], threshold: 1 },
  },
};

const MANIFEST = `schema: piship/v1alpha5
# The distribution.
app:
  id: acmepi
  name: AcmePi
  command: acmepi
  version: 1.0.0
runtime:
  pi: "1.0.0"
deployment:
  mode: personal
resources:
  instructions:
    user: [./resources/AGENTS.md]
updates:
  channel: stable
  source: https://updates.acme.example
  trust:
    bootstrap:
      version: 3
      expires: 2027-10-01T00:00:00Z
      keys:
        - id: acme-root
          publicKey: ${ROOT}
        - id: acme-channel
          publicKey: ${CHANNEL}
      roles:
        root: { keyIds: [acme-root], threshold: 1 }
        channel: { keyIds: [acme-channel], threshold: 1 }
`;

/** The same manifest: other comments, reordered keys, flow style. */
const REFORMATTED = `# Reformatted by hand.
deployment: { mode: personal }
schema: piship/v1alpha5
runtime: { pi: "1.0.0" }
app: { version: 1.0.0, command: acmepi, name: AcmePi, id: acmepi } # app
updates:
  trust:
    bootstrap:
      roles:
        channel: { threshold: 1, keyIds: [acme-channel] }
        root:
          threshold: 1
          keyIds:
            - acme-root
      keys:
        - publicKey: ${ROOT}
          id: acme-root
        - { id: acme-channel, publicKey: ${CHANNEL} }
      expires: 2027-10-01T00:00:00Z
      version: 3
  source: https://updates.acme.example
  channel: stable
resources: { instructions: { user: [./resources/AGENTS.md] } }
`;

function project(source: string): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-lock-v5-"));
  roots.push(dir);
  mkdirSync(join(dir, "resources"));
  writeFileSync(join(dir, "resources", "AGENTS.md"), "# AcmePi\n");
  const path = join(dir, "piship.yaml");
  writeFileSync(path, source);
  return path;
}

describe("lock piship-lock/v1alpha5", () => {
  it("is deterministic and records the canonical manifest digest", () => {
    const path = project(MANIFEST);
    const first = readFileSync(lockManifest(path), "utf8");
    expect(readFileSync(lockManifest(path), "utf8")).toBe(first);
    const lock = requireCurrentLock(path);
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA5);
    expect(lock.manifest.schema).toBe("piship/v1alpha5");
    expect(lock.manifest.sha256).toMatch(/^sha256-[0-9a-f]{64}$/);
  });

  it("represents the validated bootstrap root exactly", () => {
    const lock = resolveLock(project(MANIFEST));
    expect(lock.updates?.trust).toEqual({ bootstrap: BOOTSTRAP });
    expect(channelTrustFromLock(lock)).toEqual([
      { id: "acme-channel", publicKey: CHANNEL },
    ]);
    // Only public keys: no private material reaches the lock.
    expect(JSON.stringify(lock)).not.toMatch(/PRIVATE KEY|privateKey/);
  });

  it("keeps the manifest digest across YAML comments, key order, and line endings", () => {
    const base = resolveLock(project(MANIFEST));
    for (const source of [
      REFORMATTED,
      MANIFEST.replaceAll("\n", "\r\n"),
      `${MANIFEST}\n# trailing comment\n`,
    ]) {
      const lock = resolveLock(project(source));
      expect(lock.manifest.sha256).toBe(base.manifest.sha256);
      expect(lock).toEqual(base);
    }
  });

  it("changes the manifest digest with any semantic change", () => {
    const base = resolveLock(project(MANIFEST)).manifest.sha256;
    for (const [from, to] of [
      ["version: 1.0.0", "version: 1.0.1"],
      ["version: 3", "version: 4"],
      ["expires: 2027-10-01T00:00:00Z", "expires: 2027-10-02T00:00:00Z"],
      [
        "channel: { keyIds: [acme-channel], threshold: 1 }",
        "channel: { keyIds: [acme-channel, acme-root], threshold: 1 }",
      ],
      ["https://updates.acme.example", "https://updates2.acme.example"],
    ] as const) {
      const source = MANIFEST.replace(from, to);
      expect(source).not.toBe(MANIFEST);
      expect(resolveLock(project(source)).manifest.sha256).not.toBe(base);
    }
  });

  it("is update-disabled without a bootstrap", () => {
    const source = MANIFEST.slice(0, MANIFEST.indexOf("  source:"));
    const lock = resolveLock(project(source));
    expect(lock.updates?.trust).toEqual({});
    expect(channelTrustFromLock(lock)).toEqual([]);
  });
});

describe("older locks", () => {
  const v4 = MANIFEST.replace(
    "schema: piship/v1alpha5",
    "schema: piship/v1alpha4",
  )
    .slice(0, MANIFEST.indexOf("  trust:"))
    .concat(
      `  trust:\n    keys:\n      - id: acme-release\n        publicKey: ${CHANNEL}\n`,
    );

  it("keep the v1alpha4 lock schema and bare-hex manifest digest", () => {
    const path = project(v4);
    lockManifest(path);
    const lock = requireCurrentLock(path);
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA4);
    expect(lock.manifest.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(manifestDigest(readManifest(path))).toBe(lock.manifest.sha256);
  });

  it("derive channel trust from v1alpha4 keys", () => {
    const lock = resolveLock(project(v4));
    expect(channelTrustFromLock(lock)).toEqual([
      { id: "acme-release", publicKey: CHANNEL },
    ]);
    expect(channelTrustFromLock({})).toEqual([]);
  });
});

describe("updates.transport in the lock", () => {
  const HTTP = MANIFEST.replace(
    "  source: https://updates.acme.example\n",
    "  source: http://updates.corp.internal/acmepi\n  transport: http-allowed\n",
  );

  it("is locked only when declared, and diff reports the change", () => {
    const before = resolveLock(project(MANIFEST));
    expect(before.updates).not.toHaveProperty("transport");
    const after = resolveLock(project(HTTP));
    expect(after.updates?.transport).toBe("http-allowed");
    expect(after.updates?.source).toBe("http://updates.corp.internal/acmepi");
    const report = diffLocks(before, after);
    expect(report.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          area: "updates",
          item: "update transport",
          kind: "added",
          risk: "high",
          after: "http-allowed",
        }),
      ]),
    );
    expect(formatDiff(report)).toContain("update transport");
  });

  it("does not change the digest of a manifest whose comments mention it", () => {
    const commented = MANIFEST.replace(
      "  source: https://updates.acme.example\n",
      "  source: https://updates.acme.example\n  # transport: http-allowed\n",
    );
    expect(manifestDigest(readManifest(project(commented)))).toBe(
      manifestDigest(readManifest(project(MANIFEST))),
    );
  });
});
