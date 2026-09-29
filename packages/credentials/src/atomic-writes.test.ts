// The credentials package's own writers under injected I/O faults: credential
// metadata, its discarded marker, and the file secret store's entries write
// every byte and flush it before the rename, and every failure before the
// rename keeps the previous file and removes the temporary.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type CredentialProvider,
  PiShipError,
  type RuntimeCredential,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearFaults,
  type FsFault,
  fired,
  injectFault,
} from "../../../tests/helpers/fs-faults.js";
import {
  CREDENTIAL_DISCARDED_SCHEMA,
  CredentialManager,
  MemorySecretStore,
  RestrictedFileSecretStore,
} from "./index.js";

vi.mock("node:fs", async (importOriginal) =>
  (await import("../../../tests/helpers/fs-faults.js")).faultyFs(
    await importOriginal(),
  ),
);

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-credential-atomic-"));
});
afterEach(() => {
  clearFaults();
  rmSync(temp, { recursive: true, force: true });
});

const ctx = { distributionId: "acmecode" };
const directory = () => join(temp, "credentials-metadata");
const metadataPath = () => join(directory(), "inference.json");
/** The metadata file and its temporaries, never the lock file beside it. */
const metadataFiles = /inference\.json(\.p\d+-[0-9a-f]+\.tmp)?$/;
const temporaries = (dir: string) =>
  readdirSync(dir).filter((name) => name.endsWith(".tmp"));

const failures: [string, FsFault][] = [
  ["a write that makes no progress", { op: "write", stall: true }],
  ["ENOSPC while writing", { op: "write", code: "ENOSPC" }],
  ["a failed fsync", { op: "fsync", code: "EIO" }],
  ["a failed rename", { op: "rename", code: "EACCES" }],
];

class FailingDeletes extends MemorySecretStore {
  override async delete(): Promise<void> {
    throw new PiShipError("SECRET_STORE_UNAVAILABLE", "the keyring is locked");
  }
}

function manager(store: MemorySecretStore = new MemorySecretStore()) {
  const provider: CredentialProvider = {
    mode: "http-broker",
    requiresIdentity: false,
    async acquire(): Promise<RuntimeCredential> {
      return {
        kind: "api_key",
        secret: new SecretValue("fake-generation-1-secret"),
        credentialId: "vk_1",
      };
    },
  };
  return new CredentialManager({
    distributionId: "acmecode",
    provider,
    store,
    metadataPath: metadataPath(),
    beforeExpirySeconds: 300,
  });
}

describe("credential metadata", () => {
  it("is completed through short writes instead of publishing a truncated file", async () => {
    injectFault(/inference\.json\..*\.tmp$/, { op: "write", short: true }, 4);
    await manager().ensure(null, ctx, { allowAcquire: true });
    expect(fired.length).toBeGreaterThan(0);
    expect(JSON.parse(readFileSync(metadataPath(), "utf8"))).toMatchObject({
      schema: "piship-credential-metadata/v1",
      credential_ref: "piship:acmecode:inference#1",
    });
    expect(temporaries(directory())).toEqual([]);
  });

  it.each(failures)(
    "keeps the previous file byte for byte and no temporary after %s",
    async (_name, fault) => {
      const credentials = manager();
      await credentials.ensure(null, ctx, { allowAcquire: true });
      const before = readFileSync(metadataPath());
      injectFault(metadataFiles, fault);
      await expect(credentials.markRejected()).rejects.toThrow();
      expect(fired.length).toBeGreaterThan(0);
      expect(readFileSync(metadataPath())).toEqual(before);
      expect(temporaries(directory())).toEqual([]);
      clearFaults();
      await credentials.markRejected();
      expect(
        JSON.parse(readFileSync(metadataPath(), "utf8")).rejected_at,
      ).toEqual(expect.any(String));
      expect(temporaries(directory())).toEqual([]);
    },
  );

  it("leaves a complete discarded marker through short writes, and keeps the metadata after a failed flush", async () => {
    const credentials = manager(new FailingDeletes());
    await credentials.ensure(null, ctx, { allowAcquire: true });
    const before = readFileSync(metadataPath());
    // The secret cannot be deleted, so the marker replaces the metadata; the
    // flush of its temporary fails first.
    injectFault(metadataFiles, { op: "fsync", code: "EIO" });
    await expect(credentials.logout(ctx)).rejects.toThrow();
    expect(readFileSync(metadataPath())).toEqual(before);
    expect(temporaries(directory())).toEqual([]);
    clearFaults();
    injectFault(/inference\.json\..*\.tmp$/, { op: "write", short: true }, 4);
    expect(await credentials.logout(ctx)).not.toEqual([]);
    expect(fired.length).toBeGreaterThan(0);
    expect(JSON.parse(readFileSync(metadataPath(), "utf8"))).toMatchObject({
      schema: CREDENTIAL_DISCARDED_SCHEMA,
      orphans: expect.arrayContaining(["piship:acmecode:inference#1"]),
    });
    expect(temporaries(directory())).toEqual([]);
  });
});

describe("the file secret store", () => {
  const ref = "piship:acmecode:inference#1";
  const secrets = () => join(temp, "secrets");

  it("completes an entry through short writes instead of storing a truncated one", async () => {
    const store = new RestrictedFileSecretStore(secrets());
    injectFault(/\.secret\..*\.tmp$/, { op: "write", short: true }, 4);
    await store.put(ref, new SecretValue("fake-secret-value"));
    expect(fired.length).toBeGreaterThan(0);
    expect((await store.get(ref))?.reveal()).toBe("fake-secret-value");
    expect(temporaries(secrets())).toEqual([]);
  });

  it.each(failures)(
    "keeps the previous secret and no temporary after %s",
    async (_name, fault) => {
      const store = new RestrictedFileSecretStore(secrets());
      await store.put(ref, new SecretValue("fake-previous-value"));
      injectFault(/\.secret/, fault);
      await expect(
        store.put(ref, new SecretValue("fake-replacement-value")),
      ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
      expect(fired.length).toBeGreaterThan(0);
      expect((await store.get(ref))?.reveal()).toBe("fake-previous-value");
      expect(temporaries(secrets())).toEqual([]);
      clearFaults();
      await store.put(ref, new SecretValue("fake-replacement-value"));
      expect((await store.get(ref))?.reveal()).toBe("fake-replacement-value");
      expect(temporaries(secrets())).toEqual([]);
    },
  );
});
