import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type CredentialProvider,
  PiShipError,
  type RuntimeCredential,
  SecretValue,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CREDENTIAL_DISCARDED_SCHEMA,
  CredentialManager,
  MemorySecretStore,
  metadataFileSecretRefs,
  secretRefsFromText,
} from "./index.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-ownership-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

const ctx = { distributionId: "acmecode" };
const path = () => join(temp, "credentials-metadata", "inference.json");

function provider(): CredentialProvider & { acquired: () => number } {
  let count = 0;
  return {
    mode: "http-broker",
    requiresIdentity: false,
    acquired: () => count,
    async acquire(): Promise<RuntimeCredential> {
      count += 1;
      return {
        kind: "api_key",
        secret: new SecretValue(`sk-generation-${count}-secret`),
        credentialId: `vk_${count}`,
      };
    },
  };
}

class FailingDeletes extends MemorySecretStore {
  fail = false;
  override async delete(ref: string): Promise<void> {
    if (this.fail)
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        "the keyring is locked",
      );
    return super.delete(ref);
  }
}

function make(
  store: MemorySecretStore = new MemorySecretStore(),
  extra: Partial<ConstructorParameters<typeof CredentialManager>[0]> = {},
) {
  const source = provider();
  const manager = new CredentialManager({
    distributionId: "acmecode",
    provider: source,
    store,
    metadataPath: path(),
    beforeExpirySeconds: 300,
    ...extra,
  });
  return { manager, store, provider: source };
}

/** Metadata of generation 5 (with an orphan #3), cut off before its end. */
function writeTruncated(): void {
  const full = JSON.stringify(
    {
      schema: "piship-credential-metadata/v1",
      mode: "http-broker",
      credential_ref: "piship:acmecode:inference#5",
      generation: 5,
      kind: "api_key",
      credential_id: "vk_old",
      acquired_at: "2026-01-01T00:00:00.000Z",
      orphans: ["piship:acmecode:inference#3"],
    },
    null,
    2,
  );
  mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
  writeFileSync(path(), full.slice(0, full.lastIndexOf("]")));
}

async function oldSecrets(store: MemorySecretStore): Promise<void> {
  await store.put(
    "piship:acmecode:inference#5",
    new SecretValue("sk-old-generation-5-secret"),
  );
  await store.put(
    "piship:acmecode:inference#3",
    new SecretValue("sk-old-generation-3-secret"),
  );
}

describe("secret references named by a metadata file's text", () => {
  it("reads the references of a truncated file as a readable one would give them", () => {
    writeTruncated();
    expect(() => JSON.parse(readFileSync(path(), "utf8"))).toThrow();
    expect(metadataFileSecretRefs(path(), "acmecode", "inference")).toEqual([
      "piship:acmecode:inference#3",
      "piship:acmecode:inference#5",
      "piship:acmecode:inference#6",
    ]);
    expect(
      secretRefsFromText(
        '{"schema":"piship-identity-metadata/v1","secretRef":"piship:acmecode:identity#4","orphans":["piship:acmecode:identity#1"',
        "acmecode",
        "identity",
      ),
    ).toEqual([
      "piship:acmecode:identity#1",
      "piship:acmecode:identity#3",
      "piship:acmecode:identity#4",
      "piship:acmecode:identity#5",
    ]);
  });

  it("names only its own distribution and class", () => {
    const text =
      '{"credential_ref":"piship:acmecode:inference#2","orphans":["piship:other:inference#1","piship:acmecode:identity#1","piship:acme.code:inference#9"';
    expect(secretRefsFromText(text, "acmecode", "inference")).toEqual([
      "piship:acmecode:inference#2",
    ]);
    expect(secretRefsFromText(text, "acme.code", "inference")).toEqual([
      "piship:acme.code:inference#9",
    ]);
    expect(
      secretRefsFromText("\u0000garbage", "acmecode", "inference"),
    ).toEqual([]);
    expect(metadataFileSecretRefs(path(), "acmecode", "inference")).toEqual([]);
  });
});

describe("credential ownership across damaged metadata and interrupted writes", () => {
  it("deletes the secrets a truncated metadata file still names before acquiring a new credential", async () => {
    const { manager, store } = make();
    await oldSecrets(store);
    writeTruncated();
    expect(manager.status().state).toBe("absent");
    const active = await manager.ensure(null, ctx, { allowAcquire: true });
    expect(active.notices).toEqual([
      "Damaged credential metadata was cleared after the secrets it names were deleted; a new credential is required",
    ]);
    // The new credential restarts at generation 1; the older generations are
    // gone rather than stranded outside every metadata file.
    expect(active.secret?.reveal()).toBe("sk-generation-1-secret");
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
  });

  it("never uses a secret a damaged metadata file names", async () => {
    const { manager, store } = make();
    await oldSecrets(store);
    writeTruncated();
    await expect(
      manager.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    expect(store.refs()).toEqual([]);
  });

  it("keeps a damaged file's references tracked while they cannot be deleted, and logout retries them", async () => {
    const store = new FailingDeletes();
    const { manager } = make(store);
    await oldSecrets(store);
    writeTruncated();
    store.fail = true;
    await expect(
      manager.ensure(null, ctx, { allowAcquire: true }),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(JSON.parse(readFileSync(path(), "utf8"))).toMatchObject({
      schema: CREDENTIAL_DISCARDED_SCHEMA,
      orphans: [
        "piship:acmecode:inference#3",
        "piship:acmecode:inference#5",
        "piship:acmecode:inference#6",
      ],
    });
    store.fail = false;
    expect(await manager.logout(ctx)).toEqual([]);
    expect(existsSync(path())).toBe(false);
    expect(store.refs()).toEqual([]);
  });

  it("says so when a damaged file names no reference that can be recovered", async () => {
    const { manager } = make();
    mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
    writeFileSync(path(), "\u0000\u0000\u0000");
    const active = await manager.ensure(null, ctx, { allowAcquire: true });
    expect(active.notices).toEqual([
      expect.stringContaining(
        "Damaged credential metadata named no secret reference that could be recovered",
      ),
    ]);
  });

  it("tracks a first credential written before its metadata was committed", async () => {
    const store = new MemorySecretStore();
    const crashing = make(store, {
      onPhase: (phase) => {
        if (phase === "secret-written") throw new Error("simulated crash");
      },
    }).manager;
    await expect(
      crashing.ensure(null, ctx, { allowAcquire: true }),
    ).rejects.toThrow("simulated crash");
    expect(store.refs()).toEqual(["piship:acmecode:inference#1"]);
    // Named by a discarded marker, never by credential metadata.
    expect(JSON.parse(readFileSync(path(), "utf8"))).toMatchObject({
      schema: CREDENTIAL_DISCARDED_SCHEMA,
      orphans: ["piship:acmecode:inference#1"],
    });
    const { manager } = make(store);
    expect(manager.status().state).toBe("absent");
    expect(await manager.logout(ctx)).toEqual([]);
    expect(store.refs()).toEqual([]);
    expect(existsSync(path())).toBe(false);
  });

  it("never serves the secret of an interrupted first write", async () => {
    const store = new MemorySecretStore();
    await make(store, {
      onPhase: (phase) => {
        if (phase === "secret-written") throw new Error("simulated crash");
      },
    })
      .manager.ensure(null, ctx, { allowAcquire: true })
      .catch(() => undefined);
    const { manager, provider: source } = make(store);
    await expect(
      manager.ensure(null, ctx, { allowAcquire: false }),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    expect(store.refs()).toEqual([]);
    const active = await manager.ensure(null, ctx, { allowAcquire: true });
    expect(source.acquired()).toBe(1);
    expect(active.secret?.reveal()).toBe("sk-generation-1-secret");
  });
});

/** A store whose command is missing (`missing`) or that answers but fails. */
class ToggledStore extends MemorySecretStore {
  state: "ok" | "missing" | "failing" = "ok";
  #check(): void {
    if (this.state === "missing")
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        "Linux Secret Service secret store is unavailable: secret-tool was not found",
        { sanitizedDetail: { reachable: false } },
      );
    if (this.state === "failing")
      throw new PiShipError(
        "SECRET_STORE_UNAVAILABLE",
        "Linux Secret Service secret store failed: the keyring is locked",
      );
  }
  override async put(ref: string, value: SecretValue): Promise<void> {
    this.#check();
    return super.put(ref, value);
  }
  override async get(ref: string): Promise<SecretValue | null> {
    this.#check();
    return super.get(ref);
  }
  override async delete(ref: string): Promise<void> {
    this.#check();
    return super.delete(ref);
  }
}

describe("a discarded marker whose store is not installed", () => {
  const marker = () => JSON.parse(readFileSync(path(), "utf8"));
  const writeMarker = (fields: Record<string, unknown>) => {
    mkdirSync(join(temp, "credentials-metadata"), { recursive: true });
    writeFileSync(
      path(),
      JSON.stringify({
        schema: CREDENTIAL_DISCARDED_SCHEMA,
        secret_store: "system",
        discarded_at: "2026-10-03T00:00:00.000Z",
        ...fields,
      }),
    );
  };
  async function logout(manager: CredentialManager) {
    let dropped: readonly string[] = [];
    const problems = await manager.logout(ctx, {
      onDiscard: (result) => {
        dropped = result.dropped;
      },
    });
    return { problems, dropped };
  }

  it("keeps a first sign-in's secret written before a crash, once the write is confirmed", async () => {
    const store = new ToggledStore();
    await make(store, {
      onPhase: (phase) => {
        if (phase === "secret-written") throw new Error("simulated crash");
      },
    })
      .manager.ensure(null, ctx, { allowAcquire: true })
      .catch(() => undefined);
    expect(marker()).toMatchObject({
      orphans: ["piship:acmecode:inference#1"],
      unconfirmed: [],
    });
    store.state = "missing";
    const { manager } = make(store);
    const { problems, dropped } = await logout(manager);
    expect(dropped).toEqual([]);
    expect(problems).toEqual([
      expect.stringContaining("delete piship:acmecode:inference#1"),
    ]);
    expect(marker().orphans).toEqual(["piship:acmecode:inference#1"]);
    // The store is back: the secret is deleted, not lost track of.
    store.state = "ok";
    expect(await manager.logout(ctx)).toEqual([]);
    expect(store.refs()).toEqual([]);
    expect(existsSync(path())).toBe(false);
  });

  it("drops a reference never confirmed written", async () => {
    const store = new ToggledStore();
    store.state = "failing";
    await expect(
      make(store).manager.ensure(null, ctx, { allowAcquire: true }),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    // The write's outcome is unknown: tracked, and unconfirmed.
    expect(marker()).toMatchObject({
      orphans: ["piship:acmecode:inference#1"],
      unconfirmed: ["piship:acmecode:inference#1"],
    });
    store.state = "missing";
    const { problems, dropped } = await logout(make(store).manager);
    expect(problems).toEqual([]);
    expect(dropped).toEqual(["piship:acmecode:inference#1"]);
    expect(existsSync(path())).toBe(false);
  });

  it("keeps a logout's undeleted secret, and fails closed", async () => {
    const store = new ToggledStore();
    const { manager } = make(store);
    await manager.ensure(null, ctx, { allowAcquire: true });
    store.state = "failing";
    expect(await manager.logout(ctx)).not.toEqual([]);
    expect(marker()).toMatchObject({ unconfirmed: [] });
    const orphans = marker().orphans;
    expect(orphans).toContain("piship:acmecode:inference#1");
    store.state = "missing";
    const { dropped } = await logout(manager);
    expect(dropped).toEqual([]);
    await expect(
      manager.ensure(null, ctx, { allowAcquire: true }),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(marker().orphans).toEqual(orphans);
    store.state = "ok";
    expect(await manager.logout(ctx)).toEqual([]);
    expect(store.refs()).toEqual([]);
  });

  it("drops only the unconfirmed references of a mixed marker", async () => {
    writeMarker({
      orphans: ["piship:acmecode:inference#1", "piship:acmecode:inference#2"],
      unconfirmed: ["piship:acmecode:inference#2"],
    });
    const store = new ToggledStore();
    store.state = "missing";
    const { dropped } = await logout(make(store).manager);
    expect(dropped).toEqual(["piship:acmecode:inference#2"]);
    expect(marker()).toMatchObject({
      orphans: ["piship:acmecode:inference#1"],
      unconfirmed: [],
    });
  });

  it("drops every reference of a v0.8.0 marker, which cannot tell them apart", async () => {
    writeMarker({ orphans: ["piship:acmecode:inference#1"] });
    const store = new ToggledStore();
    store.state = "missing";
    const { dropped } = await logout(make(store).manager);
    expect(dropped).toEqual(["piship:acmecode:inference#1"]);
    expect(existsSync(path())).toBe(false);
  });
});
