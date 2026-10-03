// #196: a system secret store that cannot be reached at all (Linux without
// `secret-tool`, as on WSL or a headless server). A first login must report
// the store, never a "previous credential", and a reference left behind by
// an earlier release must not keep blocking login once the storage changes.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { formatError, PiShipError, type SecretStore } from "@piship/contracts";
import {
  type CommandRunner,
  MemorySecretStore,
  SecretServiceSecretStore,
  type SecretStoreProvider,
} from "@piship/credentials";
import type { AccessManifest } from "@piship/schema";
import { parseManifest, readManifestDocument } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DistributionAccess } from "./access/index.js";

const examples = fileURLToPath(new URL("../../../examples/", import.meta.url));
const KEY = "sk-mypi-store-sentinel-0001";

/** `secret-tool` is not installed: spawnSync fails with ENOENT. */
const missing: CommandRunner = () => ({
  status: null,
  stdout: "",
  stderr: "spawnSync secret-tool ENOENT",
  missing: true,
});

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-store-unavailable-"));
});
afterEach(() => rmSync(temp, { recursive: true, force: true }));

/** MyPi Local with a `local-secret` credential on the given storage. */
function open(
  storage: SecretStoreProvider,
  stores: Partial<Record<SecretStoreProvider, SecretStore>>,
): DistributionAccess {
  const document = readManifestDocument(
    join(examples, "personal", "local-model", "piship.yaml"),
  ) as Record<string, unknown>;
  document.credential = {
    provider: "local-secret",
    storage: { provider: storage },
  };
  const manifest = parseManifest(document);
  return DistributionAccess.open({
    app: manifest.app,
    mode: "personal",
    access: manifest.access as AccessManifest,
    stateDir: join(temp, "state"),
    distributionDir: temp,
    env: { MYPI_MODEL_URL: "http://127.0.0.1:9/v1" },
    onEvent: () => {},
    ...(stores[storage] ? { secretStore: stores[storage] } : {}),
    secretStoreFor: (provider) => stores[provider] ?? null,
  });
}

const login = (access: DistributionAccess) =>
  access.login({
    openUrl: () => {
      throw new Error("a personal distribution never opens a sign-in URL");
    },
    readSecret: async () => KEY,
  });

async function failure(promise: Promise<unknown>): Promise<PiShipError> {
  const error = await promise.then(
    () => {
      throw new Error("expected a failure");
    },
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(PiShipError);
  return error as PiShipError;
}

/** The discarded marker v0.8.0 left behind: it names a never-stored secret. */
function leaveV080Marker(access: DistributionAccess): void {
  mkdirSync(dirname(access.paths.credential), { recursive: true });
  writeFileSync(
    access.paths.credential,
    `${JSON.stringify({
      schema: "piship-credential-discarded/v1",
      orphans: [`piship:${access.providerId}:inference#1`],
      secret_store: "system",
      discarded_at: "2026-10-03T10:48:43.000Z",
    })}\n`,
  );
}

describe("an unreachable system secret store (#196)", () => {
  const system = () => new SecretServiceSecretStore(missing);

  it("a first login after a test launch reports the store, not a previous credential, and leaves no reference", async () => {
    const access = open("system", { system: system() });
    // `piship test` first: no credential yet.
    await expect(
      open("system", { system: system() }).activate(),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REQUIRED" });
    const first = await failure(login(access));
    expect(first.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(first.message).toBe(
      "Linux Secret Service secret store is unavailable: secret-tool was not found (spawnSync secret-tool ENOENT)",
    );
    expect(first.userAction).toMatch(/secret-tool/);
    expect(first.userAction).toMatch(
      /set credential\.storage\.provider to file in piship\.yaml, then lock and build/,
    );
    // Nothing could have been written, so nothing is tracked.
    expect(existsSync(access.paths.credential)).toBe(false);
    // A second login reports the same cause.
    const second = await failure(login(open("system", { system: system() })));
    expect(second.message).toBe(first.message);
    expect(formatError(second)).not.toMatch(/previous credential|REDACTED/);
  });

  it("then switching to the file store signs in", async () => {
    await failure(login(open("system", { system: system() })));
    const file = new MemorySecretStore();
    const stores = { system: system(), file };
    await expect(login(open("file", stores))).resolves.toMatchObject({
      credential: { state: "valid" },
    });
    expect(file.refs()).toHaveLength(1);
  });

  it("a write that fails while the store is reachable keeps its reference tracked", async () => {
    // A locked keyring answers, so the write's outcome is unknown.
    const locked: CommandRunner = () => ({
      status: 1,
      stdout: "",
      stderr: "Cannot create an item in a locked collection",
    });
    const access = open("system", {
      system: new SecretServiceSecretStore(locked),
    });
    const error = await failure(login(access));
    expect(error.message).toMatch(/secret store failed: Cannot create/);
    expect(
      JSON.parse(readFileSync(access.paths.credential, "utf8")),
    ).toMatchObject({
      schema: "piship-credential-discarded/v1",
      orphans: [`piship:${access.providerId}:inference#1`],
    });
  });

  it("a reference v0.8.0 left behind is dropped, and login reports the store", async () => {
    const access = open("system", { system: system() });
    leaveV080Marker(access);
    const error = await failure(login(access));
    expect(error.message).toBe(
      "Linux Secret Service secret store is unavailable: secret-tool was not found (spawnSync secret-tool ENOENT)",
    );
    expect(existsSync(access.paths.credential)).toBe(false);
  });

  it("after switching to the file store, a reference v0.8.0 left in the system store no longer blocks login", async () => {
    const before = open("system", { system: system() });
    leaveV080Marker(before);
    const file = new MemorySecretStore();
    const result = await login(open("file", { system: system(), file }));
    expect(result.credential.state).toBe("valid");
    expect(result.notices.join("\n")).toMatch(
      /piship:mypi-local:inference#1\) were dropped without deleting anything: the secret store that recorded them is not installed here/,
    );
    expect(file.refs()).toHaveLength(1);
  });

  it("a reference whose store answers but fails stays tracked, and login says what it is", async () => {
    const access = open("system", {
      system: new SecretServiceSecretStore(() => ({
        status: 1,
        stdout: "",
        stderr: "Cannot autolaunch D-Bus without X11 $DISPLAY",
      })),
    });
    leaveV080Marker(access);
    expect((await access.status()).credential.notice).toBe(
      "Secret references that a discarded credential or an interrupted sign-in left in the system secret store are still to be deleted; they are never used, and login or logout deletes them once that store works (or drops them when it is not installed)",
    );
    const error = await failure(login(access));
    expect(error.message).toMatch(
      /^Linux Secret Service secret store failed: Cannot autolaunch D-Bus without X11 \$DISPLAY\. Until it is available, a secret reference that an earlier sign-in or sign-out left behind \(piship:mypi-local:inference#1\) cannot be deleted from it, so sign-in stopped before acquiring a new credential$/,
    );
    expect(error.message).not.toMatch(/previous credential/);
    expect(error.userAction).toMatch(
      /set credential\.storage\.provider to file .*then run login again; it deletes the reference first$/,
    );
    expect(existsSync(access.paths.credential)).toBe(true);
  });

  it("a real previous credential that cannot be deleted still stops sign-in", async () => {
    const platform = new MemorySecretStore();
    await login(open("system", { system: platform }));
    const access = open("system", { system: system() });
    const error = await failure(login(access));
    expect(error.message).toMatch(
      /^Linux Secret Service secret store is unavailable: .*\. Until it is available, the previous credential \(piship:.*:inference#1, piship:.*:inference#2\) cannot be deleted from it/,
    );
    expect(platform.refs()).toHaveLength(1);
  });

  it("a locked store keeps the problem text unredacted", async () => {
    await login(open("system", { system: new MemorySecretStore() }));
    const locked = new MemorySecretStore();
    locked.delete = async () => {
      throw new Error("the keyring is locked");
    };
    const error = await failure(login(open("system", { system: locked })));
    expect(error.message).toMatch(
      /^The previous credential could not be deleted from the secret store, so sign-in stopped before acquiring a new credential \(delete piship:\S+:inference#1: the keyring is locked; delete piship:\S+:inference#2: the keyring is locked\)$/,
    );
  });
});
