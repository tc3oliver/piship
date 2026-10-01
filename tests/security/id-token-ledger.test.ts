import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DistributionAccess } from "@piship/core";
import { MemorySecretStore } from "@piship/credentials";
import { type AccessManifest, readManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { SecretLedger, scanTree } from "../helpers/security.js";

// The secret ledger must know every ID token the provider issued, from the
// provider side. A file-store snapshot is not enough: a run on the system
// secret store (Keychain, Credential Manager, Secret Service) leaves no file
// the snapshot could read, and the sweeps would then never look for the ID
// token at all. Here the store is a MemorySecretStore, standing in for the
// system store, so no file store exists to snapshot.

const demo = readManifest(
  fileURLToPath(
    new URL("../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;

type Services = Awaited<ReturnType<typeof startLocalServices>>;
let temp: string;
let services: Services;
beforeEach(async () => {
  temp = mkdtempSync(join(tmpdir(), "piship-id-token-ledger-"));
  services = await startLocalServices();
});
afterEach(async () => {
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

function open(store: MemorySecretStore): DistributionAccess {
  return DistributionAccess.open({
    app: demo.app,
    mode: "managed",
    access: {
      ...access,
      identity: {
        ...access.identity,
        oidc: {
          ...(access.identity as { oidc: object }).oidc,
          redirectUri: "http://127.0.0.1/callback",
        },
      },
      credential: { ...access.credential, storage: { provider: "system" } },
    } as AccessManifest,
    stateDir: join(temp, "state"),
    distributionDir: temp,
    env: services.env(),
    secretStore: store,
  });
}

/** The ID token PiShip holds in the store after sign-in. */
async function storedIdTokens(store: MemorySecretStore): Promise<string[]> {
  const found: string[] = [];
  for (const ref of store.refs()) {
    const value = (await store.get(ref))?.reveal();
    if (!value) continue;
    try {
      const parsed: unknown = JSON.parse(value);
      if (
        parsed &&
        typeof parsed === "object" &&
        "idToken" in parsed &&
        typeof parsed.idToken === "string"
      )
        found.push(parsed.idToken);
    } catch {
      // Not a token bundle.
    }
  }
  return found;
}

async function signIn(): Promise<MemorySecretStore> {
  const store = new MemorySecretStore();
  await open(store).login({
    openUrl: (url: string) => void services.approve(url),
    signal: AbortSignal.timeout(15_000),
  });
  return store;
}

describe("ID tokens in the secret ledger", () => {
  it("tracks the ID token the system store holds, with no file store to snapshot", async () => {
    const store = await signIn();
    const held = await storedIdTokens(store);
    // The sign-in stored an ID token: the case the ledger has to cover.
    expect(held).toHaveLength(1);
    const ledger = new SecretLedger();
    ledger.observeServices(services);
    expect(ledger.all()).toEqual(expect.arrayContaining(held));
  });

  it("tracks the ID token of every sign-in, the replaced one included", async () => {
    await signIn();
    await signIn();
    const issued = [...(services.state.idTokens as Set<string>)];
    expect(issued).toHaveLength(2);
    expect(new Set(issued).size).toBe(2);
    const ledger = new SecretLedger();
    ledger.observeServices(services);
    expect(ledger.all()).toEqual(expect.arrayContaining(issued));
  });

  it("finds a leaked ID token in the tree a sweep scans", async () => {
    const store = await signIn();
    const [idToken] = await storedIdTokens(store);
    expect(idToken).toBeDefined();
    const ledger = new SecretLedger();
    ledger.observeServices(services);
    // No leak yet: the state directory holds metadata only.
    expect(scanTree(temp, ledger.all())).toEqual([]);
    // A planted leak, as a log line that copied the token.
    mkdirSync(join(temp, "logs"), { recursive: true });
    writeFileSync(
      join(temp, "logs", "debug.log"),
      `signed in with id_token=${idToken}\n`,
    );
    const found = scanTree(temp, ledger.all());
    // A sighting names the secret by its place in the ledger, not its value.
    const label = `secret #${ledger.all().indexOf(idToken ?? "") + 1}`;
    expect(found.map(({ where, secret }) => ({ where, secret }))).toEqual([
      { where: join(temp, "logs", "debug.log"), secret: label },
    ]);
  });
});
