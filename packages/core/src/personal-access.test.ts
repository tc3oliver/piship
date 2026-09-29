import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { SecretValue } from "@piship/contracts";
import {
  CREDENTIAL_METADATA_SCHEMA,
  RestrictedFileSecretStore,
} from "@piship/credentials";
import {
  type AccessManifest,
  type Manifest,
  parseManifest,
  readManifest,
  readManifestDocument,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type AccessEvent, DistributionAccess } from "./access/index.js";
import { readPreferences, setPreference } from "./config.js";

// Personal distributions have no identity provider (identity.mode none), so
// there is no principal to bind state to. Binding credentials to the signed-in
// principal must change nothing for them: no principal record, no identity
// requirement at launch, no discarded credential, and sessions and the model
// selection survive login, logout, and login again as before.

const examples = fileURLToPath(new URL("../../../examples/", import.meta.url));

type Mode = "pi-native" | "local-secret" | "none";

/** The fake key a MyPi Local user types at `login`. Not a real credential. */
const OWNER_KEY = "sk-mypi-owner-sentinel-0001";
const SECOND_KEY = "sk-mypi-owner-sentinel-0002";

let temp: string;
let events: AccessEvent[];
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-personal-access-"));
  events = [];
});
afterEach(() => rmSync(temp, { recursive: true, force: true }));

const stateDir = () => join(temp, "state");

/**
 * MyPi (`pi-native`) as committed, or MyPi Local with its credential set to
 * `local-secret` (on the personal file store, which needs no keyring) or
 * `none`, and a second catalog model so a user selection differs from the
 * default.
 */
function manifestFor(mode: Mode): Manifest {
  if (mode === "pi-native")
    return readManifest(join(examples, "personal", "piship.yaml"));
  const document = readManifestDocument(
    join(examples, "personal", "local-model", "piship.yaml"),
  ) as Record<string, unknown> & {
    models: { allowed: string[]; catalog: Record<string, unknown> };
  };
  document.credential =
    mode === "local-secret"
      ? { provider: "local-secret", storage: { provider: "file" } }
      : { provider: "none" };
  document.models.allowed = [...document.models.allowed, "local/fast"];
  document.models.catalog["local/fast"] = {
    name: "Local Fast",
    contextWindow: 16000,
    maxOutputTokens: 1024,
  };
  return parseManifest(document);
}

function open(mode: Mode): DistributionAccess {
  const manifest = manifestFor(mode);
  return DistributionAccess.open({
    app: manifest.app,
    mode: "personal",
    access: manifest.access as AccessManifest,
    stateDir: stateDir(),
    distributionDir: temp,
    // Nothing listens here: a static catalog needs no request at launch.
    env: { MYPI_MODEL_URL: "http://127.0.0.1:9/v1" },
    onEvent: (event) => events.push(event),
  });
}

/** Sign in the way the branded `login` command does for each mode. */
function login(distribution: DistributionAccess, key = OWNER_KEY) {
  return distribution.login({
    openUrl: () => {
      throw new Error("a personal distribution never opens a sign-in URL");
    },
    readSecret: async () => `${key}\n`,
  });
}

/** Every file under the state directory with its content. */
function stateFiles(): Record<string, string> {
  const files: Record<string, string> = {};
  const visit = (directory: string) => {
    if (!existsSync(directory)) return;
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      if (statSync(path).isDirectory()) visit(path);
      else
        files[relative(stateDir(), path).replaceAll("\\", "/")] = readFileSync(
          path,
          "utf8",
        );
    }
  };
  visit(stateDir());
  return files;
}

/** The references the personal file store holds. */
function storedRefs(): string[] {
  const directory = join(stateDir(), "secrets");
  if (!existsSync(directory)) return [];
  return readdirSync(directory).map(
    (name) =>
      (
        JSON.parse(readFileSync(join(directory, name), "utf8")) as {
          ref: string;
        }
      ).ref,
  );
}

/** A Pi session file, as an earlier launch in this project left it. */
function writeSession(): { path: string; content: string } {
  const path = join(stateDir(), "sessions", "project", "session-1.jsonl");
  const content = '{"type":"session","id":"session-1"}\n';
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, content);
  return { path, content };
}

describe("personal distributions without identity", () => {
  it.each(["pi-native", "local-secret", "none"] as const)(
    "never create a principal record with %s credentials",
    async (mode) => {
      const distribution = open(mode);
      if (mode !== "pi-native") {
        await login(distribution);
        await distribution.logout();
        await login(distribution);
      }
      await distribution.activate();
      await open(mode).activate();
      expect(distribution.readPrincipalBinding()).toBeNull();
      expect(existsSync(distribution.paths.principal)).toBe(false);
      expect(existsSync(join(stateDir(), "identity"))).toBe(false);
    },
  );

  it.each(["pi-native", "local-secret", "none"] as const)(
    "launch with %s credentials without a signed-in identity",
    async (mode) => {
      const distribution = open(mode);
      if (mode === "local-secret") await login(distribution);
      const activated = await distribution.activate();
      expect(activated.identity).toBeNull();
      expect(await distribution.identityProvider()).toBeNull();
      expect(
        events.filter((event) => event.event.startsWith("identity.")),
      ).toEqual([]);
    },
  );

  it("stores a local secret with no principal in its metadata", async () => {
    const distribution = open("local-secret");
    const result = await login(distribution);
    expect(result.identity).toBeNull();
    const metadata = JSON.parse(
      readFileSync(distribution.paths.credential, "utf8"),
    ) as Record<string, unknown>;
    expect(metadata).toMatchObject({
      schema: CREDENTIAL_METADATA_SCHEMA,
      mode: "local-secret",
    });
    expect(metadata).not.toHaveProperty("principal");
    expect(JSON.stringify(stateFiles())).not.toContain(OWNER_KEY.slice(3));
  });

  it("reuses the stored local secret on every launch instead of discarding it as unbound", async () => {
    await login(open("local-secret"));
    const before = readFileSync(open("local-secret").paths.credential, "utf8");
    for (let launch = 0; launch < 3; launch++) {
      const activated = await open("local-secret").activate();
      expect(activated.credential.secret?.reveal()).toBe(OWNER_KEY);
      expect(activated.notices).toEqual([]);
    }
    expect(readFileSync(open("local-secret").paths.credential, "utf8")).toBe(
      before,
    );
    expect(
      events.filter((event) => event.event === "credential.revoke"),
    ).toEqual([]);
  });

  it("keeps using a local secret stored before credentials were bound to a principal", async () => {
    // State exactly as the v0.6 release (ab3e7f2) wrote it: the same
    // metadata schema with no principal field, and the secret in the file
    // store beside it.
    const distribution = open("local-secret");
    const ref = "piship:mypi-local:inference#1";
    await new RestrictedFileSecretStore(distribution.paths.secrets).put(
      ref,
      new SecretValue(OWNER_KEY),
    );
    mkdirSync(join(distribution.paths.credential, ".."), { recursive: true });
    const legacy = `${JSON.stringify(
      {
        schema: CREDENTIAL_METADATA_SCHEMA,
        mode: "local-secret",
        credential_ref: ref,
        generation: 1,
        kind: "api_key",
        acquired_at: "2026-09-01T00:00:00.000Z",
      },
      null,
      2,
    )}\n`;
    writeFileSync(distribution.paths.credential, legacy);

    const activated = await distribution.activate();
    expect(activated.credential.secret?.reveal()).toBe(OWNER_KEY);
    expect(activated.notices).toEqual([]);
    expect(readFileSync(distribution.paths.credential, "utf8")).toBe(legacy);
    expect(existsSync(distribution.paths.principal)).toBe(false);
  });

  it("replaces the local secret on a second login without logging out", async () => {
    await login(open("local-secret"));
    const second = await login(open("local-secret"), SECOND_KEY);
    expect(second.notices).toEqual([]);
    const activated = await open("local-secret").activate();
    expect(activated.credential.secret?.reveal()).toBe(SECOND_KEY);
    // The first key was deleted before the second was stored.
    expect(storedRefs()).toHaveLength(1);
  });

  it.each(["local-secret", "none"] as const)(
    "keeps sessions and the model selection across login, logout, and login with %s credentials",
    async (mode) => {
      const session = writeSession();
      const manifest = manifestFor(mode);
      const preferences = open(mode).paths.preferences;
      setPreference(
        preferences,
        manifest.access as AccessManifest,
        undefined,
        "model",
        "local/fast",
      );
      const distribution = open(mode);
      await login(distribution);
      expect((await distribution.activate()).selectedModel).toBe("local/fast");
      await distribution.logout();
      await login(open(mode));
      const activated = await open(mode).activate();
      expect(activated.selectedModel).toBe("local/fast");
      expect(activated.notices).toEqual([]);
      expect(readPreferences(preferences).values.model).toBe("local/fast");
      expect(readFileSync(session.path, "utf8")).toBe(session.content);
    },
  );

  it("leaves no secret and no credential metadata after logout with local-secret credentials", async () => {
    const distribution = open("local-secret");
    await login(distribution);
    expect(await distribution.logout()).toEqual([]);
    expect(existsSync(distribution.paths.credential)).toBe(false);
    expect(storedRefs()).toEqual([]);
    await expect(open("local-secret").activate()).rejects.toMatchObject({
      code: "CREDENTIAL_REQUIRED",
    });
  });

  it("uses a credential adapter that needs no identity once per stored credential", async () => {
    mkdirSync(join(temp, "resources", "adapters"), { recursive: true });
    writeFileSync(
      join(temp, "resources", "adapters", "local.mjs"),
      `export default () => ({
        mode: "adapter",
        requiresIdentity: false,
        async acquire(identity) {
          globalThis.__pishipPersonalAcquires = [
            ...(globalThis.__pishipPersonalAcquires ?? []),
            identity,
          ];
          return { kind: "api_key", secret: "sk-adapter-sentinel-0001" };
        },
      });`,
    );
    const document = readManifestDocument(
      join(examples, "personal", "local-model", "piship.yaml"),
    ) as Record<string, unknown>;
    document.credential = {
      provider: "adapter",
      adapter: "./adapters/local.mjs",
      storage: { provider: "file" },
    };
    const adapterManifest = parseManifest(document);
    const launch = () =>
      DistributionAccess.open({
        app: adapterManifest.app,
        mode: "personal",
        access: adapterManifest.access as AccessManifest,
        stateDir: stateDir(),
        distributionDir: temp,
        env: { MYPI_MODEL_URL: "http://127.0.0.1:9/v1" },
      }).activate();
    const recorded = globalThis as { __pishipPersonalAcquires?: unknown[] };
    delete recorded.__pishipPersonalAcquires;
    try {
      for (let count = 0; count < 3; count++)
        expect((await launch()).credential.secret?.reveal()).toBe(
          "sk-adapter-sentinel-0001",
        );
      // Acquired once, with no identity, then reused: an unbound credential
      // matches a distribution that has no identity.
      expect(recorded.__pishipPersonalAcquires).toEqual([null]);
      expect(existsSync(join(stateDir(), "identity"))).toBe(false);
    } finally {
      delete recorded.__pishipPersonalAcquires;
    }
  });
});
