import {
  chmodSync,
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
import { join } from "node:path";
import { inspect } from "node:util";
import { fileURLToPath } from "node:url";
import { LocalMetrics } from "@piship/audit";
import { PiShipError, SecretValue } from "@piship/contracts";
import { PISHIP_VERSION } from "./compatibility.js";
import { MemorySecretStore } from "@piship/credentials";
import { computeCapabilityStates } from "@piship/policy";
import {
  type CapabilityConfig,
  parseManifest,
  PISHIP_SCHEMA_V1ALPHA2,
  readManifest,
  type AccessManifest,
  type Manifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  type AccessEvent,
  boundedCredentialProvider,
  DistributionAccess,
  accessStatePaths,
  configuredModel,
  explainConfiguration,
  networkPolicyFor,
  recordGatewayResult,
  resolveRuntimeReferences,
} from "./access/index.js";
import {
  readPreferences,
  resolveEffectiveConfig,
  setPreference,
} from "./config.js";

const demo = readManifest(
  fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;
let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-core-access-"));
});
afterEach(() => rmSync(temp, { recursive: true, force: true }));

describe("configuration precedence", () => {
  it("resolves enforced > defaults > permitted user preferences with visible notices", () => {
    const effective = resolveEffectiveConfig(
      access,
      undefined,
      {
        schema: "piship-preferences/v1",
        values: {
          theme: "light",
          model: "acme/general",
          thinkingLevel: "high",
        },
      },
      undefined,
    );
    expect(effective.values).toEqual({
      model: "acme/general",
      theme: "dark",
      thinkingLevel: "high",
    });
    expect(
      effective.entries.find((entry) => entry.key === "theme"),
    ).toMatchObject({ source: "distribution-enforced", overridable: false });
    expect(
      effective.entries.find((entry) => entry.key === "model"),
    ).toMatchObject({ source: "user-preference" });
    expect(effective.notices).toEqual([
      "Preference theme=light is ignored: the distribution enforces dark",
    ]);
    const defaults = resolveEffectiveConfig(access, undefined, {
      schema: "piship-preferences/v1",
      values: {},
    });
    expect(defaults.values).toEqual({
      model: "acme/coder",
      theme: "dark",
      thinkingLevel: "off",
    });
  });
  it("intersects model allowlists and never lets a user widen them", () => {
    const effective = resolveEffectiveConfig(
      access,
      undefined,
      {
        schema: "piship-preferences/v1",
        values: {},
        modelsAllowed: ["acme/coder", "acme/review"],
      },
      ["acme/coder", "acme/general"],
    );
    expect(effective.allowedModels).toEqual(["acme/coder"]);
    expect(effective.entries.at(-1)).toMatchObject({
      key: "models.allowed",
      source: "intersection",
    });
  });
  it("makes an enforced model the only selectable model", () => {
    const enforced = {
      ...access,
      config: {
        ...access.config,
        enforced: { model: "acme/coder" },
        userOverridable: ["thinkingLevel" as const],
      },
    } as AccessManifest;
    const effective = resolveEffectiveConfig(enforced, undefined, {
      schema: "piship-preferences/v1",
      values: { model: "acme/general" },
    });
    expect(effective.values.model).toBe("acme/coder");
    expect(effective.allowedModels).toEqual(["acme/coder"]);
    expect(effective.notices).toEqual([
      "Preference model=acme/general is ignored: the distribution enforces acme/coder",
    ]);
    expect(() =>
      setPreference(
        join(temp, "p.json"),
        enforced,
        undefined,
        "model",
        "acme/general",
      ),
    ).toThrow("enforced");
  });

  it("keeps an enforced model when a user narrows an otherwise open allowlist", () => {
    const open = {
      ...access,
      models: { ...access.models, allowed: [] },
      config: { ...access.config, enforced: { model: "openai/gpt-x" } },
    } as AccessManifest;
    const narrowed = resolveEffectiveConfig(open, undefined, {
      schema: "piship-preferences/v1",
      values: {},
      modelsAllowed: ["anthropic/other"],
    });
    expect(narrowed).toMatchObject({
      allowedModels: [],
      modelsRestricted: true,
    });
    const kept = resolveEffectiveConfig(open, undefined, {
      schema: "piship-preferences/v1",
      values: {},
      modelsAllowed: ["openai/gpt-x", "anthropic/other"],
    });
    expect(kept.allowedModels).toEqual(["openai/gpt-x"]);
    const unrestricted = {
      ...open,
      config: { ...open.config, enforced: {} },
    } as AccessManifest;
    expect(
      resolveEffectiveConfig(unrestricted, undefined, {
        schema: "piship-preferences/v1",
        values: {},
      }),
    ).toMatchObject({ allowedModels: [], modelsRestricted: false });
    expect(
      resolveEffectiveConfig(unrestricted, undefined, {
        schema: "piship-preferences/v1",
        values: {},
        modelsAllowed: ["anthropic/other"],
      }),
    ).toMatchObject({
      allowedModels: ["anthropic/other"],
      modelsRestricted: true,
    });
  });

  it("enforces the effective allowlist for Pi-native personal distributions", async () => {
    const personal = parseManifest({
      schema: PISHIP_SCHEMA_V1ALPHA2,
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: { pi: "1.0.3" },
      deployment: { mode: "personal" },
      config: { enforced: { model: "openai/gpt-x" } },
    });
    const distribution = DistributionAccess.open({
      app: personal.app,
      mode: "personal",
      access: personal.access as AccessManifest,
      stateDir: join(temp, "state"),
      distributionDir: temp,
      env: {},
      secretStore: new MemorySecretStore(),
    });
    await expect(
      distribution.activate({ requestedModel: "anthropic/claude-whatever" }),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
    await expect(
      distribution.activate({ requestedModel: "openai/gpt-x" }),
    ).resolves.toMatchObject({
      selectedModel: "openai/gpt-x",
      config: { allowedModels: ["openai/gpt-x"], modelsRestricted: true },
    });
  });

  it("refuses enforced, security-sensitive, disallowed, and widening preferences", () => {
    const path = join(temp, "config", "preferences.json");
    expect(() =>
      setPreference(path, access, undefined, "theme", "light"),
    ).toThrow("enforced by the distribution");
    for (const key of [
      "inference.baseUrl",
      "credential.provider",
      "identity.oidc.issuer",
      "network.privateOnly",
    ])
      expect(() => setPreference(path, access, undefined, key, "x")).toThrow(
        "security-sensitive",
      );
    expect(() =>
      setPreference(path, access, undefined, "model", "openai/gpt-4o"),
    ).toThrow("not allowed");
    expect(() =>
      setPreference(
        path,
        access,
        undefined,
        "models.allowed",
        "acme/coder,public/model",
      ),
    ).toThrow("only narrow");
    setPreference(path, access, undefined, "model", "acme/general");
    setPreference(
      path,
      access,
      undefined,
      "models.allowed",
      "acme/coder,acme/general",
    );
    expect(readPreferences(path)).toEqual({
      schema: "piship-preferences/v1",
      values: { model: "acme/general" },
      modelsAllowed: ["acme/coder", "acme/general"],
    });
    if (process.platform !== "win32")
      expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("sets and unsets a preference over a damaged file by moving it aside, never deleting it", () => {
    const path = join(temp, "config", "preferences.json");
    mkdirSync(join(temp, "config"), { recursive: true });
    writeFileSync(path, "{not json");
    const notices: string[] = [];
    setPreference(path, access, undefined, "model", undefined, (notice) =>
      notices.push(notice),
    );
    const aside = readdirSync(join(temp, "config")).filter((name) =>
      name.startsWith("preferences.json.damaged-"),
    );
    expect(aside).toHaveLength(1);
    expect(readFileSync(join(temp, "config", aside[0] as string), "utf8")).toBe(
      "{not json",
    );
    expect(notices).toHaveLength(1);
    expect(notices[0]).toContain(join(temp, "config", aside[0] as string));
    setPreference(path, access, undefined, "model", "acme/general");
    expect(readPreferences(path).values.model).toBe("acme/general");
  });

  it("does not replace a damaged file it could not move aside", () => {
    if (process.platform === "win32" || process.getuid?.() === 0) return;
    const directory = join(temp, "config");
    const path = join(directory, "preferences.json");
    mkdirSync(directory, { recursive: true });
    writeFileSync(path, "{not json");
    chmodSync(directory, 0o500);
    try {
      expect(() =>
        setPreference(path, access, undefined, "model", "acme/general"),
      ).toThrow("unreadable");
      expect(readFileSync(path, "utf8")).toBe("{not json");
    } finally {
      chmodSync(directory, 0o700);
    }
  });
});

describe("runtime references and network policy", () => {
  it("resolves declared variables at runtime and fails visibly when missing", () => {
    expect(() => resolveRuntimeReferences(access, {})).toThrow(
      "ACMECODE_OIDC_ISSUER",
    );
    const endpoints = resolveRuntimeReferences(access, {
      ACMECODE_OIDC_ISSUER: "https://idp.corp.example/realm",
      ACMECODE_OIDC_CLIENT_ID: "acme-cli",
      ACMECODE_CREDENTIAL_BROKER_URL:
        "https://broker.corp.example/v1/llm-credential",
      ACMECODE_CREDENTIAL_REVOKE_URL: "https://broker.corp.example/v1/revoke",
      ACMECODE_LLM_GATEWAY_URL: "https://llm.corp.example/v1",
    });
    expect(endpoints.baseUrl).toBe("https://llm.corp.example/v1");
    expect(networkPolicyFor(access, endpoints)).toMatchObject({
      privateOnly: true,
      allowHosts: [
        "broker.corp.example",
        "idp.corp.example",
        "llm.corp.example",
      ],
    });
    expect(() =>
      resolveRuntimeReferences(access, {
        ACMECODE_OIDC_ISSUER: "http://idp.public.example",
        ACMECODE_OIDC_CLIENT_ID: "a",
        ACMECODE_CREDENTIAL_BROKER_URL: "https://b.example",
        ACMECODE_CREDENTIAL_REVOKE_URL: "https://b.example",
        ACMECODE_LLM_GATEWAY_URL: "https://l.example",
      }),
    ).toThrow("unacceptable URL");
  });

  it("enforces publicFallback: deny as private-only in managed mode", () => {
    const endpoints = {
      additionalCA: [],
      baseUrl: "https://llm.corp.example/v1",
    };
    const declared = (
      privateOnly: boolean,
      publicFallback: "deny" | "allow",
    ): AccessManifest => ({
      ...access,
      network: { ...access.network, privateOnly, publicFallback },
    });
    // Managed mode requires deny, so it is always private-only.
    expect(
      networkPolicyFor(declared(false, "deny"), endpoints, "managed"),
    ).toMatchObject({ privateOnly: true, allowHosts: ["llm.corp.example"] });
    // Personal mode keeps network.privateOnly as declared.
    expect(
      networkPolicyFor(declared(false, "allow"), endpoints, "personal")
        .privateOnly,
    ).toBe(false);
    expect(
      networkPolicyFor(declared(false, "deny"), endpoints).privateOnly,
    ).toBe(false);
    expect(
      networkPolicyFor(declared(true, "allow"), endpoints, "personal")
        .privateOnly,
    ).toBe(true);
  });
});

function secretScan(root: string, secrets: readonly string[]): string[] {
  const hits: string[] = [];
  const visit = (directory: string) => {
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      if (statSync(path).isDirectory()) visit(path);
      else {
        const text = readFileSync(path, "utf8");
        for (const secret of secrets)
          if (text.includes(secret))
            hits.push(`${path}: ${secret.slice(0, 8)}…`);
      }
    }
  };
  visit(root);
  return hits;
}

describe("Identity → Credential → Inference orchestration (fixtures)", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  let options: Parameters<typeof DistributionAccess.open>[0];
  let store: MemorySecretStore;
  beforeEach(async () => {
    services = await startLocalServices();
    store = new MemorySecretStore();
    const localAccess = {
      ...access,
      identity: {
        ...access.identity,
        oidc: {
          ...(access.identity as { oidc: object }).oidc,
          redirectUri: "http://127.0.0.1/callback",
        },
      },
    } as AccessManifest;
    options = {
      app: demo.app as Manifest["app"],
      mode: "managed",
      access: localAccess,
      stateDir: join(temp, "state"),
      distributionDir: temp,
      env: services.env(),
      secretStore: store,
    };
  });
  afterEach(() => services.close());

  it("logs in, activates the allowed catalog, refreshes, logs out, and never writes secrets to state", async () => {
    const distribution = DistributionAccess.open(options);
    await expect(distribution.activate()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
    const login = await distribution.login({
      openUrl: (url) => void services.approve(url),
    });
    expect(login.identity?.subject).toBe("demo-user-1");
    const activated = await distribution.activate();
    expect(activated.selectedModel).toBe("acme/coder");
    expect(activated.config.allowedModels).toEqual([
      "acme/coder",
      "acme/general",
    ]);
    expect(
      activated.models.find((model) => model.id === "acme/review")?.availability
        .available,
    ).toBe(false);
    await expect(
      distribution.activate({ requestedModel: "acme/review" }),
    ).rejects.toMatchObject({ code: "MODEL_UNAVAILABLE" });
    await expect(
      distribution.activate({ requestedModel: "public/model" }),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
    const first = await distribution.requestSecret();
    const forced = await distribution.requestSecret({ force: true });
    expect(forced?.reveal()).not.toBe(first?.reveal());
    const context = distribution.enterpriseContext(activated);
    expect(Object.isFrozen(context.inference)).toBe(true);
    expect(context.identity).toEqual({
      subject: "demo-user-1",
      issuer: services.issuer,
      displayName: "Demo Developer",
      email: "developer@demo.example",
    });
    const secrets = [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    ];
    expect(secrets.length).toBeGreaterThan(3);
    expect(secretScan(join(temp, "state"), secrets)).toEqual([]);
    expect(JSON.stringify(context)).not.toMatch(/sk-demo|demo-at-|demo-rt-/);
    const explained = JSON.stringify(await explainConfiguration(options));
    for (const secret of secrets) expect(explained).not.toContain(secret);
    expect(await distribution.logout()).toEqual([]);
    expect(store.refs()).toEqual([]);
    expect(services.state.revokedCredentials).toEqual(["vk_demo_2"]);
    await expect(
      DistributionAccess.open(options).activate(),
    ).rejects.toMatchObject({ code: "IDENTITY_REQUIRED" });
  });

  it("identifies the distribution, its version, and PiShip to the broker and the gateway", async () => {
    const distribution = DistributionAccess.open(options);
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    const activated = await distribution.activate();
    await distribution.logout();
    const client = `distribution="${demo.app.id}", version="${demo.app.version}", piship="${PISHIP_VERSION}", protocol=1`;
    const seen = services.state.requests
      .filter(
        (item: { path: string }) =>
          item.path.startsWith("/broker/") || item.path.startsWith("/gateway/"),
      )
      .map((item: { path: string; client: string | null }) => [
        item.path,
        item.client,
      ]);
    expect(seen.map(([path]: string[]) => path)).toEqual(
      expect.arrayContaining([
        "/broker/v1/llm-credential",
        "/gateway/v1/models",
        "/broker/v1/revoke",
      ]),
    );
    for (const [path, value] of seen) expect(value, path).toBe(client);
    expect(activated.runtime.headers).toEqual({ "piship-client": client });
  });

  it("adopts a credential another process renewed after the same rejection instead of issuing a second", async () => {
    const login = DistributionAccess.open(options);
    await login.login({ openUrl: (url) => void services.approve(url) });
    // Two processes hold the same credential, and the gateway rejects it for both.
    const first = DistributionAccess.open(options);
    const second = DistributionAccess.open(options);
    const rejected = (await first.requestSecret())?.reveal();
    expect((await second.requestSecret())?.reveal()).toBe(rejected);
    const renewed = (await first.requestSecret({ force: true }))?.reveal();
    expect(renewed).not.toBe(rejected);
    // The second renews the generation it saw rejected, which is already
    // replaced: it adopts the renewal instead of issuing another credential.
    expect((await second.requestSecret({ force: true }))?.reveal()).toBe(
      renewed,
    );
    expect(services.state.credentials.size).toBe(2);
  });

  it("reports corrupt preferences in explain output instead of crashing", async () => {
    const { mkdirSync, writeFileSync } = await import("node:fs");
    mkdirSync(join(temp, "state", "config"), { recursive: true });
    writeFileSync(
      join(temp, "state", "config", "preferences.json"),
      "{not json",
    );
    const rows = await explainConfiguration(options);
    expect(rows.find((row) => row.key === "preferences")?.note).toContain(
      "unreadable",
    );
  });

  it("moves damaged preferences aside at launch, runs with the defaults, and says where they went", async () => {
    const directory = join(temp, "state", "config");
    const path = join(directory, "preferences.json");
    mkdirSync(directory, { recursive: true });
    writeFileSync(path, "{not json");
    const distribution = DistributionAccess.open(options);
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    const activated = await distribution.activate();
    const aside = readdirSync(directory).filter((name) =>
      name.startsWith("preferences.json.damaged-"),
    );
    expect(aside).toHaveLength(1);
    expect(readFileSync(join(directory, aside[0] as string), "utf8")).toBe(
      "{not json",
    );
    expect(existsSync(path)).toBe(false);
    expect(
      activated.notices.some(
        (notice) =>
          notice.includes("unreadable") &&
          notice.includes(join(directory, aside[0] as string)),
      ),
    ).toBe(true);
  });

  it("fails closed when the broker or gateway is unavailable", async () => {
    const distribution = DistributionAccess.open(options);
    services.knobs.brokerStatus = 503;
    await expect(
      distribution.login({ openUrl: (url) => void services.approve(url) }),
    ).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    services.knobs.brokerStatus = undefined;
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    services.knobs.entitledModels = [];
    await DistributionAccess.open(options).requestSecret({ force: true });
    await expect(
      DistributionAccess.open(options).activate(),
    ).rejects.toMatchObject({ code: "MODEL_UNAVAILABLE" });
  });

  it("re-authenticates the identity when the broker rejects an expired access token", async () => {
    services.knobs.accessTokenTtl = 3600;
    const distribution = DistributionAccess.open(options);
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    services.state.accessTokens.clear();
    const secret = await DistributionAccess.open(options).requestSecret({
      force: true,
    });
    expect(secret?.reveal()).toMatch(/^sk-demo-/);
    expect(
      services.state.requests.filter((item: { body: string }) =>
        item.body.includes("grant_type=refresh_token"),
      ),
    ).toHaveLength(1);
  });
});

describe("access metrics (fixtures)", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  let options: Parameters<typeof DistributionAccess.open>[0];
  let metrics: LocalMetrics;
  let clock: number;
  beforeEach(async () => {
    services = await startLocalServices();
    metrics = new LocalMetrics(join(temp, "state"));
    clock = Date.now();
    options = {
      app: demo.app as Manifest["app"],
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
      } as AccessManifest,
      stateDir: join(temp, "state"),
      distributionDir: temp,
      env: services.env(),
      secretStore: new MemorySecretStore(),
      // Each read of the clock advances it, so every duration is positive.
      now: () => (clock += 5),
      metrics,
    };
  });
  afterEach(() => services.close());

  it("records identity and credential durations, gateway reachability, and the live catalog", async () => {
    const distribution = DistributionAccess.open(options);
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    // Sign-in and the broker acquisition.
    expect(metrics.snapshot().latency).toMatchObject({
      identity: { count: 1 },
      "credential.acquire": { count: 1 },
    });
    const activated = await DistributionAccess.open(options).activate();
    const snapshot = metrics.snapshot();
    // The session check is timed; reusing the stored credential is not.
    expect(snapshot.latency?.identity?.count).toBe(2);
    expect(snapshot.latency?.["credential.acquire"]?.count).toBe(1);
    expect(snapshot.latency?.["credential.refresh"]).toBeUndefined();
    expect(snapshot.gateway).toMatchObject({
      reachable: true,
      reachableCount: 1,
      unreachableCount: 0,
    });
    expect(snapshot.modelCatalog?.models).toBe(activated.models.length);
    await DistributionAccess.open(options).requestSecret({ force: true });
    expect(metrics.snapshot().latency?.["credential.refresh"]?.count).toBe(1);
    // Metadata only: no token, credential, URL, or subject.
    const text = JSON.stringify(metrics.snapshot());
    for (const secret of [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
    ])
      expect(text).not.toContain(secret);
    expect(text).not.toContain("127.0.0.1");
    expect(text).not.toContain("demo-user-1");
  });

  it("records an unreachable gateway by error code and a doctor probe", async () => {
    await DistributionAccess.open(options).login({
      openUrl: (url) => void services.approve(url),
    });
    // Doctor probes after activation, which already fetched the live
    // catalog: one doctor run counts the gateway once.
    const doctor = DistributionAccess.open(options);
    await doctor.activate();
    expect(await doctor.probeGateway()).toContain("acme/coder");
    expect(metrics.snapshot().gateway?.reachableCount).toBe(1);
    // A probe on its own is recorded; a 401 answer is still reachable.
    await expect(
      DistributionAccess.open(options).probeGateway(),
    ).rejects.toMatchObject({ code: "CREDENTIAL_REVOKED" });
    expect(metrics.snapshot().gateway?.reachableCount).toBe(2);
    const unreachable = DistributionAccess.open({
      ...options,
      env: {
        ...services.env(),
        ACMECODE_LLM_GATEWAY_URL: "http://127.0.0.1:1/gateway/v1",
      },
    });
    await expect(unreachable.activate()).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
    });
    expect(metrics.snapshot().gateway).toMatchObject({
      reachable: false,
      code: "GATEWAY_UNREACHABLE",
      reachableCount: 2,
      unreachableCount: 1,
    });
    expect(metrics.snapshot().gateway?.lastReachableAt).toBeDefined();
    expect(metrics.snapshot().modelCatalog?.models).toBe(3);
  });

  it("classifies gateway answers as reachable and transport failures as not", () => {
    const local = new LocalMetrics(temp);
    recordGatewayResult(local, new PiShipError("CREDENTIAL_REVOKED", "401"));
    expect(local.snapshot().gateway?.reachable).toBe(true);
    recordGatewayResult(local, new PiShipError("NETWORK_DENIED", "denied"));
    expect(local.snapshot().gateway).toMatchObject({
      reachable: false,
      code: "NETWORK_DENIED",
    });
    recordGatewayResult(local, new Error("timeout"));
    expect(local.snapshot().gateway).toMatchObject({
      reachable: false,
      code: "UNKNOWN",
    });
    recordGatewayResult(undefined, new Error("ignored"));
  });
});

describe("credential adapters", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  beforeEach(async () => {
    services = await startLocalServices({
      knobs: { acceptedKeys: ["sk-adapter-issued-key"] },
    });
  });
  afterEach(() => services.close());
  const open = (adapter: string) => {
    const manifest = parseManifest({
      schema: PISHIP_SCHEMA_V1ALPHA2,
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: { pi: "1.0.3" },
      deployment: { mode: "personal" },
      credential: { provider: "adapter", adapter },
      inference: {
        provider: "openai-compatible",
        baseUrl: services.gatewayUrl,
      },
      models: {
        allowed: ["acme/coder"],
        catalog: {
          "acme/coder": {
            name: "Coder",
            contextWindow: 32000,
            maxOutputTokens: 2048,
          },
        },
      },
    });
    return DistributionAccess.open({
      app: manifest.app,
      mode: "personal",
      access: manifest.access as AccessManifest,
      stateDir: join(temp, "state"),
      distributionDir: temp,
      env: {},
      secretStore: new MemorySecretStore(),
    });
  };
  const write = (name: string, source: string) => {
    mkdirSync(join(temp, "resources", "adapters"), { recursive: true });
    writeFileSync(join(temp, "resources", "adapters", name), source);
  };

  it("loads the adapter from the payload with a token-free context and uses its credential", async () => {
    write(
      "credential.mjs",
      `export default (context) => {
        globalThis.__pishipAdapterContext = context;
        return {
          mode: "adapter",
          requiresIdentity: false,
          async acquire() {
            return {
              kind: "api_key",
              secret: { reveal: () => "sk-adapter-issued-key" },
            };
          },
        };
      };`,
    );
    const distribution = open("./adapters/credential.mjs");
    const activated = await distribution.activate({
      requestedModel: "acme/coder",
    });
    expect(activated.selectedModel).toBe("acme/coder");
    expect(activated.credential.secret?.reveal()).toBe("sk-adapter-issued-key");
    // The adapter's duck-typed secret is re-wrapped, so it always redacts.
    expect(activated.credential.secret).toBeInstanceOf(SecretValue);
    expect(JSON.stringify(activated.credential)).not.toContain("sk-adapter");
    expect(inspect(activated.credential, { depth: 10 })).not.toContain(
      "sk-adapter",
    );
    const context = (globalThis as Record<string, unknown>)
      .__pishipAdapterContext as Record<string, unknown>;
    expect(context).toMatchObject({
      distributionId: "mypi",
      endpoints: { baseUrl: services.gatewayUrl },
    });
    expect(typeof context.fetch).toBe("function");
    expect(JSON.stringify(context)).not.toContain("sk-adapter");
  });

  it("counts adapter load failures as provider load failures", async () => {
    const metrics = new LocalMetrics(join(temp, "state"));
    const distribution = DistributionAccess.open({
      ...open("./adapters/missing.mjs").options,
      metrics,
    });
    await expect(distribution.activate()).rejects.toMatchObject({
      code: "CONFIG_INVALID",
    });
    write("throws.mjs", "throw new Error('adapter crashed');");
    await expect(
      DistributionAccess.open({
        ...open("./adapters/throws.mjs").options,
        metrics,
      }).activate(),
    ).rejects.toThrow("adapter crashed");
    expect(metrics.snapshot().providerLoadFailures).toEqual({
      CONFIG_INVALID: 1,
      UNKNOWN: 1,
    });
    expect(metrics.snapshot().resourceLoadFailures).toBeUndefined();
  });

  it("fails visibly for a missing or malformed adapter", async () => {
    await expect(
      open("./adapters/missing.mjs").activate(),
    ).rejects.toMatchObject({
      code: "CONFIG_INVALID",
      message: expect.stringContaining("missing from the verified payload"),
    });
    write("object.mjs", "export default { acquire() {} };");
    await expect(
      open("./adapters/object.mjs").activate(),
    ).rejects.toMatchObject({
      code: "CONFIG_INVALID",
      message: expect.stringContaining("default-export a factory"),
    });
    write("empty.mjs", "export default () => null;");
    await expect(open("./adapters/empty.mjs").activate()).rejects.toMatchObject(
      {
        code: "CONFIG_INVALID",
        message: expect.stringContaining("returned no provider"),
      },
    );
  });

  it("stops waiting for an adapter whose acquire never settles, releases the lock, and repeats the key", {
    timeout: 5_000,
  }, async () => {
    write(
      "hangs.mjs",
      `export default () => ({
        mode: "adapter",
        requiresIdentity: false,
        acquire(_identity, ctx) {
          (globalThis.__pishipHungAcquire ??= []).push(ctx);
          return new Promise(() => {});
        },
      });`,
    );
    const options = {
      ...open("./adapters/hangs.mjs").options,
      adapterTimeoutMs: 50,
    };
    const timedOut = {
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
      message:
        "The credential adapter ./adapters/hangs.mjs did not answer acquire() within 1 s",
      sanitizedDetail: expect.objectContaining({
        adapter: "./adapters/hangs.mjs",
        phase: "acquire",
        reason: "timeout",
        outcome: "unknown",
      }),
    };
    await expect(
      DistributionAccess.open(options).activate(),
    ).rejects.toMatchObject(timedOut);
    // The lock is free (a held one would keep the next launch waiting) and
    // the request whose answer never came keeps its idempotency key.
    const locks = readdirSync(join(temp, "state"), { recursive: true }).filter(
      (name) => String(name).endsWith(".lock"),
    );
    expect(locks).toEqual([]);
    await expect(
      DistributionAccess.open(options).activate(),
    ).rejects.toMatchObject(timedOut);
    const calls = (globalThis as Record<string, unknown>)
      .__pishipHungAcquire as {
      idempotencyKey?: string;
      signal?: AbortSignal;
    }[];
    expect(calls).toHaveLength(2);
    expect(calls.every((ctx) => ctx.signal?.aborted)).toBe(true);
    expect(calls[0]?.idempotencyKey).toBeTruthy();
    expect(calls[1]?.idempotencyKey).toBe(calls[0]?.idempotencyKey);
  });

  it("stops waiting for an adapter module or factory that never settles", {
    timeout: 5_000,
  }, async () => {
    write("factory.mjs", "export default () => new Promise(() => {});");
    await expect(
      DistributionAccess.open({
        ...open("./adapters/factory.mjs").options,
        adapterTimeoutMs: 50,
      }).activate(),
    ).rejects.toMatchObject({
      code: "CONFIG_UNAVAILABLE",
      retryable: true,
      message:
        "The credential adapter ./adapters/factory.mjs did not load within 1 s",
    });
    write("top-level.mjs", "await new Promise(() => {});");
    await expect(
      DistributionAccess.open({
        ...open("./adapters/top-level.mjs").options,
        adapterTimeoutMs: 50,
      }).activate(),
    ).rejects.toMatchObject({ code: "CONFIG_UNAVAILABLE", retryable: true });
  });
});

describe("credential adapter deadlines", () => {
  const credential = {
    kind: "api_key" as const,
    secret: new SecretValue("sk-late-credential-0001"),
  };
  const late = () => {
    let issue: (value: typeof credential) => void = () => {};
    const revoked: unknown[] = [];
    const provider = boundedCredentialProvider(
      {
        mode: "adapter",
        requiresIdentity: false,
        acquire: () =>
          new Promise((resolve) => {
            issue = resolve;
          }),
        revoke: async (value) => {
          revoked.push(value);
        },
      },
      "./adapters/late.mjs",
      { timeoutMs: 20 },
    );
    return { provider, issue: (value = credential) => issue(value), revoked };
  };
  const settled = () => new Promise((resolve) => setTimeout(resolve, 10));

  it("revokes a credential issued after the deadline for a request no key can repeat", async () => {
    const { provider, issue, revoked } = late();
    await expect(
      provider.acquire(null, { distributionId: "mypi" }),
    ).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    issue();
    await settled();
    expect(revoked).toEqual([credential]);
  });

  it("leaves a late credential to the idempotency key that recovers it", async () => {
    const { provider, issue, revoked } = late();
    await expect(
      provider.acquire(null, { distributionId: "mypi", idempotencyKey: "k-1" }),
    ).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    issue();
    await settled();
    expect(revoked).toEqual([]);
  });

  it("ends a cancelled call that ignores its signal, and keeps the provider's declarations", async () => {
    const provider = boundedCredentialProvider(
      Object.assign(
        {
          mode: "adapter" as const,
          requiresIdentity: true,
          acquire: () => new Promise<never>(() => {}),
        },
        { revocable: false },
      ),
      "./adapters/hangs.mjs",
    );
    const controller = new AbortController();
    const acquire = provider.acquire(null, {
      distributionId: "mypi",
      signal: controller.signal,
    });
    controller.abort();
    await expect(acquire).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: false,
      sanitizedDetail: expect.objectContaining({ outcome: "unknown" }),
    });
    expect(provider).toMatchObject({
      mode: "adapter",
      requiresIdentity: true,
      revocable: false,
    });
    expect(provider.refresh).toBeUndefined();
    expect(provider.revoke).toBeUndefined();
  });
});

describe("access lifecycle events and identity refresh (fixtures)", () => {
  let services: Awaited<ReturnType<typeof startLocalServices>>;
  let options: Parameters<typeof DistributionAccess.open>[0];
  let store: MemorySecretStore;
  let events: AccessEvent[];
  beforeEach(async () => {
    services = await startLocalServices();
    store = new MemorySecretStore();
    events = [];
    options = {
      app: demo.app as Manifest["app"],
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
      } as AccessManifest,
      stateDir: join(temp, "state"),
      distributionDir: temp,
      env: services.env(),
      secretStore: store,
      onEvent: (event) => events.push(event),
    };
  });
  afterEach(() => services.close());
  const names = () => events.map((event) => event.event);

  it("records acquisitions, renewals, replacement revokes, and sign-out accurately without secrets", async () => {
    const distribution = DistributionAccess.open(options);
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    expect(names()).toEqual(["identity.login", "credential.acquire"]);
    // A launch that reuses the stored credential acquires nothing.
    events.length = 0;
    await DistributionAccess.open(options).activate();
    expect(names()).toEqual([]);
    // Login again: the previous credential is revoked before it is replaced.
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    // The previous credential is revoked and deleted before the new
    // identity is stored.
    expect(events).toEqual([
      {
        event: "credential.revoke",
        detail: expect.objectContaining({
          mode: "http-broker",
          reason: "replace",
          revocation: "revoked",
          credentialId: "vk_demo_1",
        }),
      },
      { event: "identity.login", detail: { expiresAt: expect.any(String) } },
      {
        event: "credential.acquire",
        detail: expect.objectContaining({ credentialId: "vk_demo_2" }),
      },
    ]);
    expect(services.state.revokedCredentials).toEqual(["vk_demo_1"]);
    // A gateway rejection renews the credential: a refresh, not an acquire.
    events.length = 0;
    for (const entry of services.state.credentials.values())
      entry.revoked = true;
    services.knobs.gatewayModels = ["acme/coder", "acme/general"];
    await DistributionAccess.open(options).requestSecret({ force: true });
    expect(events).toEqual([
      {
        event: "credential.refresh",
        detail: expect.objectContaining({ reason: "rejected" }),
      },
    ]);
    events.length = 0;
    expect(await distribution.logout()).toEqual([]);
    expect(events).toEqual([
      {
        event: "credential.revoke",
        detail: expect.objectContaining({
          reason: "logout",
          revocation: "revoked",
        }),
      },
      { event: "identity.logout", detail: { revocation: "completed" } },
    ]);
    // Signing out again finds nothing and records nothing.
    events.length = 0;
    expect(await distribution.logout()).toEqual([]);
    expect(events).toEqual([]);
    const secrets = [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    ];
    const text = JSON.stringify(events);
    for (const secret of secrets) expect(text).not.toContain(secret);
  });

  it("reports unsupported revocation for a broker without a revoke endpoint", async () => {
    const noRevoke = {
      ...options,
      access: {
        ...options.access,
        credential: {
          ...(options.access as AccessManifest).credential,
          broker: {
            endpoint: (options.access as AccessManifest).credential.broker
              ?.endpoint,
          },
        },
      } as AccessManifest,
    };
    const distribution = DistributionAccess.open(noRevoke);
    await distribution.login({ openUrl: (url) => void services.approve(url) });
    events.length = 0;
    await distribution.logout();
    expect(events[0]).toMatchObject({
      event: "credential.revoke",
      detail: { revocation: "unsupported" },
    });
    expect(services.state.revokedCredentials).toEqual([]);
  });

  it("shares one identity refresh between concurrent launches with rotating refresh tokens", async () => {
    // Access tokens that expire within the 60-second refresh window.
    services.knobs.accessTokenTtl = 30;
    await DistributionAccess.open(options).login({
      openUrl: (url) => void services.approve(url),
    });
    events.length = 0;
    const [first, second] = await Promise.all([
      DistributionAccess.open(options).currentIdentity({ required: true }),
      DistributionAccess.open(options).currentIdentity({ required: true }),
    ]);
    const refreshes = services.state.requests.filter((item: { body: string }) =>
      item.body.includes("grant_type=refresh_token"),
    );
    expect(refreshes).toHaveLength(1);
    expect(first?.accessToken?.reveal()).toBe(second?.accessToken?.reveal());
    expect(names()).toEqual(["identity.refresh"]);
    expect(events[0]?.detail).toMatchObject({ reason: "expiring" });
    // Only the current identity generation (and none of the replaced one) is stored.
    expect(store.refs().filter((ref) => ref.includes(":identity#"))).toEqual([
      "piship:acmecode:identity#2",
    ]);
    // A later launch keeps working with the rotated refresh token.
    await expect(
      DistributionAccess.open(options).currentIdentity({ required: true }),
    ).resolves.toMatchObject({ subject: "demo-user-1" });
  });
});

describe("identity requirements of credential providers", () => {
  it("rejects an adapter that requires identity when identity.mode is none", async () => {
    const manifest = parseManifest({
      schema: PISHIP_SCHEMA_V1ALPHA2,
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: { pi: "1.0.3" },
      deployment: { mode: "personal" },
      credential: { provider: "adapter", adapter: "./adapters/needs-id.mjs" },
      inference: {
        provider: "openai-compatible",
        baseUrl: "http://127.0.0.1:9/v1",
      },
      models: {
        allowed: ["acme/coder"],
        catalog: {
          "acme/coder": {
            name: "Coder",
            contextWindow: 32000,
            maxOutputTokens: 2048,
          },
        },
      },
    });
    mkdirSync(join(temp, "resources", "adapters"), { recursive: true });
    writeFileSync(
      join(temp, "resources", "adapters", "needs-id.mjs"),
      `export default () => ({
        mode: "adapter",
        requiresIdentity: true,
        async acquire(identity) {
          globalThis.__pishipNullIdentity = identity === null;
          return { kind: "api_key", secret: "sk-never-issued-000" };
        },
      });`,
    );
    const distribution = DistributionAccess.open({
      app: manifest.app,
      mode: "personal",
      access: manifest.access as AccessManifest,
      stateDir: join(temp, "state"),
      distributionDir: temp,
      env: {},
      secretStore: new MemorySecretStore(),
    });
    await expect(distribution.activate()).rejects.toMatchObject({
      code: "CONFIG_INVALID",
      message: expect.stringContaining("requires a signed-in identity"),
    });
    await expect(
      distribution.login({ openUrl: () => {} }),
    ).rejects.toMatchObject({ code: "CONFIG_INVALID" });
    expect(
      (globalThis as Record<string, unknown>).__pishipNullIdentity,
    ).toBeUndefined();
  });
});

describe("capability model requirements", () => {
  const capability = (
    requirements: CapabilityConfig["requirements"],
    enabled = true,
  ): CapabilityConfig => ({
    name: "workflow",
    enabled,
    settings: {},
    ...(requirements ? { requirements } : {}),
  });
  describe("at launch (fixtures)", () => {
    let services: Awaited<ReturnType<typeof startLocalServices>>;
    beforeEach(async () => {
      services = await startLocalServices();
    });
    afterEach(() => services.close());
    const open = (capabilities: readonly CapabilityConfig[]) =>
      DistributionAccess.open({
        app: demo.app as Manifest["app"],
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
        } as AccessManifest,
        stateDir: join(temp, "state"),
        distributionDir: temp,
        env: services.env(),
        secretStore: new MemorySecretStore(),
        capabilities,
      });

    it("refuses an incompatible selected model and never substitutes another", async () => {
      const distribution = open([capability({ minContextWindow: 100000 })]);
      await distribution.login({
        openUrl: (url) => void services.approve(url),
      });
      const activated = await distribution.activate();
      expect(activated.selectedModel).toBe("acme/coder");
      expect(activated.incompatibleModels).toEqual({
        "acme/general":
          "workflow: the context window 64000 is below the required 100000",
      });
      expect(() =>
        DistributionAccess.checkSelection(activated, "acme/general"),
      ).toThrow(expect.objectContaining({ code: "MODEL_INCOMPATIBLE" }));
      const error = await distribution
        .activate({ requestedModel: "acme/general" })
        .catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(PiShipError);
      expect(error).toMatchObject({
        code: "MODEL_INCOMPATIBLE",
        retryable: false,
        userAction: "Choose a compatible model with --model: acme/coder",
        sanitizedDetail: {
          model: "acmecode/acme/general",
          capabilities: [
            {
              capability: "workflow",
              reasons: [
                "the context window 64000 is below the required 100000",
              ],
            },
          ],
        },
      });
      expect((error as Error).message).toContain(
        "Model acmecode/acme/general does not meet the model requirements of capability workflow",
      );
      const secrets = [
        ...services.state.credentials.keys(),
        ...services.state.accessTokens.keys(),
      ];
      const text = JSON.stringify(error) + String((error as Error).message);
      for (const secret of secrets) expect(text).not.toContain(secret);
    });

    it("fails closed when no allowed model has the required metadata", async () => {
      const distribution = open([capability({ structuredOutput: true })]);
      await distribution.login({
        openUrl: (url) => void services.approve(url),
      });
      await expect(distribution.activate()).rejects.toMatchObject({
        code: "MODEL_INCOMPATIBLE",
        message: expect.stringContaining(
          "structured output support is unknown",
        ),
        userAction: expect.stringContaining(
          "capabilities.workflow.requirements",
        ),
      });
    });

    it("gives the capability report the same verdict as launch", async () => {
      const compatible = (distribution: DistributionAccess) =>
        computeCapabilityStates({
          capabilities: distribution.options.capabilities ?? [],
          policy: { providerTrust: {} } as never,
          piVersion: "1.0.3",
          platform: process.platform,
          model: configuredModel(distribution.options),
        }).find((state) => state.name === "workflow")?.axes.compatible;
      const meets = open([capability({ minContextWindow: 100000 })]);
      expect(configuredModel(meets.options)).toMatchObject({
        id: "acmecode/acme/coder",
        metadata: { id: "acme/coder" },
      });
      expect(compatible(meets)?.value).not.toBe("no");
      await meets.login({ openUrl: (url) => void services.approve(url) });
      await expect(meets.activate()).resolves.toMatchObject({
        selectedModel: "acme/coder",
      });
      const fails = open([capability({ structuredOutput: true })]);
      expect(compatible(fails)).toEqual({
        value: "no",
        reason:
          "Model acmecode/acme/coder does not meet the model requirements: structured output support is unknown",
      });
      await fails.login({ openUrl: (url) => void services.approve(url) });
      await expect(fails.activate()).rejects.toMatchObject({
        code: "MODEL_INCOMPATIBLE",
        message: expect.stringContaining(
          "capability workflow (structured output support is unknown)",
        ),
      });
    });

    it("reports unreadable preferences offline without moving them", () => {
      const distribution = open([]);
      const path = accessStatePaths(distribution.options.stateDir).preferences;
      mkdirSync(join(path, ".."), { recursive: true });
      writeFileSync(path, "{");
      expect(() => configuredModel(distribution.options)).toThrow(
        expect.objectContaining({ code: "CONFIG_INVALID" }),
      );
      expect(readFileSync(path, "utf8")).toBe("{");
    });

    it("ignores the requirements of a disabled capability", async () => {
      const distribution = open([
        capability({ structuredOutput: true }, false),
      ]);
      await distribution.login({
        openUrl: (url) => void services.approve(url),
      });
      await expect(distribution.activate()).resolves.toMatchObject({
        selectedModel: "acme/coder",
        incompatibleModels: {},
      });
    });
  });

  it("refuses Pi-native models, whose metadata PiShip cannot verify", async () => {
    const personal = parseManifest({
      schema: PISHIP_SCHEMA_V1ALPHA2,
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: { pi: "1.0.3" },
      deployment: { mode: "personal" },
    });
    const open = (capabilities: readonly CapabilityConfig[]) =>
      DistributionAccess.open({
        app: personal.app,
        mode: "personal",
        access: personal.access as AccessManifest,
        stateDir: join(temp, "state"),
        distributionDir: temp,
        env: {},
        secretStore: new MemorySecretStore(),
        capabilities,
      });
    const requiring = open([capability({ tools: true })]);
    await expect(
      requiring.activate({ requestedModel: "openai/gpt-x" }),
    ).rejects.toMatchObject({
      code: "MODEL_INCOMPATIBLE",
      message: expect.stringContaining("tool calling support is unknown"),
    });
    await expect(requiring.activate()).rejects.toMatchObject({
      code: "MODEL_INCOMPATIBLE",
    });
    await expect(
      open([capability(undefined)]).activate({
        requestedModel: "openai/gpt-x",
      }),
    ).resolves.toMatchObject({ selectedModel: "openai/gpt-x" });
  });
});
