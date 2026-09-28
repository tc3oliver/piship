import {
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
import { fileURLToPath } from "node:url";
import { MemorySecretStore } from "@piship/credentials";
import {
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
  DistributionAccess,
  explainConfiguration,
  networkPolicyFor,
  resolveRuntimeReferences,
} from "./access.js";
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
      runtime: { pi: "0.87.1" },
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
    await expect(
      DistributionAccess.open(options).activate(),
    ).rejects.toMatchObject({ code: "CONFIG_INVALID" });
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
      runtime: { pi: "0.87.1" },
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
    const context = (globalThis as Record<string, unknown>)
      .__pishipAdapterContext as Record<string, unknown>;
    expect(context).toMatchObject({
      distributionId: "mypi",
      endpoints: { baseUrl: services.gatewayUrl },
    });
    expect(typeof context.fetch).toBe("function");
    expect(JSON.stringify(context)).not.toContain("sk-adapter");
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
});
