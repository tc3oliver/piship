import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { MemorySecretStore } from "@piship/credentials";
import {
  type AccessManifest,
  type Manifest,
  parseManifest,
  PISHIP_SCHEMA_V1ALPHA2,
  readManifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import {
  type AccessEvent,
  type AccessOptions,
  accessStatePaths,
  DistributionAccess,
} from "./access/index.js";
import { resolveEffectiveConfig, setPreference } from "./config.js";

// The effective model catalog (spec §10): the distribution allowlist is the
// ceiling; the credential entitlement, the live gateway listing, and the
// user's preference can only remove models from it. Entitlement freshness
// (F25): a credential without `expires_at` is never renewed on its own, so
// its entitlement is re-read at login and after the gateway denies a model.

const demo = readManifest(
  fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;

// Model names used throughout: the demo catalog declares all three.
const CODER = "acme/coder";
const GENERAL = "acme/general";
const REVIEW = "acme/review";
const BROKER_PATH = "/broker/v1/llm-credential";

type Services = Awaited<ReturnType<typeof startLocalServices>>;

let temp: string;
let services: Services;
let store: MemorySecretStore;
let events: AccessEvent[];
beforeEach(async () => {
  temp = mkdtempSync(join(tmpdir(), "piship-entitlement-"));
  services = await startLocalServices();
  store = new MemorySecretStore();
  events = [];
});
afterEach(async () => {
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

/** The demo distribution against the fixtures, with manifest overrides. */
function options(
  overrides: {
    models?: Partial<AccessManifest["models"]>;
    config?: Partial<AccessManifest["config"]>;
  } = {},
): AccessOptions {
  return {
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
      models: { ...access.models, ...overrides.models },
      config: { ...access.config, ...overrides.config },
    } as AccessManifest,
    stateDir: join(temp, "state"),
    distributionDir: temp,
    env: services.env(),
    secretStore: store,
    onEvent: (event) => events.push(event),
  };
}
async function login(distribution: DistributionAccess): Promise<void> {
  await distribution.login({ openUrl: (url) => void services.approve(url) });
}

function available(
  activated: Awaited<ReturnType<DistributionAccess["activate"]>>,
): string[] {
  return activated.models
    .filter((model) => model.availability.available)
    .map((model) => model.id);
}

function brokerRequests(): number {
  return services.state.requests.filter(
    (item: { path: string }) => item.path === BROKER_PATH,
  ).length;
}

let issued = 0;
/**
 * Queue one broker answer with no `expires_at`, as a broker issuing
 * long-lived gateway keys does. The fixture gateway accepts the sentinel.
 */
function issueWithoutExpiry(models: readonly string[]): void {
  issued += 1;
  const credential = `sk-test-sentinel-no-expiry-${issued}`;
  services.knobs.acceptedKeys.push(credential);
  services.knobs.brokerFaults.push({
    status: 200,
    body: {
      credential_type: "api_key",
      credential,
      credential_id: `vk_test_${issued}`,
      models: [...models],
    },
  });
}

describe("effective model catalog (§10)", () => {
  it("narrows the allowlist to the credential entitlement", async () => {
    services.knobs.entitledModels = [CODER];
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    const activated = await distribution.activate();
    expect(activated.config.allowedModels).toEqual([CODER]);
    expect(available(activated)).toEqual([CODER]);
  });

  it("never widens the allowlist to an entitled model the distribution does not allow", async () => {
    services.knobs.entitledModels = [CODER, REVIEW, "public/model"];
    const distribution = DistributionAccess.open(
      options({ models: { allowed: [CODER, GENERAL] } }),
    );
    await login(distribution);
    const activated = await distribution.activate();
    expect(activated.config.allowedModels).toEqual([CODER]);
    expect(activated.models.map((model) => model.id)).toEqual([CODER, GENERAL]);
    await expect(
      distribution.activate({ requestedModel: REVIEW }),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
  });

  it("lets the live gateway listing remove an allowed, entitled model", async () => {
    services.knobs.entitledModels = [CODER, GENERAL];
    services.knobs.gatewayModels = [CODER];
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    const activated = await distribution.activate();
    expect(available(activated)).toEqual([CODER]);
    expect(
      activated.models.find((model) => model.id === GENERAL)?.availability,
    ).toEqual({
      available: false,
      reason: "not currently listed by the inference gateway",
    });
    await expect(
      distribution.activate({ requestedModel: GENERAL }),
    ).rejects.toMatchObject({ code: "MODEL_UNAVAILABLE" });
  });

  it("never authorizes a model because the live gateway lists it", async () => {
    services.knobs.entitledModels = [CODER];
    services.knobs.gatewayModels = [CODER, GENERAL, REVIEW, "public/model"];
    const distribution = DistributionAccess.open(
      options({ models: { allowed: [CODER, GENERAL] } }),
    );
    await login(distribution);
    const activated = await distribution.activate();
    expect(available(activated)).toEqual([CODER]);
    expect(activated.runtime.models.map((model) => model.id)).toEqual([CODER]);
    await expect(
      distribution.activate({ requestedModel: GENERAL }),
    ).rejects.toMatchObject({ code: "MODEL_UNAVAILABLE" });
    for (const outside of [REVIEW, "public/model"])
      await expect(
        distribution.activate({ requestedModel: outside }),
      ).rejects.toMatchObject({ code: "MODEL_DENIED" });
  });

  it("selects the user's preferred model when it is inside the effective catalog", async () => {
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    setPreference(
      accessStatePaths(join(temp, "state")).preferences,
      access,
      undefined,
      "model",
      GENERAL,
    );
    const activated = await distribution.activate();
    expect(activated.selectedModel).toBe(GENERAL);
  });

  it("refuses a preferred model the credential is not entitled to instead of substituting", async () => {
    services.knobs.entitledModels = [CODER];
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    setPreference(
      accessStatePaths(join(temp, "state")).preferences,
      access,
      undefined,
      "model",
      GENERAL,
    );
    await expect(distribution.activate()).rejects.toMatchObject({
      code: "MODEL_UNAVAILABLE",
      message: expect.stringContaining("runtime credential entitlement"),
    });
  });

  it("names config unset model for a stale preference, which unsets and leaves the listing working", async () => {
    services.knobs.entitledModels = [CODER];
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    const preferences = accessStatePaths(join(temp, "state")).preferences;
    setPreference(preferences, access, undefined, "model", GENERAL);
    await expect(distribution.activate()).rejects.toMatchObject({
      code: "MODEL_UNAVAILABLE",
      userAction: expect.stringContaining(
        "Run acmecode config unset model to remove the model preference, or start acmecode --model <model>; acmecode models lists the models",
      ),
    });
    // The models listing never uses the selection, so it still lists.
    const listed = await distribution.activate({ listOnly: true });
    expect(listed.selectedModel).toBeUndefined();
    expect(available(listed)).toEqual([CODER]);
    // Unsetting the preference recovers.
    setPreference(preferences, access, undefined, "model", undefined);
    expect((await distribution.activate()).selectedModel).toBe(CODER);
  });

  it("names --model and the models command when the entitlement leaves out the default", async () => {
    services.knobs.entitledModels = [GENERAL];
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    const refused = distribution.activate();
    await expect(refused).rejects.toMatchObject({
      code: "MODEL_UNAVAILABLE",
      userAction: expect.stringContaining(
        "Start acmecode --model <model>; acmecode models lists the models",
      ),
    });
    await expect(refused).rejects.not.toMatchObject({
      userAction: expect.stringContaining("config unset model"),
    });
    expect(
      (await distribution.activate({ requestedModel: GENERAL })).selectedModel,
    ).toBe(GENERAL);
  });

  it("lets a user preference only narrow the effective catalog", async () => {
    services.knobs.entitledModels = [CODER, GENERAL];
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    setPreference(
      accessStatePaths(join(temp, "state")).preferences,
      access,
      undefined,
      "models.allowed",
      `${CODER},${REVIEW}`,
    );
    const activated = await distribution.activate();
    expect(activated.config.allowedModels).toEqual([CODER]);
    expect(available(activated)).toEqual([CODER]);
  });

  it("makes an enforced model the only selectable model, over --model and a preference", async () => {
    const enforced = options({
      config: {
        enforced: { theme: "dark", model: GENERAL },
        userOverridable: ["thinkingLevel"],
      },
    });
    const distribution = DistributionAccess.open(enforced);
    await login(distribution);
    const activated = await distribution.activate();
    expect(activated.selectedModel).toBe(GENERAL);
    expect(activated.config.allowedModels).toEqual([GENERAL]);
    await expect(
      distribution.activate({ requestedModel: CODER }),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
  });

  it("does not let an enforced model override a narrower entitlement", async () => {
    services.knobs.entitledModels = [CODER];
    const distribution = DistributionAccess.open(
      options({
        config: {
          enforced: { theme: "dark", model: GENERAL },
          userOverridable: ["thinkingLevel"],
        },
      }),
    );
    await login(distribution);
    await expect(distribution.activate()).rejects.toMatchObject({
      code: "MODEL_UNAVAILABLE",
      message: "No allowed model is currently available",
    });
  });

  it("reports an allowed but unentitled model as MODEL_UNAVAILABLE and a model outside the allowlist as MODEL_DENIED", async () => {
    services.knobs.entitledModels = [CODER, GENERAL];
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    await expect(
      distribution.activate({ requestedModel: REVIEW }),
    ).rejects.toMatchObject({
      code: "MODEL_UNAVAILABLE",
      message: expect.stringContaining("runtime credential entitlement"),
    });
    await expect(
      distribution.activate({ requestedModel: "public/model" }),
    ).rejects.toMatchObject({ code: "MODEL_DENIED" });
  });

  it("yields exactly B for allowlist A,B, entitlement B,C, and live gateway B,C,D", async () => {
    const [A, B, C, D] = [CODER, GENERAL, REVIEW, "acme/unlisted"];
    services.knobs.entitledModels = [B, C];
    services.knobs.gatewayModels = [B, C, D];
    const distribution = DistributionAccess.open(
      options({ models: { allowed: [A, B], default: B } }),
    );
    await login(distribution);
    const activated = await distribution.activate();
    expect(available(activated)).toEqual([B]);
    expect(activated.config.allowedModels).toEqual([B]);
    expect(activated.runtime.models.map((model) => model.id)).toEqual([B]);
    expect(activated.selectedModel).toBe(B);
    expect(
      distribution
        .enterpriseContext(activated)
        .inference.models.map((model) => model.id),
    ).toEqual([B]);
    await expect(
      distribution.activate({ requestedModel: A }),
    ).rejects.toMatchObject({ code: "MODEL_UNAVAILABLE" });
    for (const outside of [C, D])
      await expect(
        distribution.activate({ requestedModel: outside }),
      ).rejects.toMatchObject({ code: "MODEL_DENIED" });
  });

  it("computes the same B for the worked example in the configuration layer", () => {
    const effective = resolveEffectiveConfig(
      {
        ...access,
        models: { ...access.models, allowed: [CODER, GENERAL] },
      },
      undefined,
      { schema: "piship-preferences/v1", values: {} },
      [GENERAL, REVIEW],
    );
    expect(effective.allowedModels).toEqual([GENERAL]);
  });
});

describe("entitlement freshness (F25)", () => {
  it("keeps the entitlement of a credential without expires_at across launches", async () => {
    issueWithoutExpiry([CODER]);
    await login(DistributionAccess.open(options()));
    const before = brokerRequests();
    issueWithoutExpiry([CODER, GENERAL]);
    const activated = await DistributionAccess.open(options()).activate();
    expect(activated.credential.ref?.expiresAt).toBeUndefined();
    expect(activated.config.allowedModels).toEqual([CODER]);
    expect(brokerRequests()).toBe(before);
  });

  it("re-reads the entitlement at login", async () => {
    issueWithoutExpiry([CODER]);
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    issueWithoutExpiry([CODER, GENERAL]);
    await login(distribution);
    const activated = await DistributionAccess.open(options()).activate();
    expect(activated.config.allowedModels).toEqual([CODER, GENERAL]);
  });

  it("re-reads the entitlement through the refresh path after the gateway denies a model", async () => {
    issueWithoutExpiry([CODER]);
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    await distribution.activate();
    const before = brokerRequests();
    events.length = 0;
    issueWithoutExpiry([CODER, GENERAL]);
    await expect(distribution.refreshEntitlement()).resolves.toBe(true);
    expect(brokerRequests()).toBe(before + 1);
    expect(events.map((event) => event.event)).toEqual(["credential.refresh"]);
    const activated = await DistributionAccess.open(options()).activate();
    expect(activated.config.allowedModels).toEqual([CODER, GENERAL]);
  });

  it("narrows the entitlement after the gateway denies a model the organization withdrew", async () => {
    issueWithoutExpiry([CODER, GENERAL]);
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    issueWithoutExpiry([CODER]);
    await distribution.refreshEntitlement();
    await expect(
      DistributionAccess.open(options()).activate({ requestedModel: GENERAL }),
    ).rejects.toMatchObject({ code: "MODEL_UNAVAILABLE" });
  });

  it("re-issues nothing for a second denial of the renewed credential", async () => {
    issueWithoutExpiry([CODER]);
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    issueWithoutExpiry([CODER]);
    await distribution.refreshEntitlement();
    const before = brokerRequests();
    await expect(distribution.refreshEntitlement()).resolves.toBe(false);
    expect(brokerRequests()).toBe(before);
  });

  it("keeps the current credential when the re-read fails and retries at the next denial", async () => {
    issueWithoutExpiry([CODER]);
    const distribution = DistributionAccess.open(options());
    await login(distribution);
    services.knobs.brokerFaults.push({ status: 503 });
    // The broker's own error, not a rejected credential: the credential is
    // fine and stays in use.
    const failed = await distribution
      .refreshEntitlement()
      .catch((error: unknown) => error);
    expect(failed).toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    expect((failed as Error).message).not.toContain("rejected");
    await expect(
      DistributionAccess.open(options()).activate(),
    ).resolves.toMatchObject({ config: { allowedModels: [CODER] } });
    issueWithoutExpiry([CODER, GENERAL]);
    await expect(distribution.refreshEntitlement()).resolves.toBe(true);
  });

  it("re-reads once for one denial seen by two sessions", async () => {
    issueWithoutExpiry([CODER]);
    await login(DistributionAccess.open(options()));
    const first = DistributionAccess.open(options());
    const second = DistributionAccess.open(options());
    await first.activate();
    await second.activate();
    const before = brokerRequests();
    issueWithoutExpiry([CODER, GENERAL]);
    await Promise.all([
      first.refreshEntitlement(),
      second.refreshEntitlement(),
    ]);
    // Both saw the same generation denied; the second finds it replaced.
    expect(brokerRequests()).toBe(before + 1);
  });

  it("has no entitlement to re-read without an organization-issued credential", async () => {
    const personal = parseManifest({
      schema: PISHIP_SCHEMA_V1ALPHA2,
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: { pi: "0.87.1" },
      deployment: { mode: "personal" },
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
    await expect(distribution.refreshEntitlement()).resolves.toBe(false);
  });

  it.each([
    ["login", (distribution: DistributionAccess) => login(distribution)],
    [
      "a gateway model denial",
      (distribution: DistributionAccess) => distribution.refreshEntitlement(),
    ],
  ])(
    "never widens beyond the distribution allowlist when %s re-reads a wider entitlement",
    async (_trigger, reread) => {
      const narrow = options({ models: { allowed: [CODER, GENERAL] } });
      issueWithoutExpiry([CODER]);
      const distribution = DistributionAccess.open(narrow);
      await login(distribution);
      issueWithoutExpiry([CODER, GENERAL, REVIEW, "public/model"]);
      await reread(distribution);
      const activated = await DistributionAccess.open(narrow).activate();
      expect(activated.credential.ref?.models).toEqual([
        CODER,
        GENERAL,
        REVIEW,
        "public/model",
      ]);
      expect(activated.config.allowedModels).toEqual([CODER, GENERAL]);
      expect(activated.models.map((model) => model.id)).toEqual([
        CODER,
        GENERAL,
      ]);
      for (const outside of [REVIEW, "public/model"])
        await expect(
          DistributionAccess.open(narrow).activate({ requestedModel: outside }),
        ).rejects.toMatchObject({ code: "MODEL_DENIED" });
    },
  );
});
