import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DistributionAccess } from "@piship/core";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  PiShipError,
} from "@piship/contracts";
import { MemorySecretStore } from "@piship/credentials";
import { OidcPkceIdentityProvider } from "@piship/identity";
import { type AccessManifest, readManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { ATTACKS, browser, followFixture } from "../helpers/oidc-attacks.js";
import { SecretLedger, scanTree } from "../helpers/security.js";

// Security case 1-3 (spec 30.3): invalid OIDC issuer, audience, state, nonce.
//
// The real OIDC client (`OidcPkceIdentityProvider`, and `DistributionAccess`
// around it) runs against the fixture provider over loopback HTTP. Two things
// are proved for every invalid response: PiShip rejects it (the provider-level
// tests in packages/identity cover the code and message; this file adds the
// attacks that need a hostile browser), and the rejected sign-in changes
// nothing. It stores no identity or credential, asks the broker for nothing,
// and leaves the user who was signed in signed in, with their credential
// unrevoked. The same attacks run against a live Keycloak in
// tests/enterprise-reference/security-oidc.test.ts.

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
  temp = mkdtempSync(join(tmpdir(), "piship-oidc-invalid-"));
  services = await startLocalServices();
});
afterEach(async () => {
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

const stateDir = () => join(temp, "state");

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
    stateDir: stateDir(),
    distributionDir: temp,
    env: services.env(),
    secretStore: store,
  });
}

function provider(): OidcPkceIdentityProvider {
  return new OidcPkceIdentityProvider({
    issuer: services.issuer,
    clientId: services.clientId,
    scopes: ["openid", "profile", "email"],
    redirectUri: "http://127.0.0.1/callback",
    fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
  });
}

const rejection = (promise: Promise<unknown>) =>
  promise.then(
    () => {
      throw new Error("the sign-in was accepted");
    },
    (error: unknown) => error as PiShipError,
  );

describe("hostile browser against the OIDC client (fixture provider)", () => {
  it("completes when nothing is changed, so a rejection below is the attack's", async () => {
    const honest = browser(followFixture);
    const session = await provider().login({
      openUrl: honest.openUrl,
      timeoutMs: 15_000,
    });
    expect(await honest.finished()).toBeUndefined();
    expect(session.subject).toBe("demo-user-1");
    expect(session.issuer).toBe(services.issuer);
  });

  it("reports a browser that failed, in the authorization or in the delivery of the callback", async () => {
    // A rejection below only counts when the browser did what it was told, so
    // `finished()` waits for all of it, the delivery included, and hands back
    // what went wrong.
    const refused = new Error("the browser's own failure");
    const failing = browser(async () => {
      throw refused;
    });
    failing.openUrl("http://127.0.0.1:1/authorize");
    expect(await failing.finished()).toBe(refused);
    // The callback goes to a port nobody listens on.
    const undelivered = browser(
      async () => new URL("http://127.0.0.1:1/callback"),
    );
    undelivered.openUrl("http://127.0.0.1:1/authorize");
    expect(await undelivered.finished()).toBeInstanceOf(Error);
  });

  it.each(ATTACKS)("rejects $name", async (attack) => {
    const hostile = browser(followFixture, attack);
    const error = await rejection(
      provider().login({
        openUrl: hostile.openUrl,
        timeoutMs: attack.refused ? 2_000 : 15_000,
      }),
    );
    expect(await hostile.finished()).toBeUndefined();
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({ code: attack.code });
    expect(error.message).toMatch(attack.message);
  });

  it("rejects an authorization code issued for another request's PKCE verifier", async () => {
    // The attacker signs in on its own authorization request (its own PKCE
    // challenge) and hands that code to the victim's callback, with the
    // victim's state. The token endpoint binds a code to its challenge.
    const injected = browser(async (url) => {
      const own = new URL(url);
      own.searchParams.set("code_challenge", "A".repeat(43));
      const other = await followFixture(own);
      const genuine = await followFixture(url);
      genuine.searchParams.set("code", other.searchParams.get("code") ?? "");
      return genuine;
    });
    const error = await rejection(
      provider().login({ openUrl: injected.openUrl, timeoutMs: 15_000 }),
    );
    expect(await injected.finished()).toBeUndefined();
    expect(error).toBeInstanceOf(PiShipError);
    // The token endpoint refuses the code: it is bound to another PKCE
    // challenge. (PiShip files every invalid_grant under IDENTITY_EXPIRED.)
    expect(error.code).toBe("IDENTITY_EXPIRED");
    expect(error.message).toBe(
      "Sign-in failed: token endpoint returned invalid_grant",
    );
  });

  it("does not take a second callback for the same sign-in (state replay)", async () => {
    const delivered: URL[] = [];
    const replaying = browser(async (url) => {
      const callback = await followFixture(url);
      delivered.push(callback);
      return callback;
    });
    await provider().login({ openUrl: replaying.openUrl, timeoutMs: 15_000 });
    const [callback] = delivered;
    // The listener closed with the first callback: nothing answers a replay.
    await expect(fetch(callback as URL)).rejects.toThrow();
  });
});

/**
 * Invalid responses the identity provider itself sends, each as the fixture
 * knob that produces it. The rejection is the provider's check (see
 * packages/identity/src/oidc.test.ts); what these add is the persistence
 * assertion around it.
 */
const PROVIDER_FAULTS: readonly {
  name: string;
  knob: string;
  value: unknown;
  message: RegExp;
  code?: string;
  /** Whether PiShip exchanged the code, so the provider issued tokens before the rejection. */
  exchanged?: false;
  /** The listener refused the callback and the sign-in waited (see ATTACKS). */
  waits?: true;
}[] = [
  {
    name: "an ID token from another issuer",
    knob: "idTokenIssuer",
    value: "https://evil.example/idp",
    message: /iss/,
  },
  {
    name: "an ID token for another audience",
    knob: "idTokenAudience",
    value: "another-client",
    message: /aud/,
  },
  {
    name: "an ID token for a list of audiences that omits this client",
    knob: "idTokenAudience",
    value: ["another-client", "api://other-service"],
    message: /aud/,
  },
  {
    name: "an ID token with another nonce",
    knob: "idTokenNonce",
    value: "replayed-nonce",
    message: /nonce/,
  },
  {
    name: "an ID token signed with a key the provider does not publish",
    knob: "signWithRogueKey",
    value: true,
    message: /signature/,
  },
  {
    name: "an expired ID token",
    knob: "idTokenExpired",
    value: true,
    message: /exp/,
    code: "IDENTITY_EXPIRED",
  },
  {
    name: "a callback whose state is another one",
    knob: "stateOverride",
    value: "attacker-state",
    message: /refused 1 callback without this sign-in's state/,
    code: "IDENTITY_REQUIRED",
    exchanged: false,
    waits: true,
  },
];

const ALICE = { subject: "alice-0001", models: ["acme/coder", "acme/general"] };
const BOB = { subject: "bob-0002", models: ["acme/coder"] };

function as(person: typeof ALICE): void {
  services.knobs.subject = person.subject;
  services.knobs.entitledModels = [...person.models];
}

const approve = (url: string) => void services.approve(url);
const brokerCalls = () =>
  services.state.requests.filter((item: { path: string }) =>
    item.path.startsWith("/broker/"),
  ).length;
const gatewayCalls = () =>
  services.state.requests.filter((item: { path: string }) =>
    item.path.startsWith("/gateway/"),
  ).length;

describe("a rejected sign-in changes nothing (fixture provider, DistributionAccess)", () => {
  describe.each(PROVIDER_FAULTS)("$name", (fault) => {
    it("stores no identity, no credential and no secret when nobody was signed in", async () => {
      const store = new MemorySecretStore();
      const distribution = open(store);
      as(BOB);
      services.knobs[fault.knob] = fault.value;
      const error = await rejection(
        distribution.login({
          openUrl: approve,
          signal: AbortSignal.timeout(fault.waits ? 2_000 : 15_000),
        }),
      );
      expect(error).toBeInstanceOf(PiShipError);
      expect(error.code).toBe(fault.code ?? "IDENTITY_INVALID");
      expect(error.message).toMatch(fault.message);
      // No token, code or credential in the error a user reads.
      const issued = new SecretLedger();
      issued.observeServices(services);
      // The tokens the provider issued for the rejected code (none when the
      // state was refused before the exchange) are stored nowhere.
      expect(issued.size > 0).toBe(fault.exchanged !== false);
      expect(JSON.stringify(error.toJSON())).not.toMatch(
        /demo-(at|rt)-|demo-code-/,
      );
      // The identity provider answered the code exchange; nothing after it ran.
      expect(brokerCalls()).toBe(0);
      expect(gatewayCalls()).toBe(0);
      expect(services.state.credentialCount).toBe(0);
      expect(store.refs()).toEqual([]);
      expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(
        false,
      );
      expect(
        existsSync(join(stateDir(), "credentials-metadata", "inference.json")),
      ).toBe(false);
      expect(distribution.readIdentityMetadata()).toBeNull();
      expect(distribution.readPrincipalBinding()).toBeNull();
      expect(scanTree(temp, issued.all())).toEqual([]);
      // The next launch is still signed out.
      services.knobs[fault.knob] = undefined;
      await expect(open(store).activate()).rejects.toMatchObject({
        code: expect.stringMatching(/^(IDENTITY|CREDENTIAL)_REQUIRED$/),
      });
    });

    it("leaves the signed-in user, and their unrevoked credential, in place", async () => {
      const store = new MemorySecretStore();
      const distribution = open(store);
      as(ALICE);
      await distribution.login({
        openUrl: approve,
        signal: AbortSignal.timeout(15_000),
      });
      const alice = await open(store).activate();
      expect(alice.identity?.subject).toBe(ALICE.subject);
      const metadata = readFileSync(
        join(stateDir(), "credentials-metadata", "inference.json"),
        "utf8",
      );
      const refs = store.refs();
      const requests = services.state.requests.length;

      as(BOB);
      services.knobs[fault.knob] = fault.value;
      const error = await rejection(
        distribution.login({
          openUrl: approve,
          signal: AbortSignal.timeout(fault.waits ? 2_000 : 15_000),
        }),
      );
      expect(error.code).toBe(fault.code ?? "IDENTITY_INVALID");

      // Nothing was asked of the broker or the gateway for Bob, and Alice's
      // credential was neither revoked nor replaced.
      const since = services.state.requests
        .slice(requests)
        .map((item: { path: string }) => item.path);
      expect(since.filter((path: string) => !path.startsWith("/idp/"))).toEqual(
        [],
      );
      expect(services.state.revokedCredentials).toEqual([]);
      expect(store.refs()).toEqual(refs);
      expect(
        readFileSync(
          join(stateDir(), "credentials-metadata", "inference.json"),
          "utf8",
        ),
      ).toBe(metadata);
      expect(distribution.readIdentityMetadata()?.subject).toBe(ALICE.subject);
      expect(distribution.readPrincipalBinding()).toMatchObject({
        subject: ALICE.subject,
      });
      services.knobs[fault.knob] = undefined;
      const still = await open(store).activate();
      expect(still.identity?.subject).toBe(ALICE.subject);
      expect(still.credential.ref?.credentialId).toBe(
        alice.credential.ref?.credentialId,
      );
      expect(still.config.allowedModels).toEqual(ALICE.models);
    });
  });

  it.each(ATTACKS)(
    "rejects $name and leaves Alice signed in, without a call to the broker",
    async (attack) => {
      const store = new MemorySecretStore();
      const distribution = open(store);
      as(ALICE);
      await distribution.login({
        openUrl: approve,
        signal: AbortSignal.timeout(15_000),
      });
      const calls = brokerCalls();
      const revoked = services.state.revokedCredentials.length;

      as(BOB);
      const hostile = browser(followFixture, attack);
      const error = await rejection(
        distribution.login({
          openUrl: hostile.openUrl,
          signal: AbortSignal.timeout(attack.refused ? 2_000 : 15_000),
        }),
      );
      expect(await hostile.finished()).toBeUndefined();
      expect(error).toMatchObject({ code: attack.code });
      expect(error.message).toMatch(attack.message);
      expect(brokerCalls()).toBe(calls);
      expect(services.state.revokedCredentials).toHaveLength(revoked);
      expect(distribution.readIdentityMetadata()?.subject).toBe(ALICE.subject);
      expect((await open(store).activate()).identity?.subject).toBe(
        ALICE.subject,
      );
    },
  );
});
