import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  PiShipError,
} from "@piship/contracts";
import { OidcPkceIdentityProvider } from "@piship/identity";
import { authorizeAtKeycloak } from "../../examples/enterprise-reference/tests/support/keycloak.js";
import { ATTACKS, browser, type Follow } from "../helpers/oidc-attacks.js";
import { type ReferenceStack, request, startReferenceStack } from "./stack.js";

// Security cases 1-3 (spec 30.3) against a live Keycloak: invalid issuer,
// audience, state, nonce. The real OIDC client runs against the reference
// realm and a hostile browser changes one thing between the authorization
// request PiShip prints and the callback it receives (the same attacks
// tests/security/oidc-invalid.test.ts runs against the fixture provider).
// Keycloak stays honest, so every rejection is PiShip's own check.
//
// What a live Keycloak cannot be made to send: an ID token for another
// audience or from another issuer. Its ID token always names the client in
// `aud` and the frontend URL, which the reference stack pins, in `iss`. Those
// two checks stay with the fixture provider (packages/identity/src/oidc.test.ts,
// tests/security/oidc-invalid.test.ts); live, the issuer is exercised as a
// discovery document that names another issuer than the one asked for, and the
// audience as a genuine Keycloak-signed token presented to the broker for
// the wrong audience.
//
// Needs Docker; run with `npm run test:reference` after `npm run build`. The
// stack publishes on ports Docker chooses (tests/enterprise-reference/
// stack.ts), so a run beside another one needs no setting.

const CLIENT_ID = "acmecode";
const REDIRECT = "http://127.0.0.1/callback";

let stack: ReferenceStack;
let issuer: string;

beforeAll(() => {
  stack = startReferenceStack({ name: "security-oidc" });
  issuer = `http://127.0.0.1:${stack.ports.KEYCLOAK_PORT}/realms/piship-reference`;
}, 600_000);
afterAll(() => {
  stack?.stop();
}, 120_000);

function provider(
  overrides: { issuer?: string } = {},
): OidcPkceIdentityProvider {
  return new OidcPkceIdentityProvider({
    issuer: overrides.issuer ?? issuer,
    clientId: CLIENT_ID,
    scopes: ["openid", "profile", "email"],
    redirectUri: REDIRECT,
    fetch: createManagedFetch(DEFAULT_NETWORK_POLICY),
  });
}

/** The real Keycloak sign-in form, submitted for a reference user. */
const at =
  (user: "alice" | "bob"): Follow =>
  async (url) =>
    new URL(await authorizeAtKeycloak(url, user, stack.password(user)));

const rejection = (promise: Promise<unknown>) =>
  promise.then(
    () => {
      throw new Error("the sign-in was accepted");
    },
    (error: unknown) => error as PiShipError,
  );

describe("hostile browser against the OIDC client (live Keycloak)", () => {
  it("completes when nothing is changed, so a rejection below is the attack's", async () => {
    const honest = browser(at("alice"));
    const session = await provider().login({
      openUrl: honest.openUrl,
      timeoutMs: 60_000,
    });
    expect(await honest.finished()).toBeUndefined();
    expect(session.issuer).toBe(issuer);
    expect(session.displayName).toBe("Alice Engineer");
  });

  it.each(ATTACKS)("rejects $name", async (attack) => {
    const hostile = browser(at("alice"), attack);
    // A refused callback leaves the sign-in waiting until its timeout: long
    // enough for Keycloak to deliver the callback, short enough to end.
    const error = await rejection(
      provider().login({
        openUrl: hostile.openUrl,
        timeoutMs: attack.refused ? 20_000 : 60_000,
      }),
    );
    expect(await hostile.finished()).toBeUndefined();
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({ code: attack.code });
    expect(error.message).toMatch(attack.message);
  });

  it("rejects an authorization code issued for another request's PKCE verifier", async () => {
    // Bob signs in on the attacker's own authorization request (its own
    // PKCE challenge); the code goes to Alice's callback with Alice's state.
    // Keycloak binds the code to the challenge it was issued for.
    const injected = browser(async (url) => {
      const own = new URL(url);
      own.searchParams.set("code_challenge", "A".repeat(43));
      const other = await at("bob")(own);
      const genuine = await at("alice")(url);
      genuine.searchParams.set("code", other.searchParams.get("code") ?? "");
      return genuine;
    });
    const error = await rejection(
      provider().login({ openUrl: injected.openUrl, timeoutMs: 60_000 }),
    );
    expect(await injected.finished()).toBeUndefined();
    expect(error).toBeInstanceOf(PiShipError);
    // Keycloak refuses the code at the token endpoint: it is bound to another
    // PKCE challenge. (PiShip files every invalid_grant under IDENTITY_EXPIRED.)
    expect(error.code).toBe("IDENTITY_EXPIRED");
    expect(error.message).toBe(
      "Sign-in failed: token endpoint returned invalid_grant",
    );
  });

  it("does not take a second callback for the same sign-in (state replay)", async () => {
    const delivered: URL[] = [];
    const replaying = browser(async (url) => {
      const callback = await at("alice")(url);
      delivered.push(callback);
      return callback;
    });
    await provider().login({
      openUrl: replaying.openUrl,
      timeoutMs: 60_000,
    });
    expect(await replaying.finished()).toBeUndefined();
    // The listener closed with the first callback: nothing answers a replay.
    await expect(fetch(delivered[0] as URL)).rejects.toThrow();
  });

  it("advertises the issuer response parameter, so a callback without it is refused too", async () => {
    // RFC 9207: a client that is told the provider sends `iss` must insist on it.
    const discovery = (await (
      await fetch(`${issuer}/.well-known/openid-configuration`)
    ).json()) as { authorization_response_iss_parameter_supported?: boolean };
    expect(discovery.authorization_response_iss_parameter_supported).toBe(true);
    const hostile = browser(at("alice"), {
      name: "a callback with no issuer parameter",
      callback: (parameters) => parameters.delete("iss"),
      code: "IDENTITY_INVALID",
      message: /\biss\b|issuer/,
    });
    const error = await rejection(
      provider().login({ openUrl: hostile.openUrl, timeoutMs: 60_000 }),
    );
    expect(await hostile.finished()).toBeUndefined();
    expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    expect(error.message).toMatch(/\biss\b|issuer/);
  });

  it("refuses an issuer whose discovery document names another issuer", async () => {
    // The stack pins Keycloak's frontend host to 127.0.0.1, so asking
    // through `localhost` gets a document whose `issuer` is not the one asked
    // for.
    const other = `http://localhost:${stack.ports.KEYCLOAK_PORT}/realms/piship-reference`;
    const discovery = (await (
      await fetch(`${other}/.well-known/openid-configuration`)
    ).json()) as { issuer: string };
    expect(discovery.issuer).toBe(issuer);
    const error = await rejection(
      provider({ issuer: other }).login({
        openUrl: () => {
          throw new Error("no browser may be opened for a distrusted issuer");
        },
        timeoutMs: 15_000,
      }),
    );
    expect(error).toBeInstanceOf(PiShipError);
    expect(error).toMatchObject({ code: "IDENTITY_INVALID" });
    expect(error.message).toMatch(/^OIDC discovery failed/);
  });
});

describe("the credential broker refuses tokens Keycloak signed for another purpose (live)", () => {
  const broker = () => `${stack.broker}/v1/credential`;
  const acquire = (bearer: string) =>
    request(broker(), {
      bearer,
      body: { distribution: "acmecode-reference", purpose: "inference" },
    });

  it("refuses the ID token, which has the right issuer and signature and the wrong audience", async () => {
    const { id_token: idToken, access_token: accessToken } =
      stack.tokenResponse("alice");
    // The control: the access token of the same sign-in is accepted.
    const accepted = await acquire(accessToken);
    expect(accepted.status).toBe(200);
    const refused = await acquire(idToken);
    expect(refused.status).toBe(401);
    expect(refused.headers["www-authenticate"]).toMatch(/^Bearer/);
    expect(refused.scrubbed).not.toMatch(/sk-|eyJ/);
  });

  it("refuses an access token whose claims were changed after signing", async () => {
    const [header, payload, signature] = stack.accessToken("bob").split(".");
    const claims = JSON.parse(
      Buffer.from(payload ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    // Bob presents himself as an engineer.
    claims.groups = ["/engineering"];
    const forged = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const refused = await acquire(`${header}.${forged}.${signature}`);
    expect(refused.status).toBe(401);
    expect(refused.scrubbed).not.toMatch(/sk-|eyJ/);
  });
});
