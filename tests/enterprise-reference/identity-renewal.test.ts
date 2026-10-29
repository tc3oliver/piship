import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type AccessEvent, DistributionAccess } from "@piship/core";
import { MemorySecretStore } from "@piship/credentials";
import { type AccessManifest, readManifest } from "@piship/schema";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { authorizeAtKeycloak } from "../../examples/enterprise-reference/tests/support/keycloak.js";
import { browser } from "../helpers/oidc-attacks.js";
import { type ReferenceStack, startReferenceStack } from "./stack.js";

const manifest = readManifest(
  fileURLToPath(
    new URL("../../examples/enterprise-reference/piship.yaml", import.meta.url),
  ),
);

let stack: ReferenceStack;

beforeAll(() => {
  stack = startReferenceStack({ name: "identity-renewal" });
}, 600_000);

afterAll(() => {
  stack?.stop();
}, 120_000);

describe("live-session identity renewal (Keycloak and credential broker)", () => {
  it("refreshes silently, rechecks broker entitlements and fails closed after revocation", async () => {
    const directory = mkdtempSync(join(tmpdir(), "piship-renewal-"));
    const store = new MemorySecretStore();
    const events: AccessEvent[] = [];
    const issuer =
      "http://127.0.0.1:" +
      stack.ports.KEYCLOAK_PORT +
      "/realms/piship-reference";
    let clock = Date.now();
    const distribution = DistributionAccess.open({
      app: manifest.app,
      mode: "managed",
      access: manifest.access as AccessManifest,
      stateDir: join(directory, "state"),
      distributionDir: directory,
      secretStore: store,
      now: () => clock,
      onEvent: (event) => events.push(event),
      env: {
        ACMECODE_OIDC_ISSUER: issuer,
        ACMECODE_CREDENTIAL_BROKER_URL: stack.broker + "/v1/credential",
        ACMECODE_CREDENTIAL_REVOKE_URL: stack.broker + "/v1/revoke",
        ACMECODE_LLM_GATEWAY_URL: stack.gateway + "/v1",
      },
    });

    try {
      const signIn = browser(
        async (url) =>
          new URL(
            await authorizeAtKeycloak(url, "alice", stack.password("alice")),
          ),
      );
      const login = await distribution.login({ openUrl: signIn.openUrl });
      expect(await signIn.finished()).toBeUndefined();
      const initial = login.identity;
      if (!initial?.expiresAt || !initial.refreshToken)
        throw new Error("The reference login must provide expiring tokens");

      const first = await distribution.activate();
      expect(first.identity?.subject).toBe(initial.subject);
      expect(first.selectedModel).toBe("acme/coder");
      const firstKey = await distribution.requestSecret();
      if (!firstKey) throw new Error("The broker did not issue a credential");
      expect((await stack.chat(firstKey.reveal())).status).toBe(200);

      // Advance the session clock into the refresh window without waiting
      // five real minutes. The refresh itself uses the live Keycloak endpoint.
      clock = initial.expiresAt.getTime() - 30_000;
      const renewedKey = await distribution.requestSecret({ force: true });
      if (!renewedKey)
        throw new Error("The broker did not renew the credential");
      clock = Date.now();

      const renewed = await distribution.currentIdentity({ required: true });
      if (!renewed?.expiresAt || !renewed.refreshToken)
        throw new Error("The renewed session must retain expiring tokens");
      expect(renewed.subject).toBe(initial.subject);
      expect(renewed.issuer).toBe(initial.issuer);
      expect(renewed.refreshToken.reveal()).not.toBe(
        initial.refreshToken.reveal(),
      );
      expect(
        events.filter((event) => event.event === "identity.refresh"),
      ).toHaveLength(1);

      const resumed = await distribution.activate();
      expect(resumed.config.allowedModels).toEqual([
        "acme/coder",
        "acme/general",
      ]);
      expect((await stack.chat(renewedKey.reveal())).status).toBe(200);

      // Both the on-disk state and lifecycle audit contain metadata only.
      const visible =
        readFileSync(distribution.paths.identity, "utf8") +
        readFileSync(distribution.paths.credential, "utf8") +
        JSON.stringify(events);
      const secrets = [
        initial.accessToken?.reveal(),
        initial.refreshToken.reveal(),
        renewed.accessToken?.reveal(),
        renewed.refreshToken.reveal(),
        firstKey?.reveal(),
        renewedKey?.reveal(),
      ].filter((value): value is string => typeof value === "string");
      expect(secrets.some((secret) => visible.includes(secret))).toBe(false);

      // Keycloak revokes the current rotating refresh token. The next
      // forced in-session renewal must refuse it, not reuse the old key.
      const revoked = await fetch(issuer + "/protocol/openid-connect/revoke", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: "acmecode",
          token: renewed.refreshToken.reveal(),
          token_type_hint: "refresh_token",
        }),
      });
      expect(revoked.status).toBe(200);
      clock = renewed.expiresAt.getTime() - 30_000;
      let failure: unknown;
      try {
        await distribution.requestSecret({ force: true });
      } catch (error) {
        failure = error;
      }
      expect(failure).toMatchObject({ code: "IDENTITY_EXPIRED" });
      expect(
        events.filter((event) => event.event === "identity.refresh"),
      ).toHaveLength(1);
    } finally {
      clock = Date.now();
      await distribution.logout().catch(() => {});
      rmSync(directory, { recursive: true, force: true });
    }
  }, 120_000);
});
