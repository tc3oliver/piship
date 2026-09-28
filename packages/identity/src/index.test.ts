import { inspect } from "node:util";
import { type IdentityProvider, SecretValue } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import {
  identityMetadata,
  normalizedIdentityProvider,
  normalizeIdentitySession,
} from "./index.js";

const TOKEN = "adapter-access-token-000";

describe("adapter identity sessions", () => {
  it("re-wraps plain and foreign tokens so they never serialize", async () => {
    const adapter: IdentityProvider = {
      kind: "adapter",
      login: async () =>
        ({
          subject: "user-1",
          issuer: "https://idp.example",
          accessToken: TOKEN,
          refreshToken: { reveal: () => "adapter-refresh-token-000" },
          expiresAt: "2030-01-01T00:00:00.000Z",
        }) as never,
      refresh: async (session) => ({ ...session, accessToken: TOKEN as never }),
    };
    const provider = normalizedIdentityProvider(adapter);
    const session = await provider.login({ openUrl: () => {} });
    expect(session.accessToken).toBeInstanceOf(SecretValue);
    expect(session.refreshToken).toBeInstanceOf(SecretValue);
    expect(session.accessToken?.reveal()).toBe(TOKEN);
    expect(session.expiresAt).toEqual(new Date("2030-01-01T00:00:00.000Z"));
    for (const text of [
      JSON.stringify(session),
      inspect(session, { depth: 10 }),
    ]) {
      expect(text).not.toContain(TOKEN);
      expect(text).not.toContain("adapter-refresh-token");
    }
    const refreshed = await provider.refresh?.(session);
    expect(refreshed?.accessToken).toBeInstanceOf(SecretValue);
    expect(provider.logout).toBeUndefined();
  });

  it("rejects a session without a subject, issuer, or usable token", () => {
    for (const value of [
      null,
      { issuer: "https://idp.example" },
      { subject: "user-1", issuer: "https://idp.example", accessToken: "" },
      {
        subject: "user-1",
        issuer: "https://idp.example",
        accessToken: { reveal: () => 1 },
      },
      { subject: "user-1", issuer: "https://idp.example", expiresAt: "soon" },
    ])
      expect(() => normalizeIdentitySession(value)).toThrow(
        expect.objectContaining({ code: "IDENTITY_INVALID" }),
      );
  });

  it("persists only allowlisted claims from an adapter session", () => {
    const session = normalizeIdentitySession({
      subject: "user-1",
      issuer: "https://idp.example",
      accessToken: TOKEN,
      claims: {
        sub: "user-1",
        email: "dev@example.test",
        groups: ["eng", "release"],
        address: { street: "1 Main St" },
        phone_number: "+1 555 0100",
        at_hash: "adapter-token-hash",
        name: { nested: true },
      },
    });
    const expected = {
      sub: "user-1",
      email: "dev@example.test",
      groups: ["eng", "release"],
    };
    expect(session.claims).toEqual(expected);
    // Metadata written from a session built without normalization is filtered too.
    const metadata = identityMetadata(
      { ...session, claims: { ...expected, phone_number: "+1 555 0100" } },
      "piship:acme:identity#1",
    );
    expect(metadata.claims).toEqual(expected);
    expect(JSON.stringify(metadata)).not.toContain("555");
  });
});
