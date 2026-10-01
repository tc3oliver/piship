import { inspect } from "node:util";
import { type IdentityProvider, SecretValue } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import {
  assertSamePrincipal,
  identityMetadata,
  isWorkloadIdentityProvider,
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

describe("adapter identity refresh", () => {
  const signedIn = { subject: "user-1", issuer: "https://idp.example" };
  it.each([
    ["subject", { subject: "user-2" }],
    ["issuer", { issuer: "https://other.example" }],
  ])("refuses a refresh that changes the %s", async (_part, change) => {
    const provider = normalizedIdentityProvider({
      kind: "adapter",
      login: async () => signedIn,
      refresh: async (session) => ({ ...session, ...change }),
    });
    const session = await provider.login({ openUrl: () => {} });
    await expect(provider.refresh?.(session)).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
    });
  });
  it("keeps a refresh that changes only attributes", async () => {
    const provider = normalizedIdentityProvider({
      kind: "adapter",
      login: async () => signedIn,
      refresh: async (session) => ({
        ...session,
        email: "renamed@idp.example",
        displayName: "Renamed",
      }),
    });
    const session = await provider.login({ openUrl: () => {} });
    await expect(provider.refresh?.(session)).resolves.toMatchObject({
      ...signedIn,
      email: "renamed@idp.example",
    });
    expect(assertSamePrincipal(session, session)).toBe(session);
  });
});

describe("workload identity adapters", () => {
  const login = async () => ({
    subject: "svc-build-1",
    issuer: "https://workload.example",
  });

  it("keeps a non-interactive declaration and treats anything else as interactive", () => {
    const workload = normalizedIdentityProvider({
      kind: "workload",
      interactive: false,
      login,
    } as IdentityProvider);
    expect(isWorkloadIdentityProvider(workload)).toBe(true);
    for (const interactive of [true, undefined]) {
      const provider = normalizedIdentityProvider({
        kind: "adapter",
        ...(interactive === undefined ? {} : { interactive }),
        login,
      } as IdentityProvider);
      expect(isWorkloadIdentityProvider(provider)).toBe(false);
      expect("interactive" in provider).toBe(false);
    }
  });

  it("refuses an interactive declaration that is not a boolean", () => {
    for (const interactive of ["false", 0, null])
      expect(() =>
        normalizedIdentityProvider({
          kind: "workload",
          interactive,
          login,
        } as unknown as IdentityProvider),
      ).toThrow(
        expect.objectContaining({
          code: "CONFIG_INVALID",
          message: expect.stringContaining("interactive declaration"),
        }),
      );
  });
});

describe("identity adapter deadlines", () => {
  const signedIn = { subject: "user-1", issuer: "https://idp.example" };
  // An adapter whose every call never settles, recording the signal it got.
  const hanging = (signals: AbortSignal[]): IdentityProvider => ({
    kind: "adapter",
    login: (ctx) => {
      if (ctx.signal) signals.push(ctx.signal);
      return new Promise(() => undefined);
    },
    refresh: (_session, ctx) => {
      if (ctx?.signal) signals.push(ctx.signal);
      return new Promise(() => undefined);
    },
    logout: (_session, ctx) => {
      if (ctx?.signal) signals.push(ctx.signal);
      return new Promise(() => undefined);
    },
  });
  const timedOut = (phase: string) => ({
    code: "GATEWAY_UNREACHABLE",
    retryable: true,
    message: `The identity adapter ./adapters/sso.mjs did not answer ${phase}() within 1 s`,
    sanitizedDetail: expect.objectContaining({
      adapter: "./adapters/sso.mjs",
      phase,
      reason: "timeout",
    }),
  });

  it("ends login, refresh, and logout of an adapter that never answers, and aborts its signal", {
    timeout: 2_000,
  }, async () => {
    const signals: AbortSignal[] = [];
    const provider = normalizedIdentityProvider(hanging(signals), {
      name: "./adapters/sso.mjs",
      timeoutMs: 20,
      loginTimeoutMs: 30,
    });
    await expect(provider.login({ openUrl: () => {} })).rejects.toMatchObject(
      timedOut("login"),
    );
    await expect(provider.refresh?.(signedIn)).rejects.toMatchObject(
      timedOut("refresh"),
    );
    await expect(provider.logout?.(signedIn)).rejects.toMatchObject(
      timedOut("logout"),
    );
    expect(signals).toHaveLength(3);
    expect(signals.every((signal) => signal.aborted)).toBe(true);
  });

  it("gives an interactive login the caller's timeout, and a workload login the call deadline", {
    timeout: 2_000,
  }, async () => {
    const interactive = normalizedIdentityProvider(hanging([]), {
      timeoutMs: 60_000,
      loginTimeoutMs: 60_000,
    });
    await expect(
      interactive.login({ openUrl: () => {}, timeoutMs: 20 }),
    ).rejects.toMatchObject({ code: "GATEWAY_UNREACHABLE", retryable: true });
    const workload = normalizedIdentityProvider(
      { ...hanging([]), interactive: false } as IdentityProvider,
      { timeoutMs: 20, loginTimeoutMs: 60_000 },
    );
    await expect(workload.login({ openUrl: () => {} })).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
      retryable: true,
    });
  });

  it("ends a login the caller cancels even when the adapter ignores the signal", {
    timeout: 2_000,
  }, async () => {
    const provider = normalizedIdentityProvider(hanging([]));
    const controller = new AbortController();
    const login = provider.login({
      openUrl: () => {},
      signal: controller.signal,
    });
    controller.abort();
    await expect(login).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      retryable: false,
    });
  });

  it("keeps working with an adapter's refresh and logout that ignore the signal", async () => {
    const provider = normalizedIdentityProvider({
      kind: "adapter",
      login: async () => signedIn,
      refresh: async (session) => session,
      logout: async () => {},
    });
    await expect(provider.refresh?.(signedIn)).resolves.toMatchObject(signedIn);
    await expect(provider.logout?.(signedIn)).resolves.toBeUndefined();
  });
});
