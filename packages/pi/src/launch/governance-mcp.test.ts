// The launch's MCP wiring: the plain-HTTP fetch only for servers that opt
// in, and identity claims read from the identity signed in now.
import type { IdentitySession } from "@piship/contracts";
import type { GovernedLock } from "@piship/core";
import { describe, expect, it } from "vitest";
import type { LaunchContext, PreparedAccess } from "./context.js";
import { governanceOptions } from "./governance.js";

const ISSUER = "https://login.acme.example";

function identity(subject: string, username: string): IdentitySession {
  return {
    subject,
    issuer: ISSUER,
    claims: { sub: subject, iss: ISSUER, preferred_username: username },
  };
}

function options(
  servers: readonly Record<string, unknown>[],
  current: () => Promise<IdentitySession | null>,
) {
  const ctx = {
    distributionDir: "/nonexistent",
    stateDir: "/nonexistent",
    metadata: { app: { id: "acmecode", command: "acmecode" }, access: {} },
  } as unknown as LaunchContext;
  const lock = {
    app: { id: "acmecode", command: "acmecode" },
    governance: {
      manifest: { sandbox: { credential: "none" }, mcp: { servers } },
    },
  } as unknown as GovernedLock;
  const prepared = {
    access: { currentIdentity: current },
    activated: {
      identity: identity("u-1", "alice.chen"),
      runtime: { requiresCredential: false },
      models: [],
    },
    events: {},
  } as unknown as PreparedAccess;
  return governanceOptions(ctx, lock, prepared, false);
}

const HEADERS = { "X-MiTAC-User": { identityClaim: "preferred_username" } };

describe("launch MCP options", () => {
  it("adds neither seam when no server opts in", () => {
    const built = options([{ id: "docs", transport: "stdio" }], async () =>
      identity("u-1", "alice.chen"),
    );
    expect(built.mcpPlainHttpFetch).toBeUndefined();
    expect(built.identityClaims).toBeUndefined();
  });

  it("adds the plain-HTTP fetch only for http-allowed", () => {
    const built = options(
      [{ id: "tickets", httpTransport: "http-allowed" }],
      async () => null,
    );
    expect(built.mcpPlainHttpFetch).toBeTypeOf("function");
    expect(built.fetch).not.toBe(built.mcpPlainHttpFetch);
  });

  it("reads the claims of the identity signed in now, never a stale one", async () => {
    let current: IdentitySession | null = identity("u-1", "alice.chen");
    const built = options(
      [{ id: "tickets", headers: HEADERS }],
      async () => current,
    );
    const claims = built.identityClaims;
    if (!claims) throw new Error("identityClaims is offered");
    expect((await claims())?.preferred_username).toBe("alice.chen");
    // The same principal's renewed session with a changed claim.
    current = identity("u-1", "alice.wang");
    expect((await claims())?.preferred_username).toBe("alice.wang");
    // Signed out: no claims, so the server cannot send the header.
    current = null;
    expect(await claims()).toBeNull();
    // Another user signed in meanwhile: refused, never that user's claim
    // under this launch, and never the launch user's old one.
    current = identity("u-2", "bob.lin");
    await expect(claims()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
  });

  it("uses the new user's claim at the next launch", async () => {
    const next = identity("u-2", "bob.lin");
    const built = governanceOptions(
      {
        distributionDir: "/nonexistent",
        stateDir: "/nonexistent",
        metadata: { app: { id: "acmecode", command: "acmecode" }, access: {} },
      } as unknown as LaunchContext,
      {
        app: { id: "acmecode", command: "acmecode" },
        governance: {
          manifest: {
            sandbox: { credential: "none" },
            mcp: { servers: [{ id: "tickets", headers: HEADERS }] },
          },
        },
      } as unknown as GovernedLock,
      {
        access: { currentIdentity: async () => next },
        activated: {
          identity: next,
          runtime: { requiresCredential: false },
          models: [],
        },
        events: {},
      } as unknown as PreparedAccess,
      false,
    );
    expect((await built.identityClaims?.())?.preferred_username).toBe(
      "bob.lin",
    );
  });
});
