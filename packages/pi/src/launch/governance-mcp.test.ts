// The launch's MCP wiring: the plain-HTTP fetch only for servers that opt
// in, and identity claims from the identity this launch activated, checked
// per request against the stored identity metadata only.
import type { IdentitySession } from "@piship/contracts";
import type { GovernedLock } from "@piship/core";
import { describe, expect, it } from "vitest";
import type { LaunchContext, PreparedAccess } from "./context.js";
import { governanceOptions } from "./governance.js";

const ISSUER = "https://login.acme.example";
const HEADERS = { "X-MiTAC-User": { identityClaim: "preferred_username" } };

function identity(subject: string, username: string): IdentitySession {
  return {
    subject,
    issuer: ISSUER,
    claims: { sub: subject, iss: ISSUER, preferred_username: username },
  };
}

/** Stored identity metadata: what `readIdentityMetadata` returns. */
function metadata(subject: string) {
  return { subject, issuer: ISSUER, claims: {}, secretRef: "ref" };
}

interface FakeAccess {
  stored: ReturnType<typeof metadata> | null;
  /** Calls that reach the secret store or the identity provider. */
  expensive: number;
}

function options(
  servers: readonly Record<string, unknown>[],
  activated: IdentitySession,
  fake: FakeAccess,
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
  const access = {
    readIdentityMetadata: () => fake.stored,
    currentIdentity: async () => {
      fake.expensive++;
      return activated;
    },
    requestSecret: async () => {
      fake.expensive++;
      return undefined;
    },
    store: {
      get: async () => {
        fake.expensive++;
        return null;
      },
    },
  };
  const prepared = {
    access,
    activated: {
      identity: activated,
      runtime: { requiresCredential: false },
      models: [],
    },
    events: {},
  } as unknown as PreparedAccess;
  return governanceOptions(ctx, lock, prepared, false);
}

describe("launch MCP options", () => {
  it("adds neither seam when no server opts in", () => {
    const built = options(
      [{ id: "docs", transport: "stdio" }],
      identity("u-1", "alice.chen"),
      { stored: metadata("u-1"), expensive: 0 },
    );
    expect(built.mcpPlainHttpFetch).toBeUndefined();
    expect(built.identityClaims).toBeUndefined();
  });

  it("adds the plain-HTTP fetch only for http-allowed", () => {
    const built = options(
      [{ id: "tickets", httpTransport: "http-allowed" }],
      identity("u-1", "alice.chen"),
      { stored: metadata("u-1"), expensive: 0 },
    );
    expect(built.mcpPlainHttpFetch).toBeTypeOf("function");
    expect(built.fetch).not.toBe(built.mcpPlainHttpFetch);
  });

  it("uses the activated claims without the secret store or the IdP", async () => {
    const fake: FakeAccess = { stored: metadata("u-1"), expensive: 0 };
    const built = options(
      [{ id: "tickets", headers: HEADERS }],
      identity("u-1", "alice.chen"),
      fake,
    );
    const claims = built.identityClaims;
    if (!claims) throw new Error("identityClaims is offered");
    for (let request = 0; request < 5; request++)
      expect((await claims())?.preferred_username).toBe("alice.chen");
    expect(fake.expensive).toBe(0);
  });

  it("refuses after a logout and after another user signs in", async () => {
    const fake: FakeAccess = { stored: metadata("u-1"), expensive: 0 };
    const built = options(
      [{ id: "tickets", headers: HEADERS }],
      identity("u-1", "alice.chen"),
      fake,
    );
    const claims = built.identityClaims;
    if (!claims) throw new Error("identityClaims is offered");
    // Logout deletes the identity metadata.
    fake.stored = null;
    await expect(claims()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: expect.stringContaining("signed out"),
    });
    // Another user signed in meanwhile: never this launch's old claim.
    fake.stored = metadata("u-2");
    await expect(claims()).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: expect.stringContaining("Another identity signed in"),
    });
    expect(fake.expensive).toBe(0);
  });

  it("uses the new user's claim at the next launch", async () => {
    const built = options(
      [{ id: "tickets", headers: HEADERS }],
      identity("u-2", "bob.lin"),
      { stored: metadata("u-2"), expensive: 0 },
    );
    expect((await built.identityClaims?.())?.preferred_username).toBe(
      "bob.lin",
    );
  });
});
