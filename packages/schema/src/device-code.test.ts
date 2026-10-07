import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  PISHIP_SCHEMA_V1,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
} from "./index.js";

type Json = Record<string, unknown>;

const root = fileURLToPath(new URL("../../../", import.meta.url));
const demo = readFileSync(
  join(root, "examples/demo-company/piship.yaml"),
  "utf8",
);

/** The demo company's managed manifest, with its identity.oidc rewritten. */
const manifest = (schema: string, oidc: Json) => {
  const parsed = parseYaml(
    demo.replace(/^schema: .*$/m, `schema: ${schema}`),
  ) as { identity: { oidc: Json } };
  parsed.identity.oidc = {
    issuer: parsed.identity.oidc.issuer,
    clientId: parsed.identity.oidc.clientId,
    ...oidc,
  };
  return parsed;
};

const oidcOf = (parsed: ReturnType<typeof parseManifest>) => {
  const identity = parsed.access?.identity;
  if (identity?.mode !== "oidc") throw new Error("expected oidc");
  return identity.oidc;
};

const redirectUri = "http://127.0.0.1:8765/callback";

describe("identity.oidc.flow: device_code", () => {
  it("is accepted in piship/v1 without a redirect, and records the flow", () => {
    const oidc = oidcOf(
      parseManifest(manifest(PISHIP_SCHEMA_V1, { flow: "device_code" })),
    );
    expect(oidc.flow).toBe("device_code");
    expect(oidc).not.toHaveProperty("redirectUri");
    expect(oidc.scopes).toEqual(["openid", "profile", "email"]);
  });

  it("refuses a redirectUri with it, naming the field", () => {
    expect(() =>
      parseManifest(
        manifest(PISHIP_SCHEMA_V1, { flow: "device_code", redirectUri }),
      ),
    ).toThrow(/identity\.oidc\.redirectUri.*device_code has no redirect/);
  });

  it("keeps the scope rules: openid is required", () => {
    expect(() =>
      parseManifest(
        manifest(PISHIP_SCHEMA_V1, {
          flow: "device_code",
          scopes: ["profile"],
        }),
      ),
    ).toThrow("OIDC login requires the openid scope");
  });

  it("is refused by piship/v1alpha6, which stays as it was", () => {
    expect(() =>
      parseManifest(manifest(PISHIP_SCHEMA_V1ALPHA6, { flow: "device_code" })),
    ).toThrow(/device_code needs schema piship\/v1/);
  });

  it("refuses an unknown flow, naming both values", () => {
    expect(() =>
      parseManifest(
        manifest(PISHIP_SCHEMA_V1, { flow: "implicit", redirectUri }),
      ),
    ).toThrow("Expected authorization_code_pkce or device_code");
  });

  it("works with http-allowed transport", () => {
    const oidc = oidcOf(
      parseManifest(
        manifest(PISHIP_SCHEMA_V1, {
          flow: "device_code",
          httpTransport: "http-allowed",
        }),
      ),
    );
    expect(oidc.httpTransport).toBe("http-allowed");
  });
});

describe("identity.oidc.flow: authorization_code_pkce is unchanged", () => {
  it.each([PISHIP_SCHEMA_V1, PISHIP_SCHEMA_V1ALPHA6])(
    "is the default in %s and keeps the redirect and key order",
    (schema) => {
      const oidc = oidcOf(parseManifest(manifest(schema, { redirectUri })));
      expect(oidc.flow).toBe("authorization_code_pkce");
      expect(oidc.redirectUri).toBe(redirectUri);
      // The lock digest is computed over this object: its keys stay in order.
      expect(Object.keys(oidc)).toEqual([
        "issuer",
        "clientId",
        "flow",
        "scopes",
        "redirectUri",
      ]);
    },
  );

  it("still requires a loopback redirectUri", () => {
    expect(() =>
      parseManifest(
        manifest(PISHIP_SCHEMA_V1, { flow: "authorization_code_pkce" }),
      ),
    ).toThrow("identity.oidc.redirectUri");
    expect(() =>
      parseManifest(
        manifest(PISHIP_SCHEMA_V1, {
          redirectUri: "https://app.example/callback",
        }),
      ),
    ).toThrow("loopback redirect");
  });
});
