// piship/v1alpha5 `updates.transport`: a plain-HTTP update source on a private
// or internal host is admitted by default (http-allowed is the explicit
// spelling), `https` forces HTTPS-only, a public host is refused, plain HTTP
// needs bootstrap trust, and no other endpoint's rule changes.
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA4,
  PISHIP_SCHEMA_V1ALPHA5,
  parseManifest,
} from "./index.js";

type Json = Record<string, unknown>;

const CHANNEL = generateKeyPairSync("ed25519")
  .publicKey.export({ type: "spki", format: "der" })
  .toString("base64");
const BOOTSTRAP = {
  version: 1,
  expires: "2099-01-01T00:00:00Z",
  keys: [{ id: "release", publicKey: CHANNEL }],
  roles: {
    root: { keyIds: ["release"], threshold: 1 },
    channel: { keyIds: ["release"], threshold: 1 },
  },
};

function manifest(updates: Json, extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA5,
    app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
    runtime: { pi: "1.1.0" },
    deployment: { mode: "personal" },
    ...(JSON.stringify(updates).includes("MYPI_UPDATE_SOURCE")
      ? { variables: ["MYPI_UPDATE_SOURCE"] }
      : {}),
    updates: { trust: { bootstrap: BOOTSTRAP }, ...updates },
    ...extra,
  };
}
function rejects(input: Json, field: string, message: string): void {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).field).toBe(field);
  expect((error as ManifestError).message).toContain(message);
}
const updatesOf = (input: Json) => parseManifest(input).lifecycle?.updates;

describe("updates.transport", () => {
  it("is absent unless declared, so existing manifests lock unchanged", () => {
    const updates = updatesOf(
      manifest({ source: "https://updates.acme.example" }),
    );
    expect(updates).not.toHaveProperty("transport");
  });

  it("accepts https and http-allowed and keeps the declared value", () => {
    for (const transport of ["https", "http-allowed"])
      expect(updatesOf(manifest({ transport }))?.transport).toBe(transport);
    rejects(
      manifest({ transport: "http" }),
      "updates.transport",
      "Expected https, http-allowed",
    );
  });

  it("is a piship/v1alpha5 field", () => {
    rejects(
      {
        ...manifest({ transport: "https" }),
        schema: PISHIP_SCHEMA_V1ALPHA4,
        updates: { transport: "https" },
      },
      "updates.transport",
      "Unknown field",
    );
  });

  it("refuses a plain-HTTP internal source under an explicit https", () => {
    for (const updates of [
      { source: "http://updates.corp.internal/acmepi", transport: "https" },
      { source: "http://10.0.0.5/acmepi", transport: "https" },
    ])
      rejects(
        manifest(updates),
        "updates.source",
        "Expected an https URL, an http URL on 127.0.0.1, localhost, or [::1]",
      );
  });

  it("admits a plain-HTTP private or internal source by default", () => {
    for (const source of [
      "http://updates.corp.internal/acmepi",
      "http://updates/acmepi",
      "http://10.1.2.3:8080/acmepi",
    ]) {
      const updates = updatesOf(manifest({ source }));
      expect(updates?.source).toBe(source);
      expect(updates).not.toHaveProperty("transport");
    }
  });

  it("refuses a public plain-HTTP host by default", () => {
    for (const source of [
      "http://updates.acme.example/acmepi",
      "http://8.8.8.8/acmepi",
    ])
      rejects(
        manifest({ source }),
        "updates.source",
        "is public, so serve it over https",
      );
  });

  it("accepts a plain-HTTP private or internal source with http-allowed", () => {
    for (const source of [
      "http://updates.corp.internal/acmepi",
      "http://updates/acmepi",
      "http://10.1.2.3:8080/acmepi",
      "http://192.168.0.20/acmepi",
      "http://[fd00::20]/acmepi",
      "http://nas.local/acmepi",
      "https://updates.acme.example/acmepi",
      `\${MYPI_UPDATE_SOURCE}`,
    ])
      expect(
        updatesOf(manifest({ source, transport: "http-allowed" }))?.source,
      ).toBe(source);
  });

  it("refuses a public plain-HTTP host with http-allowed", () => {
    for (const source of [
      "http://updates.acme.example/acmepi",
      "http://8.8.8.8/acmepi",
      "http://updates.internal.acme.example/acmepi",
    ])
      rejects(
        manifest({ source, transport: "http-allowed" }),
        "updates.source",
        "is public, so serve it over https",
      );
  });

  it("requires bootstrap trust for http-allowed", () => {
    rejects(
      { ...manifest({}), updates: { transport: "http-allowed" } },
      "updates.transport",
      "http-allowed requires updates.trust.bootstrap",
    );
    rejects(
      {
        ...manifest({}),
        updates: {
          transport: "http-allowed",
          source: "http://updates.corp.internal/acmepi",
          trust: {},
        },
      },
      "updates.transport",
      "http-allowed requires updates.trust.bootstrap",
    );
  });

  it("requires bootstrap trust for a plain-HTTP source beyond loopback", () => {
    rejects(
      {
        ...manifest({}),
        updates: { source: "http://updates.corp.internal/acmepi", trust: {} },
      },
      "updates.transport",
      "A plain-HTTP updates.source requires updates.trust.bootstrap",
    );
  });

  it("does not change another endpoint's rule", () => {
    const access = {
      identity: {
        mode: "oidc",
        oidc: {
          issuer: "https://login.corp.internal",
          clientId: "mypi",
          redirectUri: "http://127.0.0.1:8765/callback",
        },
      },
      credential: {
        provider: "http-broker",
        broker: { endpoint: "https://broker.corp.internal/token" },
      },
      inference: {
        provider: "openai-compatible",
        baseUrl: "https://gateway.corp.internal/v1",
      },
      models: {
        default: "acme/coder",
        allowed: ["acme/coder"],
        catalog: {
          "acme/coder": {
            name: "Coder",
            contextWindow: 128000,
            maxOutputTokens: 8192,
          },
        },
      },
    };
    const updates = {
      transport: "https",
      source: "https://updates.corp.internal/acmepi",
    };
    expect(() => parseManifest(manifest(updates, access))).not.toThrow();
    const plain = (path: string[], value: string): Json => {
      const copy = structuredClone(access) as Json;
      let target = copy;
      for (const key of path.slice(0, -1)) target = target[key] as Json;
      target[path[path.length - 1] as string] = value;
      return copy;
    };
    // updates.transport: https governs the update channel only: the
    // endpoints keep their own default, plain HTTP to a private host.
    for (const [path, value] of [
      [["identity", "oidc", "issuer"], "http://login.corp.internal"],
      [["credential", "broker", "endpoint"], "http://broker.corp.internal/t"],
      [["inference", "baseUrl"], "http://gateway.corp.internal/v1"],
    ] as const)
      expect(() =>
        parseManifest(manifest(updates, plain([...path], value))),
      ).not.toThrow();
    for (const [path, value] of [
      [["identity", "oidc", "issuer"], "http://login.acme.example"],
      [["credential", "broker", "endpoint"], "http://broker.acme.example/t"],
      [["inference", "baseUrl"], "http://gateway.acme.example/v1"],
    ] as const)
      rejects(
        manifest(updates, plain([...path], value)),
        path.join("."),
        "Plain HTTP is accepted only to a private or internal host",
      );
  });
});
