// piship/v1alpha6 `httpTransport` on the inference gateway, the credential
// broker, the OIDC issuer, HTTP audit sinks, and remote sandbox endpoints:
// plain HTTP to a private or internal host is admitted by default,
// `http-allowed` says so explicitly, and `https` forces HTTPS-only.
import { describe, expect, it } from "vitest";
import {
  launchWarnings,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  effectiveHttpTransport,
  parseManifest,
  plainHttpPermitted,
  plainHttpProblem,
} from "./index.js";

type Json = Record<string, unknown>;

/** A `${GATEWAY_URL}` runtime reference. */
const GATEWAY_REF = ["$", "{GATEWAY_URL}"].join("");

function manifest(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA6,
    app: {
      id: "acmecode",
      name: "AcmeCode",
      command: "acmecode",
      version: "1.0.0",
    },
    runtime: { pi: "1.0.0" },
    deployment: { mode: "managed" },
    updates: { channel: "stable", channels: ["stable"] },
    identity: {
      mode: "oidc",
      oidc: {
        issuer: "https://login.acme.example",
        clientId: "acmecode",
        redirectUri: "http://127.0.0.1:8765/callback",
      },
    },
    credential: {
      provider: "http-broker",
      broker: { endpoint: "https://broker.acme.example/token" },
    },
    inference: {
      provider: "openai-compatible",
      baseUrl: "https://gateway.acme.example/v1",
    },
    models: {
      default: "acme/coder",
      allowed: ["acme/coder"],
      catalog: {
        "acme/coder": {
          name: "Acme Coder",
          contextWindow: 128000,
          maxOutputTokens: 8192,
        },
      },
    },
    network: {
      allowHosts: ["10.20.30.40", "10.0.0.6", "sandbox.corp.internal"],
    },
    ...extra,
  };
}

const gateway = (fields: Json): Json => ({
  inference: { provider: "openai-compatible", ...fields },
});
const broker = (fields: Json): Json => ({
  credential: { provider: "http-broker", broker: fields },
});
const oidc = (fields: Json): Json => ({
  identity: {
    mode: "oidc",
    oidc: {
      clientId: "acmecode",
      redirectUri: "http://127.0.0.1:8765/callback",
      ...fields,
    },
  },
});

function rejects(input: Json, field: string, message?: string): void {
  let error: unknown;
  try {
    parseManifest(input);
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(ManifestError);
  expect((error as ManifestError).field).toBe(field);
  if (message) expect((error as ManifestError).message).toContain(message);
}

const warnings = (input: Json) => launchWarnings(parseManifest(input));

describe("httpTransport on access endpoints", () => {
  it("is absent unless declared, so existing manifests parse and lock unchanged", () => {
    const access = parseManifest(manifest()).access;
    expect(access?.inference).not.toHaveProperty("httpTransport");
    expect(access?.credential.broker).not.toHaveProperty("httpTransport");
    expect(
      access?.identity.mode === "oidc" ? access.identity.oidc : {},
    ).not.toHaveProperty("httpTransport");
    const explicit = parseManifest(
      manifest({
        ...gateway({
          baseUrl: "https://gateway.acme.example/v1",
          httpTransport: "https",
        }),
      }),
    ).access;
    // An explicit https is recorded: it differs from the default.
    expect(explicit?.inference).toMatchObject({ httpTransport: "https" });
  });

  it("admits plain HTTP to a private host by default and says nothing in the lock", () => {
    const access = parseManifest(
      manifest({
        ...gateway({ baseUrl: "http://10.20.30.40:4000/v1" }),
        ...broker({ endpoint: "http://10.20.30.40:8080/token" }),
        ...oidc({ issuer: "http://keycloak.corp.internal/realms/acme" }),
      }),
    ).access;
    expect(access?.inference.baseUrl).toBe("http://10.20.30.40:4000/v1");
    expect(access?.inference).not.toHaveProperty("httpTransport");
    expect(access?.credential.broker).not.toHaveProperty("httpTransport");
  });

  it("forces https with httpTransport: https", () => {
    rejects(
      manifest(
        gateway({
          baseUrl: "http://10.20.30.40:4000/v1",
          httpTransport: "https",
        }),
      ),
      "inference.baseUrl",
      "this endpoint is https-only (inference.httpTransport: https",
    );
    rejects(
      manifest(
        broker({
          endpoint: "http://10.20.30.40:8080/token",
          httpTransport: "https",
        }),
      ),
      "credential.broker.endpoint",
      "credential.broker.httpTransport: https",
    );
    rejects(
      manifest(
        oidc({
          issuer: "http://keycloak.corp.internal",
          httpTransport: "https",
        }),
      ),
      "identity.oidc.issuer",
      "identity.oidc.httpTransport: https",
    );
  });

  it("accepts plain HTTP to a private or internal host with http-allowed", () => {
    for (const baseUrl of [
      "http://10.20.30.40:4000/v1",
      "http://172.16.0.1/v1",
      "http://192.168.1.10:4000/v1",
      "http://100.64.0.1/v1",
      "http://[fd00::1]:4000/v1",
      "http://gateway.corp.internal/v1",
      "http://litellm/v1",
    ]) {
      const access = parseManifest(
        manifest(gateway({ baseUrl, httpTransport: "http-allowed" })),
      ).access;
      expect(access?.inference.httpTransport, baseUrl).toBe("http-allowed");
      expect(access?.inference.baseUrl).toBe(baseUrl);
    }
    const access = parseManifest(
      manifest({
        ...broker({
          endpoint: "http://10.20.30.40:8080/token",
          revokeEndpoint: "http://10.20.30.40:8080/revoke",
          httpTransport: "http-allowed",
        }),
        ...oidc({
          issuer: "http://keycloak.corp.internal/realms/acme",
          httpTransport: "http-allowed",
        }),
      }),
    ).access;
    expect(access?.credential.broker?.httpTransport).toBe("http-allowed");
    expect(
      access?.identity.mode === "oidc" && access.identity.oidc.httpTransport,
    ).toBe("http-allowed");
  });

  it("refuses plain HTTP to a public host, including public IP literals", () => {
    for (const baseUrl of [
      "http://gateway.acme.example/v1",
      "http://8.8.8.8/v1",
      "http://172.32.0.1/v1",
      "http://[2001:db8::1]/v1",
      "http://com/v1",
    ])
      rejects(
        manifest(gateway({ baseUrl, httpTransport: "http-allowed" })),
        "inference.baseUrl",
        "is public, so serve it over https",
      );
    rejects(
      manifest(
        broker({
          endpoint: "https://broker.acme.example/token",
          revokeEndpoint: "http://broker.acme.example/revoke",
          httpTransport: "http-allowed",
        }),
      ),
      "credential.broker.revokeEndpoint",
      "is public",
    );
    rejects(
      manifest(
        oidc({
          issuer: "http://login.acme.example",
          httpTransport: "http-allowed",
        }),
      ),
      "identity.oidc.issuer",
      "is public",
    );
  });

  it("refuses plain HTTP to a public host by default too", () => {
    for (const input of [
      manifest(gateway({ baseUrl: "http://gw.acme.example/v1" })),
      manifest(broker({ endpoint: "http://broker.acme.example/token" })),
      manifest(oidc({ issuer: "http://login.acme.example" })),
    ]) {
      let message = "";
      try {
        parseManifest(input);
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain("is public, so serve it over https");
    }
  });

  it("refuses userinfo, a query, and an unknown value", () => {
    rejects(
      manifest(
        gateway({
          baseUrl: "http://user:pw@10.20.30.40:4000/v1",
          httpTransport: "http-allowed",
        }),
      ),
      "inference.baseUrl",
      "must not embed credentials",
    );
    rejects(
      manifest(
        gateway({
          baseUrl: "http://10.20.30.40:4000/v1?x=1",
          httpTransport: "http-allowed",
        }),
      ),
      "inference.baseUrl",
      "query strings",
    );
    rejects(
      manifest(
        gateway({
          baseUrl: "http://10.20.30.40:4000/v1",
          httpTransport: "http",
        }),
      ),
      "inference.httpTransport",
      "Expected https, http-allowed",
    );
  });

  it("does not apply to the OIDC redirect, which stays a loopback redirect", () => {
    rejects(
      manifest(
        oidc({
          issuer: "http://keycloak.corp.internal",
          redirectUri: "http://10.0.0.5:8765/callback",
          httpTransport: "http-allowed",
        }),
      ),
      "identity.oidc.redirectUri",
    );
  });

  it("is a piship/v1alpha6 field: v1alpha5 rejects it", () => {
    const v5 = (extra: Json) => ({
      ...manifest(extra),
      schema: PISHIP_SCHEMA_V1ALPHA5,
    });
    rejects(
      v5(
        gateway({
          baseUrl: "https://gateway.acme.example/v1",
          httpTransport: "https",
        }),
      ),
      "inference.httpTransport",
    );
    rejects(
      v5(
        broker({
          endpoint: "https://broker.acme.example/token",
          httpTransport: "http-allowed",
        }),
      ),
      "credential.broker.httpTransport",
    );
    rejects(
      v5(
        oidc({
          issuer: "https://login.acme.example",
          httpTransport: "http-allowed",
        }),
      ),
      "identity.oidc.httpTransport",
    );
  });

  it("accepts a runtime reference, which is checked again when it resolves", () => {
    const access = parseManifest(
      manifest({
        variables: ["GATEWAY_URL"],
        ...gateway({ baseUrl: GATEWAY_REF, httpTransport: "http-allowed" }),
      }),
    ).access;
    expect(access?.inference.baseUrl).toBe(GATEWAY_REF);
    expect(
      warnings(
        manifest({
          variables: ["GATEWAY_URL"],
          ...gateway({ baseUrl: GATEWAY_REF, httpTransport: "http-allowed" }),
        }),
      ),
    ).toContainEqual({
      path: "network",
      message: expect.stringContaining(
        "inference.baseUrl, if it resolves to plain HTTP (the gateway credential",
      ),
    });
    // A reference is not guessed at without the explicit setting.
    expect(
      warnings(
        manifest({
          variables: ["GATEWAY_URL"],
          ...gateway({ baseUrl: GATEWAY_REF }),
        }),
      ),
    ).toEqual([]);
  });

  it("warns that the credential and prompts are unencrypted, and about spoofable names", () => {
    const found = warnings(
      manifest({
        ...gateway({
          baseUrl: "http://litellm:4000/v1",
          httpTransport: "http-allowed",
        }),
        ...broker({
          endpoint: "http://broker.local/token",
          httpTransport: "http-allowed",
        }),
        ...oidc({
          issuer: "https://login.acme.example",
          httpTransport: "http-allowed",
        }),
        network: { allowHosts: ["litellm", "broker.local"] },
      }),
    );
    const at = (path: string) =>
      found.filter((item) => item.path === path).map((item) => item.message);
    // One line for every unencrypted endpoint.
    expect(at("network")).toHaveLength(1);
    expect(at("network")[0]).toBe(
      "Plain HTTP to a private or internal host is admitted by default, and these endpoints travel unencrypted and unauthenticated on the network path: " +
        "identity.oidc.issuer, if it resolves to plain HTTP (the authorization code and the identity tokens, including the refresh token, which anyone on the network path can read and replay); " +
        "credential.broker.endpoint (the identity token sent to the broker and the gateway credential it issues, which anyone on the network path can read and replay until they expire); " +
        "inference.baseUrl (the gateway credential, which anyone on the network path can read and replay until it expires, and every prompt, file excerpt, and response, which can also be altered in transit). " +
        "Serve them over https where possible, or set httpTransport: https on an endpoint to require it",
    );
    expect(at("inference.baseUrl").join()).toContain(
      "litellm is resolved through mDNS or the machine's DNS search domains",
    );
    expect(at("credential.broker.endpoint").join()).toContain(
      "broker.local is resolved through mDNS",
    );
    // An IP literal or a name under .internal is not spoofable this way.
    expect(
      warnings(
        manifest(
          gateway({
            baseUrl: "http://10.20.30.40:4000/v1",
            httpTransport: "http-allowed",
          }),
        ),
      ).map((item) => item.path),
    ).not.toContain("inference.baseUrl");
  });
});

describe("httpTransport on audit sinks and the sandbox", () => {
  const sink = (fields: Json): Json => ({
    audit: {
      sinks: [{ id: "collector", type: "http", ...fields }],
    },
  });
  const sandbox = (fields: Json): Json => ({
    sandbox: { required: true, provider: "e2b-compatible", ...fields },
  });

  it("accepts plain HTTP to a private host per sink, and records only what is declared", () => {
    const parsed = parseManifest(
      manifest(
        sink({
          url: "http://10.0.0.6:9000/events",
          httpTransport: "http-allowed",
        }),
      ),
    ).governance?.audit.sinks[0];
    expect(parsed).toMatchObject({
      url: "http://10.0.0.6:9000/events",
      httpTransport: "http-allowed",
    });
    expect(
      parseManifest(manifest(sink({ url: "https://audit.acme.example/e" })))
        .governance?.audit.sinks[0],
    ).not.toHaveProperty("httpTransport");
    expect(
      parseManifest(manifest(sink({ url: "http://10.0.0.6:9000/events" })))
        .governance?.audit.sinks[0],
    ).not.toHaveProperty("httpTransport");
    rejects(
      manifest(
        sink({ url: "http://10.0.0.6:9000/events", httpTransport: "https" }),
      ),
      "audit.sinks[0].url",
      "Use https",
    );
    rejects(
      manifest(
        sink({
          url: "http://audit.acme.example/events",
          httpTransport: "http-allowed",
        }),
      ),
      "audit.sinks[0].url",
      "is public",
    );
    rejects(
      manifest({
        audit: {
          sinks: [{ id: "local", type: "file", httpTransport: "http-allowed" }],
        },
      }),
      "audit.sinks[0].httpTransport",
    );
    expect(
      warnings(
        manifest(
          sink({
            url: "http://10.0.0.6:9000/events",
            httpTransport: "http-allowed",
          }),
        ),
      ).map((item) => item.path),
    ).toContain("network");
  });

  it("accepts a private sandbox endpoint and router, and refuses a public one", () => {
    const parsed = parseManifest(
      manifest(
        sandbox({
          endpoint: "http://sandbox.corp.internal:3000",
          httpTransport: "http-allowed",
        }),
      ),
    ).governance?.sandbox;
    expect(parsed?.httpTransport).toBe("http-allowed");
    rejects(
      manifest(
        sandbox({
          endpoint: "http://sandbox.acme.example",
          httpTransport: "http-allowed",
        }),
      ),
      "sandbox.endpoint",
      "is public",
    );
    rejects(
      manifest(
        sandbox({
          provider: "kubernetes-agent-sandbox",
          endpoint: "http://10.0.0.7:8080",
          router: "http://router.acme.example",
          template: "python",
          httpTransport: "http-allowed",
        }),
      ),
      "sandbox.router",
      "is public",
    );
    expect(
      parseManifest(
        manifest(sandbox({ endpoint: "http://sandbox.corp.internal:3000" })),
      ).governance?.sandbox,
    ).toMatchObject({ endpoint: "http://sandbox.corp.internal:3000" });
    rejects(
      manifest(
        sandbox({
          endpoint: "http://sandbox.corp.internal:3000",
          httpTransport: "https",
        }),
      ),
      "sandbox.endpoint",
      "Use https",
    );
  });

  it("never sends the runtime credential to a plain-HTTP sandbox", () => {
    rejects(
      manifest(
        sandbox({
          endpoint: "http://sandbox.corp.internal:3000",
          credential: "runtime",
          httpTransport: "http-allowed",
        }),
      ),
      "sandbox.httpTransport",
      "the runtime credential is never sent to the sandbox over plain HTTP",
    );
    // Without the explicit setting the runtime credential is still kept off
    // plain HTTP: the endpoint must be https.
    rejects(
      manifest(
        sandbox({
          endpoint: "http://sandbox.corp.internal:3000",
          credential: "runtime",
        }),
      ),
      "sandbox.endpoint",
      "Use https",
    );
    expect(
      warnings(
        manifest(
          sandbox({
            endpoint: "http://sandbox.corp.internal:3000",
            credential: "stored",
            httpTransport: "http-allowed",
          }),
        ),
      ).find((item) => item.path === "network")?.message,
    ).toContain("the stored sandbox credential");
  });

  it("is refused for the native sandbox and on v1alpha5", () => {
    rejects(
      manifest({
        sandbox: { required: true, httpTransport: "http-allowed" },
      }),
      "sandbox.httpTransport",
    );
    rejects(
      {
        ...manifest(
          sink({
            url: "https://audit.acme.example/e",
            httpTransport: "https",
          }),
        ),
        schema: PISHIP_SCHEMA_V1ALPHA5,
      },
      "audit.sinks[0].httpTransport",
    );
    rejects(
      {
        ...manifest(
          sandbox({
            endpoint: "https://sandbox.acme.example",
            httpTransport: "http-allowed",
          }),
        ),
        schema: PISHIP_SCHEMA_V1ALPHA5,
      },
      "sandbox.httpTransport",
    );
  });
});

describe("plainHttpProblem", () => {
  it("judges only plain HTTP, and only by the host name", () => {
    expect(plainHttpProblem(new URL("https://example.com"))).toBeUndefined();
    expect(plainHttpProblem(new URL("http://10.1.2.3"))).toBeUndefined();
    expect(plainHttpProblem(new URL("http://example.com"))).toContain(
      "example.com is public",
    );
  });
});

describe("plainHttpPermitted and effectiveHttpTransport", () => {
  it("permit every transport but an explicit https", () => {
    expect(plainHttpPermitted(undefined)).toBe(true);
    expect(plainHttpPermitted("http-allowed")).toBe(true);
    expect(plainHttpPermitted("https")).toBe(false);
    expect(effectiveHttpTransport(undefined)).toBe("http-allowed");
    expect(effectiveHttpTransport("https")).toBe("https");
    // A runtime credential is never sent over plain HTTP.
    expect(effectiveHttpTransport(undefined, true)).toBe("https");
  });
});
