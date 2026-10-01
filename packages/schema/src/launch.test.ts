import { describe, expect, it } from "vitest";
import {
  launchWarnings,
  ManifestError,
  PISHIP_SCHEMA_V1ALPHA4,
  parseManifest,
} from "./index.js";

type Json = Record<string, unknown>;

const catalog = {
  "acme/coder": {
    name: "Acme Coder",
    contextWindow: 128000,
    maxOutputTokens: 8192,
  },
};
/** A managed v1alpha4 manifest with plain https endpoints. */
function managed(extra: Json = {}): Json {
  return {
    schema: PISHIP_SCHEMA_V1ALPHA4,
    app: {
      id: "acmecode",
      name: "AcmeCode",
      command: "acmecode",
      version: "1.0.0",
    },
    runtime: { pi: "0.87.1" },
    deployment: { mode: "managed" },
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
    models: { default: "acme/coder", allowed: ["acme/coder"], catalog },
    updates: { channel: "stable", channels: ["stable"] },
    ...extra,
  };
}
function rejects(input: Json, field: string, message: string) {
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
function warnings(input: Json) {
  return launchWarnings(parseManifest(input));
}

describe("network.tls.additionalCA paths", () => {
  it("warns about a relative bundle path, which is read from the launch directory", () => {
    for (const path of ["certs/acme.pem", "./certs/acme.pem", "~/acme.pem"])
      expect(
        warnings(managed({ network: { tls: { additionalCA: [path] } } })),
      ).toEqual([
        expect.objectContaining({
          path: "network.tls.additionalCA[0]",
          message: expect.stringContaining("absolute"),
        }),
      ]);
  });
  it("accepts absolute paths and a variable that supplies the whole path", () => {
    for (const path of [
      "/etc/acme/ca.pem",
      "C:\\ProgramData\\Acme\\ca.pem",
      `\${ACME_CA_BUNDLE}`,
    ])
      expect(
        warnings(
          managed({
            variables: path.startsWith("$") ? ["ACME_CA_BUNDLE"] : [],
            network: { tls: { additionalCA: [path] } },
          }),
        ),
      ).toEqual([]);
  });
  it("warns when a variable fills only part of a relative path", () => {
    expect(
      warnings(
        managed({
          variables: ["ACME_CA_NAME"],
          network: { tls: { additionalCA: [`certs/\${ACME_CA_NAME}.pem`] } },
        }),
      ).map((item) => item.path),
    ).toEqual(["network.tls.additionalCA[0]"]);
  });
});

describe("HTTP audit sinks under a private-only network policy", () => {
  const sink = (url: string, required = true): Json => ({
    audit: {
      enabled: true,
      sinks: [{ id: "siem", type: "http", url, required }],
    },
  });
  const personal = (extra: Json): Json => ({
    ...managed(extra),
    deployment: { mode: "personal" },
    identity: { mode: "none" },
    credential: { provider: "local-secret" },
    models: { allowed: ["acme/coder"], catalog },
  });
  it("rejects a required sink whose host the launch can never contact", () => {
    rejects(
      managed(sink("https://siem.acme.example/events")),
      "audit.sinks[0].url",
      "siem.acme.example is not in network.allowHosts",
    );
    rejects(
      personal({
        ...sink("https://siem.acme.example/events"),
        network: { privateOnly: true },
      }),
      "audit.sinks[0].url",
      "network.allowHosts",
    );
  });
  it("accepts the sink host when it is allowed or is a declared endpoint host", () => {
    for (const extra of [
      {
        ...sink("https://siem.acme.example/events"),
        network: { allowHosts: ["siem.acme.example"] },
      },
      sink("https://gateway.acme.example/audit"),
      sink("https://siem.acme.example/events", false),
    ])
      expect(() => parseManifest(managed(extra))).not.toThrow();
    // Personal mode is not private-only unless it says so.
    expect(
      warnings(personal(sink("https://siem.acme.example/events"))),
    ).toEqual([]);
  });
  it("warns when the host is decided by a runtime variable or the sink is optional", () => {
    expect(
      warnings(managed(sink("https://siem.acme.example/events", false))),
    ).toEqual([
      expect.objectContaining({
        path: "audit.sinks[0].url",
        message: expect.stringContaining("dropped"),
      }),
    ]);
    expect(
      warnings(
        managed({
          variables: ["ACME_SIEM_URL"],
          ...sink(`\${ACME_SIEM_URL}`),
        }),
      ).map((item) => item.path),
    ).toEqual(["audit.sinks[0].url"]);
    // A templated endpoint may resolve to the sink's host; not certain.
    const templated = managed({
      variables: ["ACME_GATEWAY_URL"],
      ...sink("https://siem.acme.example/events"),
    });
    (templated.inference as Json).baseUrl = `\${ACME_GATEWAY_URL}`;
    expect(warnings(templated).map((item) => item.path)).toEqual([
      "audit.sinks[0].url",
    ]);
  });
  it("ignores the sinks of a disabled audit log", () => {
    const extra = sink("https://siem.acme.example/events");
    (extra.audit as Json).enabled = false;
    expect(warnings(managed(extra))).toEqual([]);
  });
});
