import { describe, expect, it } from "vitest";
import {
  launchWarnings,
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
