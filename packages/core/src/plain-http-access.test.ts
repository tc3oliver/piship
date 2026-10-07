// httpTransport on the access endpoints: plain HTTP to a private host is
// admitted by default, runtime references are checked again when they
// resolve, plain HTTP is admitted for the gateway's origin only, httpTransport:
// https forces HTTPS-only, and config explain shows the effective transport.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AccessManifest, GovernanceManifest } from "@piship/schema";
import { afterEach, describe, expect, it } from "vitest";
import {
  DistributionAccess,
  explainConfiguration,
  resolveRuntimeReferences,
} from "./access/index.js";
import { resolveLock } from "./index.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const ENV = {
  ACMECODE_OIDC_ISSUER: "http://keycloak.corp.internal/realms/acme",
  ACMECODE_OIDC_CLIENT_ID: "acmecode",
  ACMECODE_CREDENTIAL_BROKER_URL: "http://10.20.30.40:8080/token",
  ACMECODE_CREDENTIAL_REVOKE_URL: "http://10.20.30.40:8080/revoke",
  ACMECODE_LLM_GATEWAY_URL: "http://10.20.30.40:4000/v1",
};

/** The demo's access section with every endpoint set to `transport`. */
function withTransport(
  access: AccessManifest,
  transport: "http-allowed" | "https",
): AccessManifest {
  if (access.identity.mode !== "oidc" || !access.credential.broker)
    throw new Error("the demo uses OIDC and the broker");
  return {
    ...access,
    identity: {
      ...access.identity,
      oidc: { ...access.identity.oidc, httpTransport: transport },
    },
    credential: {
      ...access.credential,
      broker: { ...access.credential.broker, httpTransport: transport },
    },
    inference: { ...access.inference, httpTransport: transport },
  };
}
const optedIn = (access: AccessManifest) =>
  withTransport(access, "http-allowed");

describe("access endpoints and httpTransport", () => {
  const lock = resolveLock(DEMO);
  const access = lock.access as AccessManifest;

  it("resolves plain-HTTP references to private hosts unless https is forced", () => {
    expect(() =>
      resolveRuntimeReferences(withTransport(access, "https"), ENV),
    ).toThrow(
      /inference\.baseUrl resolved to an unacceptable URL|identity\.oidc\.issuer resolved to an unacceptable URL/,
    );
    // The demo says nothing about httpTransport: that is the default.
    for (const manifest of [access, optedIn(access)]) {
      const resolved = resolveRuntimeReferences(manifest, ENV);
      expect(resolved.baseUrl).toBe(ENV.ACMECODE_LLM_GATEWAY_URL);
      expect(resolved.brokerEndpoint).toBe(ENV.ACMECODE_CREDENTIAL_BROKER_URL);
      expect(resolved.issuer).toBe(ENV.ACMECODE_OIDC_ISSUER);
    }
    // A reference that resolves to a public plain-HTTP host fails closed.
    for (const [name, field] of [
      ["ACMECODE_LLM_GATEWAY_URL", "inference.baseUrl"],
      ["ACMECODE_CREDENTIAL_REVOKE_URL", "credential.broker.revokeEndpoint"],
      ["ACMECODE_OIDC_ISSUER", "identity.oidc.issuer"],
    ] as const)
      expect(() =>
        resolveRuntimeReferences(access, {
          ...ENV,
          [name]: "http://gateway.acme.example/v1",
        }),
      ).toThrow(
        expect.objectContaining({
          code: "CONFIG_INVALID",
          message: expect.stringContaining(`${field} resolved to`),
        }),
      );
    expect(() =>
      resolveRuntimeReferences(optedIn(access), {
        ...ENV,
        ACMECODE_LLM_GATEWAY_URL: "http://user:pw@10.20.30.40:4000/v1",
      }),
    ).toThrow(/must not embed credentials/);
  });

  it("admits plain HTTP on the process dispatcher for the gateway's origin only", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "piship-plain-http-"));
    roots.push(stateDir);
    const open = (
      manifest: AccessManifest,
      env: Record<string, string> = ENV,
    ) =>
      DistributionAccess.open({
        app: lock.app as never,
        mode: "managed",
        access: manifest,
        stateDir,
        distributionDir: stateDir,
        env,
      });
    const opened = open(access);
    const admit = opened.inferencePlainHttp;
    expect(admit?.(new URL("http://10.20.30.40:4000/v1/chat"))).toBe(true);
    // The broker shares the host but not the port; it is not the gateway.
    expect(admit?.(new URL("http://10.20.30.40:8080/token"))).toBe(false);
    expect(admit?.(new URL("http://keycloak.corp.internal/"))).toBe(false);
    // Only the gateway's own setting widens the process dispatcher.
    const brokerOnly = withTransport(access, "http-allowed");
    expect(
      open(
        {
          ...brokerOnly,
          inference: { ...brokerOnly.inference, httpTransport: "https" },
        },
        { ...ENV, ACMECODE_LLM_GATEWAY_URL: "https://10.20.30.40:4000/v1" },
      ).inferencePlainHttp,
    ).toBeUndefined();
    // Allowed, but the gateway resolves to https: nothing is widened.
    expect(
      open(access, {
        ...ENV,
        ACMECODE_LLM_GATEWAY_URL: "https://10.20.30.40:4000/v1",
      }).inferencePlainHttp,
    ).toBeUndefined();
    expect(open(access).network.allowHosts).toEqual([
      "10.20.30.40",
      "keycloak.corp.internal",
    ]);
  });

  it("is shown by config explain as the effective transport of each endpoint", async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "piship-plain-http-"));
    roots.push(stateDir);
    const governance = lock.governance?.manifest as GovernanceManifest;
    const explain = (manifest: AccessManifest, gov: GovernanceManifest) =>
      explainConfiguration({
        app: lock.app as never,
        mode: "managed",
        access: manifest,
        stateDir,
        distributionDir: stateDir,
        env: ENV,
        schema: lock.manifest.schema,
        governance: gov,
      });
    const keys = (rows: Awaited<ReturnType<typeof explain>>) =>
      rows.filter((row) => row.key.endsWith("httpTransport"));
    // Absent is the default: plain HTTP to a private host is allowed.
    expect(
      keys(await explain(access, governance)).map((row) => [
        row.key,
        row.value,
        row.source,
      ]),
    ).toEqual([
      ["identity.oidc.httpTransport", "http-allowed", "builtin-default"],
      ["credential.broker.httpTransport", "http-allowed", "builtin-default"],
      ["inference.httpTransport", "http-allowed", "builtin-default"],
    ]);
    // https forces HTTPS-only and is shown as the owner's choice.
    expect(
      keys(await explain(withTransport(access, "https"), governance)).map(
        (row) => [row.key, row.value, row.source],
      ),
    ).toEqual([
      ["identity.oidc.httpTransport", "https", "distribution-enforced"],
      ["credential.broker.httpTransport", "https", "distribution-enforced"],
      ["inference.httpTransport", "https", "distribution-enforced"],
    ]);
    const rows = keys(
      await explain(optedIn(access), {
        ...governance,
        sandbox: {
          ...governance.sandbox,
          endpoint: "http://sandbox.corp.internal:3000",
          httpTransport: "http-allowed",
        },
        audit: {
          ...governance.audit,
          sinks: [
            {
              id: "collector",
              type: "http",
              url: "http://10.0.0.6/events",
              required: false,
              httpTransport: "http-allowed",
            },
          ],
        },
      }),
    );
    expect(rows.map((row) => [row.key, row.value])).toEqual([
      ["identity.oidc.httpTransport", "http-allowed"],
      ["credential.broker.httpTransport", "http-allowed"],
      ["inference.httpTransport", "http-allowed"],
      ["sandbox.httpTransport", "http-allowed"],
      ["audit.sinks[0].httpTransport", "http-allowed"],
    ]);
    expect(rows[2]?.note).toContain(
      "the gateway credential and every prompt and response are then unencrypted",
    );
  });
});
