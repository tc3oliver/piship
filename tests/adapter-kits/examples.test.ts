// Every conformance kit run against the SDK's example adapters
// (packages/adapter-sdk/examples). An example is what a company copies, so a
// good one passes every behavior its kit can exercise; what the kit cannot
// exercise is skipped with a reason, never passed. The services the
// examples call are fakes the kits (or this file) own.
import {
  CREDENTIAL_BEHAVIORS,
  type IssuedCredential,
  IDENTITY_BEHAVIORS,
  SANDBOX_BEHAVIORS,
  testCredentialAdapter,
  testIdentityAdapter,
  testSandboxAdapter,
} from "@piship/adapter-conformance";
import type {
  AdapterFactory,
  CredentialProvider,
  IdentityProvider,
  SandboxAdapterFactory,
} from "@piship/adapter-sdk";
import { afterAll, describe, expect, it } from "vitest";
import { ExecutionService } from "./execution-service.js";
import { isolator } from "./isolator.js";
import { itIsolated } from "./isolator-gate.js";
import {
  examplesPayload,
  reasons,
  record,
  statuses,
  writeReports,
} from "./support.js";

// The examples time a request out after 30 s; the kits wait a few times a
// request's timeout for a stalled call, so the copies under test use 200 ms.
const TIMEOUT_MS = 200;
const SHORT_TIMEOUT: [RegExp, string] = [
  /const TIMEOUT_MS = 30_000;/,
  `const TIMEOUT_MS = ${TIMEOUT_MS};`,
];

const payload = examplesPayload();
afterAll(() => {
  payload.close();
  writeReports();
});

const every = (behaviors: readonly string[], status: string) =>
  Object.fromEntries(behaviors.map((behavior) => [behavior, status]));

describe("the SDK example adapters under the conformance kits", () => {
  it("credential.mjs passes every credential behavior", async () => {
    const adapter = await payload.load<AdapterFactory<CredentialProvider>>(
      "credential.mjs",
      [SHORT_TIMEOUT],
    );
    const report = record(
      "example credential.mjs",
      await testCredentialAdapter(adapter, {
        requestTimeoutMs: TIMEOUT_MS,
        // The example's service answers {key, id, expiresAt}.
        issue: (credential: IssuedCredential) =>
          Response.json({
            key: credential.secret,
            id: credential.credentialId,
            expiresAt: credential.expiresAt.toISOString(),
          }),
      }),
    );
    expect({ statuses: statuses(report), reasons: reasons(report) }).toEqual({
      statuses: every(CREDENTIAL_BEHAVIORS, "passed"),
      reasons: {},
    });
  }, 60_000);

  it("identity.mjs passes every identity behavior it can exercise without a token harness", async () => {
    const adapter = await payload.load<AdapterFactory<IdentityProvider>>(
      "identity.mjs",
      [SHORT_TIMEOUT],
    );
    const report = record(
      "example identity.mjs",
      await testIdentityAdapter(adapter, { requestTimeoutMs: TIMEOUT_MS }),
    );
    // The example validates no token itself: the service it calls does.
    const tokenChecks = [
      "invalid issuer",
      "invalid audience",
      "invalid signature",
      "token validity window",
      "revoked token",
    ];
    expect(statuses(report)).toEqual({
      ...every(IDENTITY_BEHAVIORS, "passed"),
      ...every(tokenChecks, "skipped"),
    });
    for (const behavior of tokenChecks)
      expect(reasons(report)[behavior]).toMatch(/^needs harness: /);
  }, 60_000);

  itIsolated(isolator)(
    "sandbox.mjs passes every sandbox behavior a deny-only snapshot backend can show",
    async () => {
      const adapter = await payload.load<SandboxAdapterFactory>("sandbox.mjs");
      const service = new ExecutionService();
      try {
        const report = record(
          "example sandbox.mjs",
          await testSandboxAdapter(adapter, {
            context: {
              endpoint: "https://exec.conformance.invalid/sandbox",
              fetch: service.fetch,
            },
            sandboxes: () => service.sessions.size,
            settleMs: 1_500,
            callTimeoutMs: 20_000,
          }),
        );
        const skipped = [
          // The example enforces only a denied network, so the kit cannot
          // show a connection that would succeed with the network allowed.
          "network claims",
          // A snapshot workspace: the sandbox never sees PiShip's files.
          "workspace consistency",
          "git control protection",
          "workspace re-check",
        ];
        expect({
          statuses: statuses(report),
          reasons: reasons(report),
        }).toEqual({
          statuses: {
            ...every(SANDBOX_BEHAVIORS, "passed"),
            ...every(skipped, "skipped"),
          },
          reasons: {
            "network claims": expect.stringMatching(
              /enforces only network deny/,
            ),
            "workspace consistency": expect.stringMatching(/declares snapshot/),
            "git control protection":
              expect.stringMatching(/declares snapshot/),
            "workspace re-check": expect.stringMatching(/declares snapshot/),
          },
        });
      } finally {
        service.close();
      }
    },
    180_000,
  );
});
