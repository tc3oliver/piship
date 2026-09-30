// Every conformance kit run against PiShip's own implementations, reached
// through their packages' public surface: the http-broker credential
// provider, the built-in HTTP audit sink's delivery, the native sandbox
// backend, the e2b-compatible backend against a fake service that runs each
// command for real, and a custom backend as PiShip's loader wraps it. Where
// a built-in fails a behavior, the expectation below names the decision:
// a PiShip defect is fixed, and a point where the kit is stricter than
// PiShip is documented in docs/adapter-sdk.md.
import {
  AUDIT_SINK_BEHAVIORS,
  CREDENTIAL_BEHAVIORS,
  SANDBOX_BEHAVIORS,
  testAuditSink,
  testCredentialAdapter,
  testSandboxAdapter,
} from "@piship/adapter-conformance";
import type {
  AdapterContext,
  SandboxAdapterFactory,
} from "@piship/adapter-sdk";
import { HttpSinkWriter } from "@piship/audit";
import { HttpBrokerCredentialProvider } from "@piship/credentials";
import {
  customBackend,
  E2bCompatibleBackend,
  NativeBackend,
} from "@piship/sandbox";
import { afterAll, describe, expect, it } from "vitest";
import { E2B_ENDPOINT, E2bService } from "./e2b-service.js";
import { ExecutionService } from "./execution-service.js";
import { isolator } from "./isolator.js";
import { describeIsolated } from "./isolator-gate.js";
import {
  examplesPayload,
  reasons,
  record,
  statuses,
  writeReports,
} from "./support.js";

const TIMEOUT_MS = 200;
const TIMINGS = { settleMs: 1_500, callTimeoutMs: 20_000 } as const;
const WORKSPACE = [
  "workspace consistency",
  "git control protection",
  "workspace re-check",
] as const;

const payload = examplesPayload();
afterAll(() => {
  payload.close();
  writeReports();
});

const every = (behaviors: readonly string[], status: string) =>
  Object.fromEntries(behaviors.map((behavior) => [behavior, status]));

describe("PiShip's built-in implementations under the conformance kits", () => {
  it("the http-broker credential provider passes every credential behavior", async () => {
    const report = record(
      "built-in HttpBrokerCredentialProvider",
      await testCredentialAdapter(
        (context: AdapterContext) =>
          new HttpBrokerCredentialProvider({
            endpoint: context.endpoints.brokerEndpoint ?? "",
            ...(context.endpoints.brokerRevokeEndpoint
              ? { revokeEndpoint: context.endpoints.brokerRevokeEndpoint }
              : {}),
            fetch: context.fetch,
            timeoutMs: TIMEOUT_MS,
          }),
        { requestTimeoutMs: TIMEOUT_MS },
      ),
    );
    expect({ statuses: statuses(report), reasons: reasons(report) }).toEqual({
      statuses: every(CREDENTIAL_BEHAVIORS, "passed"),
      reasons: {},
    });
  }, 60_000);

  it("the HTTP audit sink's delivery passes every audit behavior a plain sink can show", async () => {
    const report = record(
      "built-in HTTP audit sink (HttpSinkWriter)",
      await testAuditSink(
        (env) => new HttpSinkWriter(new URL(env.url), env.fetch, 10_000),
      ),
    );
    // Queueing belongs to AuditLog, which holds events for the sink.
    expect({ statuses: statuses(report), reasons: reasons(report) }).toEqual({
      statuses: {
        ...every(AUDIT_SINK_BEHAVIORS, "passed"),
        "buffer behavior": "skipped",
        "shutdown flush": "skipped",
      },
      reasons: {
        "buffer behavior": expect.stringMatching(/PiShip's audit log buffer/),
        "shutdown flush": expect.stringMatching(/PiShip's audit log buffer/),
      },
    });
  }, 60_000);

  // Most of a sandbox kit run is waiting out its marker and settle windows,
  // so the four backends run concurrently; each has its own service.
  describeIsolated(isolator)("sandbox backends", () => {
    it.concurrent("the native backend passes every sandbox behavior of a local backend", async () => {
      const report = record(
        `built-in NativeBackend (${isolator})`,
        await testSandboxAdapter(new NativeBackend(), TIMINGS),
      );
      expect({ statuses: statuses(report), reasons: reasons(report) }).toEqual({
        statuses: {
          ...every(SANDBOX_BEHAVIORS, "passed"),
          // A local backend holds no sandboxes of its own to count.
          cleanup: "skipped",
          ...every(WORKSPACE, "skipped"),
        },
        reasons: {
          cleanup: expect.stringMatching(/pass sandboxes\(\)/),
          ...Object.fromEntries(
            WORKSPACE.map((behavior) => [
              behavior,
              expect.stringMatching(/a local backend runs commands/),
            ]),
          ),
        },
      });
    }, 180_000);

    it.concurrent("a custom backend as PiShip's loader wraps it passes like the adapter itself", async () => {
      const example = await payload.load<SandboxAdapterFactory>("sandbox.mjs");
      const service = new ExecutionService();
      try {
        // The loader imports the module and passes what its factory
        // returns through customBackend() (packages/pi governance).
        const loaded: SandboxAdapterFactory = async (context) =>
          customBackend(await example(context));
        const report = record(
          "custom backend through customBackend() (example sandbox.mjs)",
          await testSandboxAdapter(loaded, {
            ...TIMINGS,
            context: {
              endpoint: "https://exec.conformance.invalid/sandbox",
              fetch: service.fetch,
            },
            sandboxes: () => service.sessions.size,
          }),
        );
        expect(statuses(report)).toEqual({
          ...every(SANDBOX_BEHAVIORS, "passed"),
          "network claims": "skipped",
          ...every(WORKSPACE, "skipped"),
        });
      } finally {
        service.close();
      }
    }, 180_000);

    it.concurrent.each(["group", "process"] as const)(
      "the e2b-compatible backend, against a service whose SendSignal stops the %s",
      async (scope) => {
        const service = new E2bService(scope);
        try {
          const factory: SandboxAdapterFactory = async (context) =>
            new E2bCompatibleBackend({
              endpoint: context.endpoint ?? E2B_ENDPOINT,
              fetch: context.fetch,
              ...(context.credential ? { credential: context.credential } : {}),
              envdUrl: service.envdUrl,
            });
          const report = record(
            `built-in E2bCompatibleBackend (SendSignal stops the ${scope})`,
            await testSandboxAdapter(factory, {
              ...TIMINGS,
              context: { endpoint: E2B_ENDPOINT, fetch: service.fetch },
              sandboxes: () => service.sandboxes.size,
            }),
          );
          // Where the kit is stricter than PiShip (docs/adapter-sdk.md):
          // the backend passes a transport error from prepare() on as it
          // came, and PiShip redacts it where it reports it; and envd's
          // SendSignal stops the command's own process, so a background
          // process it started runs on until the sandbox is deleted, as
          // docs/sandbox.md states.
          const stricter = {
            "secret leakage":
              "after a transport error that quotes the credential: the credential appeared in the error from prepare()",
            ...(scope === "process"
              ? {
                  timeout:
                    "the timed-out command kept running and wrote its marker after the timeout",
                }
              : {}),
          };
          expect({
            statuses: statuses(report),
            reasons: reasons(report),
          }).toEqual({
            statuses: {
              ...every(SANDBOX_BEHAVIORS, "passed"),
              ...every(WORKSPACE, "skipped"),
              ...every(Object.keys(stricter), "failed"),
            },
            reasons: {
              ...stricter,
              ...Object.fromEntries(
                WORKSPACE.map((behavior) => [
                  behavior,
                  expect.stringMatching(/^declares snapshot/),
                ]),
              ),
            },
          });
        } finally {
          service.close();
        }
      },
      180_000,
    );
  });
});
