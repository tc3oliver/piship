// The network policy of update and rollback when a runtime variable is unset
// in the shell that runs them: the manifest's private-only rule and proxy
// setting still apply, so an undeclared host is never contacted.
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PiShipError } from "@piship/contracts";
import type { AccessManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  installed,
  stateDir,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import type { BrandedContext } from "./branded/context.js";
import {
  auditLifecycle,
  lifecycleNetwork,
  runUpdate,
} from "./branded/lifecycle.js";
import { resolveLock, verifyPayload } from "./index.js";
import { readInstallReceipt } from "./install/index.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const DEMO_VARIABLES = [
  "ACMECODE_OIDC_ISSUER",
  "ACMECODE_OIDC_CLIENT_ID",
  "ACMECODE_CREDENTIAL_BROKER_URL",
  "ACMECODE_CREDENTIAL_REVOKE_URL",
  "ACMECODE_LLM_GATEWAY_URL",
  "ACMECODE_UPDATE_SOURCE",
];

useLifecycleHomes();

let saved: Record<string, string | undefined>;
let server: Server;
let requests: string[];
let url: string;
beforeEach(async () => {
  saved = Object.fromEntries(
    DEMO_VARIABLES.map((key) => [key, process.env[key]]),
  );
  for (const key of DEMO_VARIABLES) delete process.env[key];
  requests = [];
  server = createServer((request, response) => {
    requests.push(`${request.method} ${request.url}`);
    request.resume();
    response.statusCode = 404;
    response.end();
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterEach(async () => {
  await new Promise<void>((done) => server.close(() => done()));
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});

/** The branded command of the installed active release. */
function installedContext(): BrandedContext {
  const receipt = readInstallReceipt(ID);
  return {
    metadata: verifyPayload(receipt.payload) as BrandedContext["metadata"],
    distributionDir: receipt.payload,
    stateDir: stateDir(),
    mode: "personal",
    out: () => {},
    err: () => {},
  };
}

async function refusal(promise: Promise<unknown>): Promise<PiShipError> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(PiShipError);
  return error as PiShipError;
}

describe.runIf(HOST_EVIDENCED)(
  "update with a private-only network and a runtime variable unset",
  () => {
    it("refuses an undeclared --from host when every variable is set", async () => {
      await installed(true);
      process.env.ACMEPI_GATEWAY_URL = "http://localhost:9/v1";
      const error = await refusal(
        runUpdate(installedContext(), ["--check", "--from", `${url}/`]),
      );
      expect(error.code).toBe("NETWORK_DENIED");
      expect(requests).toEqual([]);
    });

    it("still refuses it when the gateway variable is unset", async () => {
      await installed(true);
      delete process.env.ACMEPI_GATEWAY_URL;
      const ctx = installedContext();
      expect(lifecycleNetwork(ctx)).toMatchObject({
        privateOnly: true,
        allowHosts: [],
      });
      const error = await refusal(
        runUpdate(ctx, ["--check", "--from", `${url}/`]),
      );
      expect(error.code).toBe("NETWORK_DENIED");
      expect(requests).toEqual([]);
    });
  },
);

describe("lifecycle audit with every runtime variable unset", () => {
  let temp: string;
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), "piship-lifecycle-network-"));
  });
  afterEach(() => {
    rmSync(temp, { recursive: true, force: true });
  });

  function demoContext(): BrandedContext {
    const lock = resolveLock(DEMO);
    const governance = lock.governance as NonNullable<typeof lock.governance>;
    return {
      metadata: {
        ...lock,
        governance: {
          ...governance,
          manifest: {
            ...governance.manifest,
            audit: {
              ...governance.manifest.audit,
              enabled: true,
              sinks: [
                {
                  id: "company",
                  type: "http",
                  url: `${url}/audit`,
                  required: true,
                },
              ],
            },
          },
        },
      },
      distributionDir: temp,
      stateDir: join(temp, "state"),
      mode: "managed",
      out: () => {},
      err: () => {},
      auditCloseDeadlineMs: 300,
    };
  }

  it("keeps the manifest's network policy", () => {
    const ctx = demoContext();
    const access = ctx.metadata.access as AccessManifest;
    expect(lifecycleNetwork(ctx)).toEqual({
      inheritProxyEnvironment: access.network.proxy.inheritEnvironment,
      additionalCA: [],
      privateOnly: true,
      allowHosts: [...access.network.allowHosts].sort(),
    });
  });

  it("does not send an event to a sink host the manifest does not declare", async () => {
    const error = await refusal(
      auditLifecycle(demoContext(), "runtime.update", "allowed", {
        from: "1.0.0",
      }),
    );
    expect(error.code).toBe("AUDIT_UNAVAILABLE");
    expect(requests).toEqual([]);
  });
});
