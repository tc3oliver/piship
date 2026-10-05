// The SDK's example adapters, loaded through PiShip's real loaders: identity
// and credential adapters through DistributionAccess (core), the sandbox
// adapter through the governance sandbox loader (pi), and the audit sink as
// the collector behind the built-in HTTP audit sink. The services they talk
// to are a local fake; this is loader evidence, not a live integration.
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inspect } from "node:util";
import type { AuditSink } from "@piship/adapter-sdk";
import { AuditLog } from "@piship/audit";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  NO_CONTENT_CAPTURE,
  SecretValue,
} from "@piship/contracts";
import { DistributionAccess, resolveLock } from "@piship/core";
import { MemorySecretStore } from "@piship/credentials";
import { inspectGovernance } from "@piship/pi";
import {
  type AccessManifest,
  PISHIP_SCHEMA_V1ALPHA2,
  parseManifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SDK_DIR = fileURLToPath(
  new URL("../packages/adapter-sdk/", import.meta.url),
);
const EXAMPLES = join(SDK_DIR, "examples");

interface Seen {
  readonly method: string;
  readonly path: string;
  readonly authorization?: string;
  readonly body: Record<string, unknown>;
}

let root: string;
let server: Server;
let url: string;
let seen: Seen[];
let collector: AuditSink | undefined;

async function body(request: IncomingMessage): Promise<string> {
  let text = "";
  for await (const chunk of request) text += chunk;
  return text;
}

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), "piship-sdk-examples-"));
  seen = [];
  collector = undefined;
  // A fake of every service the examples call.
  server = createServer(async (request, response) => {
    const text = await body(request);
    const parsed = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    const path = request.url ?? "";
    seen.push({
      method: request.method ?? "",
      path,
      ...(request.headers.authorization
        ? { authorization: request.headers.authorization }
        : {}),
      body: parsed,
    });
    const json = (value: unknown) => response.end(JSON.stringify(value));
    if (path === "/device")
      return json({
        deviceCode: "device-1",
        verificationUrl: `${url}/verify`,
      });
    if (path === "/token" || path === "/refresh")
      return json({
        subject: "user-1",
        issuer: url,
        name: "Ada",
        accessToken: "identity-access-token-1",
        refreshToken: "identity-refresh-token-1",
        expiresIn: 3600,
      });
    if (path === "/revoke") return json({});
    if (path === "/credentials" && request.method === "POST")
      return json({
        id: "cred-1",
        key: "sk-example-runtime-key",
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      });
    if (path.startsWith("/credentials/")) {
      response.statusCode = 204;
      return response.end();
    }
    if (path === "/sandbox/health") return json({ ok: true });
    if (path === "/sandbox/sessions") return json({ id: "session-1" });
    if (path === "/sandbox/sessions/session-1/exec") {
      // Report what actually arrived: PiShip must have filtered the
      // unlisted marker out of the approved environment.
      const env = (parsed.env ?? {}) as Record<string, string>;
      return json({
        exitCode: 0,
        stdout: `piship-sandbox-ready ${env.PISHIP_PROBE_UNLISTED ?? "unset"}\n`,
      });
    }
    if (path === "/sandbox/sessions/session-1") {
      response.statusCode = 204;
      return response.end();
    }
    if (path === "/collect" && collector) {
      try {
        await collector.write(parsed as never, AbortSignal.timeout(5000));
        response.statusCode = 204;
      } catch {
        response.statusCode = 400;
      }
      return response.end();
    }
    response.statusCode = 404;
    response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(root, { recursive: true, force: true });
});

/**
 * A payload-shaped distribution directory: the adapter in `resources/` and
 * the SDK in `node_modules/`, the only place a bare import resolves from.
 * The example's placeholder service URL points at the fake.
 */
function payload(examples: readonly string[], placeholder?: string): string {
  const distribution = join(root, "distribution");
  mkdirSync(join(distribution, "resources", "adapters"), { recursive: true });
  mkdirSync(join(distribution, "node_modules", "@piship"), { recursive: true });
  symlinkSync(
    SDK_DIR,
    join(distribution, "node_modules", "@piship", "adapter-sdk"),
    process.platform === "win32" ? "junction" : "dir",
  );
  for (const name of examples) {
    const target = join(distribution, "resources", "adapters", name);
    if (placeholder === undefined) copyFileSync(join(EXAMPLES, name), target);
    else
      writeFileSync(
        target,
        readFileSync(join(EXAMPLES, name), "utf8").replaceAll(
          /https:\/\/[a-z-]+\.example\.com/g,
          placeholder,
        ),
      );
  }
  return distribution;
}

describe("the SDK example adapters", () => {
  it("sign in and acquire a credential through the identity and credential loaders", async () => {
    const distribution = payload(["identity.mjs", "credential.mjs"], url);
    const manifest = parseManifest({
      schema: PISHIP_SCHEMA_V1ALPHA2,
      app: {
        id: "acmecode",
        name: "AcmeCode",
        command: "acme",
        version: "1.0.0",
      },
      runtime: { pi: "1.0.3" },
      deployment: { mode: "personal" },
      identity: { mode: "adapter", adapter: "./adapters/identity.mjs" },
      credential: { provider: "adapter", adapter: "./adapters/credential.mjs" },
      inference: { provider: "openai-compatible", baseUrl: `${url}/v1` },
      models: {
        allowed: ["acme/coder"],
        catalog: {
          "acme/coder": {
            name: "Coder",
            contextWindow: 32000,
            maxOutputTokens: 2048,
          },
        },
      },
    });
    const access = DistributionAccess.open({
      app: manifest.app,
      mode: "personal",
      access: manifest.access as AccessManifest,
      stateDir: join(root, "state"),
      distributionDir: distribution,
      env: {},
      secretStore: new MemorySecretStore(),
    });
    const opened: string[] = [];
    const result = await access.login({
      openUrl: (value) => {
        opened.push(value);
      },
    });
    expect(opened).toEqual([`${url}/verify`]);
    expect(result.identity).toMatchObject({
      subject: "user-1",
      issuer: url,
      displayName: "Ada",
    });
    // The identity loader re-wraps the adapter's secrets.
    expect(result.identity?.accessToken).toBeInstanceOf(SecretValue);
    expect(inspect(result, { depth: 10 })).not.toContain("sk-example");
    expect(inspect(result, { depth: 10 })).not.toContain("identity-access");
    const acquire = seen.find((item) => item.path === "/credentials");
    expect(acquire?.authorization).toBe("Bearer identity-access-token-1");
    expect(result.credential).toMatchObject({
      state: "valid",
      metadata: { mode: "adapter", credential_id: "cred-1" },
    });

    expect(await access.logout()).toEqual([]);
    expect(
      seen.find((item) => item.path === "/credentials/cred-1"),
    ).toMatchObject({
      method: "DELETE",
      authorization: "Bearer sk-example-runtime-key",
    });
    expect(seen.find((item) => item.path === "/revoke")?.body).toEqual({
      refreshToken: "identity-refresh-token-1",
    });
  });

  it("runs the sandbox check through the custom sandbox loader", async () => {
    const distribution = payload(["sandbox.mjs"]);
    const workspace = join(root, "workspace");
    const home = join(root, "home");
    // The distribution source: the lock resolves the adapter next to the
    // manifest; a build copies it into the payload's resources.
    const source = join(root, "source");
    for (const path of [workspace, home, join(source, "adapters")])
      mkdirSync(path, { recursive: true });
    copyFileSync(
      join(EXAMPLES, "sandbox.mjs"),
      join(source, "adapters", "sandbox.mjs"),
    );
    writeFileSync(
      join(source, "piship.yaml"),
      [
        "schema: piship/v1alpha3",
        "app: { id: acmecode, name: AcmeCode, command: acme, version: 0.1.0 }",
        'runtime: { pi: "1.0.3" }',
        "deployment: { mode: personal }",
        "sandbox:",
        "  required: true",
        "  provider: custom",
        "  adapter: ./adapters/sandbox.mjs",
        `  endpoint: ${url}/sandbox`,
        "  network: { mode: deny }",
        "  environment: { allow: [PATH] }",
        "",
      ].join("\n"),
    );
    const lock = resolveLock(join(source, "piship.yaml"));
    const inspection = await inspectGovernance({
      lock: lock as Parameters<typeof inspectGovernance>[0]["lock"],
      distributionDir: distribution,
      stateDir: join(root, "state"),
      cwd: workspace,
      piVersion: "1.0.3",
      interactive: false,
      fetch: createManagedFetch({
        ...DEFAULT_NETWORK_POLICY,
        inheritProxyEnvironment: false,
      }),
      resolveTemplate: (_key, template) => template,
      homeDir: home,
    });
    expect(inspection.sandbox).toMatchObject({
      level: "enforced",
      adapter: "example-remote",
      provider: "custom",
      verification: "backend-attested",
      // The example lists only deny and declares no network probe: its
      // denial is the service's word, and no allow-mode session is created.
      networkDenial: { evidence: "attested", probe: false },
    });
    expect(seen.map((item) => `${item.method} ${item.path}`)).toEqual([
      "GET /sandbox/health",
      "POST /sandbox/sessions",
      "POST /sandbox/sessions/session-1/exec",
      "DELETE /sandbox/sessions/session-1",
    ]);
    expect(seen[1]?.body).toEqual({ network: "deny" });
  });

  it("stores the batches the built-in HTTP audit sink delivers, once each", async () => {
    const distribution = payload(["audit-sink.mjs"]);
    const module = join(
      distribution,
      "resources",
      "adapters",
      "audit-sink.mjs",
    );
    collector = (
      (await import(pathToFileURL(module).href)) as { default: AuditSink }
    ).default;
    const log = await AuditLog.open({
      config: {
        enabled: true,
        sinks: [
          {
            id: "collector",
            type: "http",
            url: `${url}/collect`,
            required: true,
          },
        ],
        buffer: { maxEvents: 100, flushIntervalMs: 0 },
        capture: NO_CONTENT_CAPTURE,
      },
      distribution: "acmecode",
      stateDir: join(root, "state"),
      fetch: createManagedFetch({
        ...DEFAULT_NETWORK_POLICY,
        inheritProxyEnvironment: false,
      }),
    });
    log.emit({ event: "session.start", user: "user-1", session: "s1" });
    log.emit({
      event: "tool.denied",
      user: "user-1",
      session: "s1",
      resource: "bash",
    });
    await log.flush();
    const status = await log.close();
    expect(status.state).toBe("ok");
    const file = join(
      distribution,
      "resources",
      "adapters",
      "audit-events.jsonl",
    );
    const events = readFileSync(file, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { id: string; event: string });
    expect(events.map((event) => event.event)).toEqual([
      "session.start",
      "tool.denied",
    ]);
    // A resent batch is stored once.
    await collector.write(
      { schema: "piship-audit-batch/v1", events: events as never },
      AbortSignal.timeout(5000),
    );
    expect(readFileSync(file, "utf8").trim().split("\n")).toHaveLength(2);
    await expect(
      collector.write({ events: [] } as never, AbortSignal.timeout(5000)),
    ).rejects.toThrow("piship-audit-batch/v1");
  });
});
