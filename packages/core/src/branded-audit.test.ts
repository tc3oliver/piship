// Audit of the branded commands that run outside a governed session: login,
// logout, credential changes, update, and rollback. Events come from the real
// DistributionAccess flows against the deterministic fixture services and
// from the real emitting functions, written through real sinks.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditConfig } from "@piship/audit";
import type { AuditEvent } from "@piship/contracts";
import { MemorySecretStore } from "@piship/credentials";
import type { AccessManifest, Manifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { type AccessEvent, DistributionAccess } from "./access/index.js";
import { auditAccess, type BrandedContext } from "./branded/context.js";
import { auditLifecycle } from "./branded/lifecycle.js";
import { resolveLock } from "./index.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);

/** The events this file proves; the governance session emits the rest. */
const BRANDED_EVENTS = [
  "identity.login",
  "identity.refresh",
  "identity.logout",
  "credential.acquire",
  "credential.refresh",
  "credential.revoke",
  "runtime.update",
  "runtime.rollback",
] as const;

interface Collector {
  url: string;
  batches: { schema: string; events: AuditEvent[] }[];
  /** Status for requests after the readiness probe. */
  status: number;
  close(): Promise<void>;
}

async function startCollector(): Promise<Collector> {
  const collector = {
    url: "",
    batches: [] as Collector["batches"],
    status: 200,
    close: async () => {},
  };
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const batch = JSON.parse(Buffer.concat(chunks).toString());
      const status = batch.events.length ? collector.status : 200;
      if (status < 300) collector.batches.push(batch);
      response.statusCode = status;
      response.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  collector.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/ingest?route=audit`;
  collector.close = () =>
    new Promise<void>((resolve) => server.close(() => resolve()));
  return collector;
}

let temp: string;
let services: Awaited<ReturnType<typeof startLocalServices>>;
let collector: Collector;
beforeEach(async () => {
  temp = mkdtempSync(join(tmpdir(), "piship-branded-audit-"));
  services = await startLocalServices();
  collector = await startCollector();
});
afterEach(async () => {
  await collector.close();
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

function context(audit: Partial<AuditConfig["sinks"][number]>[]) {
  const lock = resolveLock(DEMO);
  const governance = lock.governance as NonNullable<typeof lock.governance>;
  const errors: string[] = [];
  const ctx: BrandedContext = {
    metadata: {
      ...lock,
      governance: {
        ...governance,
        manifest: {
          ...governance.manifest,
          audit: {
            ...governance.manifest.audit,
            enabled: true,
            sinks: audit as AuditConfig["sinks"],
          },
        },
      },
    },
    distributionDir: temp,
    stateDir: join(temp, "state"),
    mode: "managed",
    out: () => {},
    err: (message) => errors.push(message),
    // A required sink that keeps failing is reported after this, not after 5 s.
    auditCloseDeadlineMs: 300,
  };
  return { ctx, errors };
}

function accessOptions(
  events: AccessEvent[],
): Parameters<typeof DistributionAccess.open>[0] {
  const demo = resolveLock(DEMO);
  const access = demo.access as AccessManifest;
  return {
    app: demo.app as Manifest["app"],
    mode: "managed",
    access: {
      ...access,
      identity: {
        ...access.identity,
        oidc: {
          ...(access.identity as { oidc: object }).oidc,
          redirectUri: "http://127.0.0.1/callback",
        },
      },
    } as AccessManifest,
    stateDir: join(temp, "state"),
    distributionDir: temp,
    env: services.env(),
    secretStore: new MemorySecretStore(),
    onEvent: (event) => events.push(event),
  };
}

const sinks = (url: string, required: boolean) => [
  { id: "local", type: "file" as const, required: false },
  { id: "company", type: "http" as const, url, required },
];

describe("branded command audit (real flows)", () => {
  it("records every identity, credential, and runtime event through real sinks without secrets", async () => {
    const { ctx, errors } = context(sinks(collector.url, true));
    const events: AccessEvent[] = [];
    const options = accessOptions(events);
    // Access tokens inside the refresh window, so the next use refreshes.
    services.knobs.accessTokenTtl = 30;
    const access = DistributionAccess.open(options);
    const record = async (user: string | null) => {
      await auditAccess(ctx, access, user, events.splice(0));
    };
    await access.login({ openUrl: (url) => void services.approve(url) });
    await record("demo-user-1");
    // A second login replaces (revokes) the first credential.
    await access.login({ openUrl: (url) => void services.approve(url) });
    await record("demo-user-1");
    await DistributionAccess.open(options).currentIdentity({ required: true });
    await record("demo-user-1");
    // The gateway rejects the credential: it is renewed.
    for (const entry of services.state.credentials.values())
      entry.revoked = true;
    await DistributionAccess.open(options).requestSecret({ force: true });
    await record("demo-user-1");
    await access.logout();
    await record("demo-user-1");
    await auditLifecycle(ctx, "runtime.update", "allowed", {
      from: "1.0.0",
      to: "1.1.0",
      channel: "stable",
      key: "acme",
    });
    await auditLifecycle(ctx, "runtime.rollback", "allowed", {
      from: "1.1.0",
      to: "1.0.0",
    });
    expect(errors).toEqual([]);

    const delivered = collector.batches.flatMap((batch) => batch.events);
    const local = readFileSync(
      join(ctx.stateDir, "logs", "audit.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);
    for (const received of [delivered, local]) {
      expect(new Set(received.map((event) => event.event))).toEqual(
        new Set(BRANDED_EVENTS),
      );
      expect(new Set(received.map((event) => event.id)).size).toBe(
        received.length,
      );
    }
    // Both sinks got the same events, with the same ids.
    expect(local.map((event) => event.id)).toEqual(
      delivered.map((event) => event.id),
    );
    expect(delivered.find((event) => event.event === "identity.login")).toEqual(
      expect.objectContaining({ user: "demo-user-1", session: null }),
    );
    // No token, credential, or refresh token value reaches either sink.
    const secrets = [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    ];
    expect(secrets.length).toBeGreaterThan(3);
    const text = `${JSON.stringify(collector.batches)}\n${JSON.stringify(local)}`;
    for (const secret of secrets) expect(text).not.toContain(secret);
  });
});

describe("branded command audit with a required sink", () => {
  const signIn = async (ctx: BrandedContext) => {
    const events: AccessEvent[] = [];
    const access = DistributionAccess.open(accessOptions(events));
    await access.login({ openUrl: (url) => void services.approve(url) });
    return () => auditAccess(ctx, access, "demo-user-1", events);
  };

  it("fails the command when the required sink is unreachable", async () => {
    await collector.close();
    const { ctx, errors } = context(sinks(collector.url, true));
    const record = await signIn(ctx);
    const error = await record().then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({
      code: "AUDIT_UNAVAILABLE",
      message: expect.stringMatching(
        /^The operation completed, but its audit was not recorded: Required audit sink company \(http\) is unavailable/,
      ),
    });
    // The collector's path and query are never echoed.
    expect(JSON.stringify(error)).not.toContain("route=audit");
    expect(errors).toEqual([]);
    await expect(
      auditLifecycle(ctx, "runtime.update", "allowed", { from: "1.0.0" }),
    ).rejects.toMatchObject({ code: "AUDIT_UNAVAILABLE" });
  });

  it("fails the command when the required sink does not take the events", async () => {
    const { ctx } = context(sinks(collector.url, true));
    const record = await signIn(ctx);
    // Fault injection: the probe succeeds, every delivery fails.
    collector.status = 503;
    await expect(record()).rejects.toMatchObject({
      code: "AUDIT_UNAVAILABLE",
      message: expect.stringContaining(
        "2 audit event(s) were not delivered to required audit sink company (2 pending, 0 dropped; last error: collector answered HTTP 503)",
      ),
    });
    // The optional file sink still recorded them.
    expect(
      readFileSync(join(ctx.stateDir, "logs", "audit.jsonl"), "utf8"),
    ).toContain('"event":"identity.login"');
  }, 15_000);

  it("stays best effort with only optional sinks", async () => {
    await collector.close();
    const { ctx, errors } = context(sinks(collector.url, false));
    const record = await signIn(ctx);
    await expect(record()).resolves.toBeUndefined();
    await expect(
      auditLifecycle(ctx, "runtime.rollback", "denied", { code: "X" }),
    ).resolves.toBeUndefined();
    expect(errors).toEqual([]);
    // A configuration the audit log refuses is a warning without a
    // required sink.
    const broken = context([
      { id: "local", type: "file", required: false },
      { id: "local", type: "file", required: false },
    ]);
    await auditLifecycle(broken.ctx, "runtime.update", "allowed", {});
    expect(broken.errors).toEqual([
      expect.stringMatching(
        /^Warning: audit events were not recorded: CONFIG_INVALID: Duplicate audit sink id local/,
      ),
    ]);
  });
});
