// The service kits must pass a broker and a collector that follow the
// contract and fail one seeded with a single defect. The services below are
// in-memory fakes reached through the kit's `fetch` option, as a company's
// staging broker or collector would be reached over the network.
import { describe, expect, it } from "vitest";
import {
  AUDIT_COLLECTOR_BEHAVIORS,
  type AuditCollectorBehavior,
  CREDENTIAL_BROKER_BEHAVIORS,
  type CredentialBrokerBehavior,
  testAuditCollector,
  testCredentialBroker,
} from "./services.js";

const TOKEN = "identity-access-token-for-conformance";
const BROKER = "https://broker.example.test/v1/credentials";
const REVOKE = "https://broker.example.test/v1/revoke";
const COLLECTOR = "https://audit.example.test/v1/batches";

type Fetch = typeof globalThis.fetch;

interface BrokerDefects {
  readonly ignoresKey?: boolean;
  readonly replaysOnConflict?: boolean;
  readonly acceptsAnyToken?: boolean;
  readonly redirects?: boolean;
  readonly badCredentialId?: boolean;
  readonly revokeFails?: boolean;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A broker that follows the contract, except for the seeded defects. */
function broker(defects: BrokerDefects = {}): {
  fetch: Fetch;
  revoked: string[];
} {
  const issued = new Map<string, { body: string; answer: unknown }>();
  const revoked: string[] = [];
  let next = 0;
  const fetch: Fetch = async (input, init) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    const body = String(init?.body ?? "");
    if (defects.redirects)
      return new Response(null, {
        status: 307,
        headers: { location: "https://elsewhere.example.test/" },
      });
    if (url === REVOKE) {
      const { credential_id } = JSON.parse(body) as { credential_id: string };
      revoked.push(credential_id);
      return defects.revokeFails ? json(500, {}) : json(200, {});
    }
    if (
      !defects.acceptsAnyToken &&
      headers.get("authorization") !== `Bearer ${TOKEN}`
    )
      return json(401, { error: "unauthorized" });
    const key = headers.get("idempotency-key") ?? "";
    const stored = defects.ignoresKey ? undefined : issued.get(key);
    if (stored && stored.body !== body)
      return defects.replaysOnConflict
        ? json(200, stored.answer)
        : json(409, { error: "idempotency_key_reused" });
    if (stored) return json(200, stored.answer);
    next += 1;
    const answer = {
      credential_type: "api_key",
      credential: `sk-conformance-${next}-${"x".repeat(16)}`,
      credential_id: defects.badCredentialId ? "vk 1/2" : `vk_${next}`,
      expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      models: ["acme/coder"],
    };
    issued.set(key, { body, answer });
    return json(200, answer);
  };
  return { fetch, revoked };
}

function brokerStatuses(
  results: readonly { behavior: string; status: string }[],
): Record<CredentialBrokerBehavior, string> {
  return Object.fromEntries(
    results.map((result) => [result.behavior, result.status]),
  ) as Record<CredentialBrokerBehavior, string>;
}

describe("testCredentialBroker", () => {
  const options = (fetch: Fetch, revokeEndpoint: string | null = REVOKE) => ({
    endpoint: BROKER,
    revokeEndpoint: revokeEndpoint ?? undefined,
    distribution: "acmecode",
    identityToken: () => TOKEN,
    fetch,
  });

  it("passes a broker that follows the contract, and revokes what it issued", async () => {
    const service = broker();
    const report = await testCredentialBroker(options(service.fetch));
    expect(report.kind).toBe("credential");
    expect(report.results.map((result) => result.behavior)).toEqual([
      ...CREDENTIAL_BROKER_BEHAVIORS,
    ]);
    expect(report.results.filter((r) => r.status !== "passed")).toEqual([]);
    expect(service.revoked).toEqual(["vk_1"]);
  });

  it("skips revoke without a revoke endpoint", async () => {
    const report = await testCredentialBroker(options(broker().fetch, null));
    expect(brokerStatuses(report.results).revoke).toBe("skipped");
  });

  it.each([
    [{ ignoresKey: true }, "idempotent replay"],
    [{ replaysOnConflict: true }, "key reuse"],
    [{ acceptsAnyToken: true }, "authentication"],
    [{ badCredentialId: true }, "acquire"],
    [{ revokeFails: true }, "revoke"],
  ] as const)(
    "fails a broker with the defect %o at %s",
    async (defects, behavior) => {
      const report = await testCredentialBroker(options(broker(defects).fetch));
      expect(brokerStatuses(report.results)[behavior]).toBe("failed");
    },
  );

  it("fails every behavior of a broker that redirects, without following it", async () => {
    const report = await testCredentialBroker(
      options(broker({ redirects: true }).fetch),
    );
    expect(brokerStatuses(report.results).acquire).toBe("failed");
  });

  it("never puts the issued credential or the identity token in a reason", async () => {
    const report = await testCredentialBroker(
      options(broker({ replaysOnConflict: true }).fetch),
    );
    const text = JSON.stringify(report);
    expect(text).not.toContain("sk-conformance");
    expect(text).not.toContain(TOKEN);
  });
});

interface CollectorDefects {
  readonly rejectsDuplicates?: boolean;
  readonly storesTwice?: boolean;
  readonly rejectsUnknownProperty?: boolean;
  readonly rejectsEmpty?: boolean;
  readonly rejectsConflict?: boolean;
}

/** A collector that follows the contract, except for the seeded defects. */
function collector(defects: CollectorDefects = {}): {
  fetch: Fetch;
  stored: (id: string) => Promise<readonly unknown[]>;
} {
  const events: { id: string; text: string }[] = [];
  const fetch: Fetch = async (_input, init) => {
    const batch = JSON.parse(String(init?.body)) as {
      schema: string;
      events: ({ id: string } & Record<string, unknown>)[];
    };
    if (batch.schema !== "piship-audit-batch/v1") return json(400, {});
    if (batch.events.length === 0 && defects.rejectsEmpty) return json(503, {});
    for (const event of batch.events) {
      if (defects.rejectsUnknownProperty && "conformanceExtension" in event)
        return json(400, {});
      const text = JSON.stringify(event);
      const same = events.filter((stored) => stored.id === event.id);
      if (same.length > 0 && defects.rejectsDuplicates) return json(409, {});
      if (
        same.some((stored) => stored.text !== text) &&
        defects.rejectsConflict
      )
        return json(409, {});
      if (
        defects.storesTwice ||
        same.length === 0 ||
        same.every((stored) => stored.text !== text)
      )
        events.push({ id: event.id, text });
    }
    return new Response(null, { status: 202 });
  };
  return {
    fetch,
    stored: async (id) => events.filter((event) => event.id === id),
  };
}

function collectorStatuses(
  results: readonly { behavior: string; status: string }[],
): Record<AuditCollectorBehavior, string> {
  return Object.fromEntries(
    results.map((result) => [result.behavior, result.status]),
  ) as Record<AuditCollectorBehavior, string>;
}

describe("testAuditCollector", () => {
  it("passes a collector that follows the contract", async () => {
    const service = collector();
    const report = await testAuditCollector({
      url: COLLECTOR,
      distribution: "acmecode",
      fetch: service.fetch,
      stored: service.stored,
    });
    expect(report.kind).toBe("audit-sink");
    expect(report.results.map((result) => result.behavior)).toEqual([
      ...AUDIT_COLLECTOR_BEHAVIORS,
    ]);
    expect(report.results.filter((r) => r.status !== "passed")).toEqual([]);
  });

  it("checks only the answers without a way to read what was stored", async () => {
    const report = await testAuditCollector({
      url: COLLECTOR,
      distribution: "acmecode",
      fetch: collector({ storesTwice: true }).fetch,
    });
    expect(report.results.filter((r) => r.status === "failed")).toEqual([]);
  });

  it.each([
    [{ rejectsEmpty: true }, "readiness probe"],
    [{ rejectsDuplicates: true }, "duplicate batch"],
    [{ storesTwice: true }, "duplicate batch"],
    [{ rejectsConflict: true }, "conflicting id"],
    [{ rejectsUnknownProperty: true }, "unknown property"],
  ] as const)(
    "fails a collector with the defect %o at %s",
    async (defects, behavior) => {
      const service = collector(defects);
      const report = await testAuditCollector({
        url: COLLECTOR,
        distribution: "acmecode",
        fetch: service.fetch,
        stored: service.stored,
      });
      expect(collectorStatuses(report.results)[behavior]).toBe("failed");
    },
  );
});
