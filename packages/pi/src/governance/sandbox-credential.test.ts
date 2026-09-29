// The sandbox credential sources as the governed session builds a backend:
// `stored` (sandbox login) and a custom adapter's own `sandboxCredential`.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  IdentitySession,
  PrincipalKey,
  SecretStore,
  SecretValue,
} from "@piship/contracts";
import { type AccessEvent, openSandboxCredential } from "@piship/core";
import type { SandboxBackend } from "@piship/sandbox";
import type { SandboxConfig } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GovernanceOptions } from "./options.js";
import { sandboxBackend } from "./sandbox.js";

const SECRET = "fake-sandbox-key-SENTINEL-0001";
const ALICE: PrincipalKey = {
  issuer: "https://idp.test.invalid",
  subject: "alice",
};

/** A secret store double that records every read of a secret it holds. */
class Store implements SecretStore {
  readonly kind = "memory";
  readonly description = "test store";
  readonly values = new Map<string, SecretValue>();
  readonly reads: string[] = [];
  async put(ref: string, value: SecretValue) {
    this.values.set(ref, value);
  }
  async get(ref: string) {
    const value = this.values.get(ref) ?? null;
    if (value) this.reads.push(ref);
    return value;
  }
  async delete(ref: string) {
    this.values.delete(ref);
  }
}

let root: string;
let store: Store;
let variables: Record<string, string>;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "piship-sandbox-credential-pi-"));
  store = new Store();
  variables = {
    ACME_SANDBOX_URL: "https://sandbox-api.test.invalid",
    ACME_ROUTER_URL: "https://sandbox-router.test.invalid",
  };
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const stateDir = () => join(root, "state");
const base: SandboxConfig = {
  required: true,
  filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: { allow: ["PATH"] },
};

interface Sent {
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
  readonly body: string;
}

/** A fetch double for the E2B and Kubernetes APIs that records every request. */
function recorder(
  answer: (sent: Sent) => Response | undefined = () => undefined,
) {
  const sent: Sent[] = [];
  const fetch = async (url: string | URL, init: RequestInit = {}) => {
    const request: Sent = {
      url: String(url),
      method: init.method ?? "GET",
      headers: new Headers(init.headers),
      body: typeof init.body === "string" ? init.body : String(init.body ?? ""),
    };
    sent.push(request);
    const custom = answer(request);
    if (custom) return custom;
    const path = new URL(url).pathname;
    if (request.method === "POST" && path.endsWith("/sandboxes"))
      return Response.json({ sandboxID: "sbx1", envdAccessToken: "envd-1" });
    if (path.endsWith("/sandboxclaims") && request.method === "POST")
      return new Response(null, { status: 201 });
    if (path.includes("/sandboxclaims/"))
      return Response.json({
        status: { conditions: [{ type: "Ready", status: "True" }] },
      });
    return new Response(null, { status: 204 });
  };
  return { sent, fetch };
}

function options(
  sandbox: Partial<SandboxConfig>,
  extra: Partial<GovernanceOptions> = {},
): GovernanceOptions {
  return {
    lock: {
      app: { id: "acmecode", command: "acme" },
      governance: { manifest: { sandbox: { ...base, ...sandbox } } },
    },
    distributionDir: root,
    stateDir: stateDir(),
    fetch: async () => new Response(null, { status: 204 }),
    resolveTemplate: (_key: string, template: string) =>
      template.replace(/\$\{([A-Z_]+)\}/g, (_match, name: string) => {
        const value = variables[name];
        if (value === undefined)
          throw new Error(`Runtime variable ${name} is not set`);
        return value;
      }),
    ...extra,
  } as unknown as GovernanceOptions;
}

/** What launch passes for `stored`: the principal's credential in `store`. */
function stored(
  principal: PrincipalKey | null,
  provider: "e2b-compatible" | "kubernetes-agent-sandbox" = "e2b-compatible",
): Pick<GovernanceOptions, "sandboxCredential"> {
  return {
    sandboxCredential: (targets) =>
      openSandboxCredential({
        distributionId: "acmecode",
        command: "acme",
        stateDir: stateDir(),
        provider,
        secretStore: store,
        principal,
        targets,
      }).access(),
  };
}

async function save(
  targets: readonly string[],
  provider: "e2b-compatible" | "kubernetes-agent-sandbox" = "e2b-compatible",
) {
  await openSandboxCredential({
    distributionId: "acmecode",
    command: "acme",
    stateDir: stateDir(),
    provider,
    secretStore: store,
    principal: ALICE,
    targets,
  }).save(async () => SECRET);
}

const io = () => ({
  signal: new AbortController().signal,
  onStdout: () => {},
  onStderr: () => {},
});
const request = { command: "true", cwd: "/w", workspacePath: ".", env: {} };

async function run(backend: SandboxBackend | undefined) {
  const instance = await backend?.prepare({
    profile: { network: "deny" } as never,
  });
  await instance?.exec(request, io()).catch(() => undefined);
  await instance?.dispose();
}

/** Every place of a request, other than the one allowed header, holding `value`. */
function leaks(sent: readonly Sent[], value: string, allowed: string[]) {
  const hits: string[] = [];
  for (const item of sent) {
    if (item.url.includes(value)) hits.push(`${item.url} url`);
    if (item.body.includes(value)) hits.push(`${item.url} body`);
    for (const [name, header] of item.headers)
      if (header.includes(value) && !allowed.includes(name))
        hits.push(`${item.url} ${name}`);
  }
  return hits;
}

describe("sandbox.credential: stored", () => {
  const e2b = {
    provider: "e2b-compatible" as const,
    endpoint: `\${ACME_SANDBOX_URL}`,
    credential: "stored" as const,
  };

  it("sends the stored key as X-API-Key to the control plane only, never to envd, a body, or a query", async () => {
    await save(["https://sandbox-api.test.invalid"]);
    const { sent, fetch } = recorder();
    await run(
      await sandboxBackend(
        options(e2b, { fetch, ...stored(ALICE) } as Partial<GovernanceOptions>),
      ),
    );
    const control = sent.filter((item) =>
      item.url.startsWith("https://sandbox-api.test.invalid/sandboxes"),
    );
    expect(control.length).toBeGreaterThanOrEqual(3);
    for (const item of control)
      expect(item.headers.get("x-api-key")).toBe(SECRET);
    const envd = sent.filter((item) => item.url.includes("49983-sbx1"));
    expect(envd.length).toBeGreaterThan(0);
    for (const item of envd) expect(item.headers.get("x-api-key")).toBeNull();
    expect(leaks(sent, SECRET, ["x-api-key"])).toEqual([]);
    expect(
      sent
        .filter((item) => item.headers.get("x-api-key"))
        .every((item) =>
          item.url.startsWith("https://sandbox-api.test.invalid/"),
        ),
    ).toBe(true);
  });

  it("fails closed, reading no secret, when the endpoint variable points elsewhere", async () => {
    await save(["https://sandbox-api.test.invalid"]);
    variables.ACME_SANDBOX_URL = "https://attacker.test.invalid";
    const { sent, fetch } = recorder();
    await expect(
      sandboxBackend(
        options(e2b, { fetch, ...stored(ALICE) } as Partial<GovernanceOptions>),
      ),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(store.reads).toEqual([]);
    expect(sent).toEqual([]);
  });

  it("fails closed without a principal to check it against", async () => {
    await save(["https://sandbox-api.test.invalid"]);
    await expect(sandboxBackend(options(e2b))).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    expect(store.reads).toEqual([]);
  });

  it("sends a Kubernetes bearer only to the endpoint and the router it was stored for", async () => {
    const k8s = {
      provider: "kubernetes-agent-sandbox" as const,
      endpoint: "https://k8s-api.test.invalid",
      router: `\${ACME_ROUTER_URL}`,
      template: "pool",
      credential: "stored" as const,
    };
    await save(
      ["https://k8s-api.test.invalid", "https://sandbox-router.test.invalid"],
      "kubernetes-agent-sandbox",
    );
    const { sent, fetch } = recorder();
    await run(
      await sandboxBackend(
        options(k8s, {
          fetch,
          ...stored(ALICE, "kubernetes-agent-sandbox"),
        } as Partial<GovernanceOptions>),
      ),
    );
    expect(sent.some((item) => item.url.includes("sandbox-router"))).toBe(true);
    for (const item of sent)
      expect(item.headers.get("authorization")).toBe(`Bearer ${SECRET}`);
    expect(leaks(sent, SECRET, ["authorization"])).toEqual([]);
    // A router it was not stored for is refused before anything is sent.
    variables.ACME_ROUTER_URL = "https://other-router.test.invalid";
    const second = recorder();
    store.reads.length = 0;
    await expect(
      sandboxBackend(
        options(k8s, {
          fetch: second.fetch,
          ...stored(ALICE, "kubernetes-agent-sandbox"),
        } as Partial<GovernanceOptions>),
      ),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(store.reads).toEqual([]);
    expect(second.sent).toEqual([]);
  });

  it("marks a 401 as rejected, never repeats the create, and keeps the secret out of the error", async () => {
    await save(["https://sandbox-api.test.invalid"]);
    const { sent, fetch } = recorder((item) =>
      item.method === "POST" && item.url.endsWith("/sandboxes")
        ? new Response(
            JSON.stringify({
              message: `invalid api key ${item.headers.get("x-api-key")}`,
            }),
            { status: 401 },
          )
        : undefined,
    );
    const backend = await sandboxBackend(
      options(e2b, { fetch, ...stored(ALICE) } as Partial<GovernanceOptions>),
    );
    const error = await backend
      ?.prepare({ profile: { network: "deny" } as never })
      .catch((caught: Error) => caught);
    expect(String((error as Error).message)).toMatch(/HTTP 401/);
    expect(String((error as Error).message)).not.toContain(SECRET);
    expect(
      sent.filter(
        (item) => item.method === "POST" && item.url.endsWith("/sandboxes"),
      ),
    ).toHaveLength(1);
    const metadata = JSON.parse(
      readFileSync(
        join(stateDir(), "credentials-metadata", "sandbox.json"),
        "utf8",
      ),
    ) as { rejected_at?: string };
    expect(typeof metadata.rejected_at).toBe("string");
    // The next launch asks for a new one instead of sending it again.
    await expect(
      sandboxBackend(
        options(e2b, { fetch, ...stored(ALICE) } as Partial<GovernanceOptions>),
      ),
    ).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      userAction: expect.stringMatching(/acme sandbox login/),
    });
  });

  it("discards another user's stored credential at launch", async () => {
    await save(["https://sandbox-api.test.invalid"]);
    await expect(
      sandboxBackend(
        options(e2b, {
          ...stored({ issuer: ALICE.issuer, subject: "bob" }),
        } as Partial<GovernanceOptions>),
      ),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(store.values.size).toBe(0);
    expect(
      existsSync(join(stateDir(), "credentials-metadata", "sandbox.json")),
    ).toBe(false);
  });
});

// ---------------------------------------------------- custom adapter source

/** A custom adapter module that records what PiShip gives it. */
function writeAdapter(options: { readonly expiresInMs: number }): void {
  mkdirSync(join(root, "resources", "sandbox"), { recursive: true });
  writeFileSync(
    join(root, "resources", "sandbox", "adapter.mjs"),
    `
const log = (globalThis.__sandboxAdapterLog ??= { acquired: [], refreshed: 0, revoked: [], context: null });
let issued = 0;
const next = () => ({
  kind: "bearer",
  secret: "fake-adapter-token-" + ++issued,
  expiresAt: new Date(Date.now() + ${options.expiresInMs}),
});
export const sandboxCredential = {
  mode: "adapter",
  requiresIdentity: false,
  async acquire(identity) {
    log.acquired.push(identity ? identity.subject : null);
    return next();
  },
  async refresh(identity) {
    log.refreshed++;
    return next();
  },
  async revoke(credential) {
    log.revoked.push(credential.secret.reveal());
  },
};
export default async function factory(context) {
  log.context = context;
  return {
    id: "acme-remote",
    async available() { return { available: true }; },
    capabilities() {
      return { isolation: "remote", planes: ["host-filesystem-isolation", "network-deny", "environment-filter"], network: ["deny"], localProcesses: false };
    },
    async prepare() {
      return { async exec() { return { exitCode: 0 }; }, async dispose() {} };
    },
  };
}
`,
  );
}

interface AdapterLog {
  acquired: (string | null)[];
  refreshed: number;
  revoked: string[];
  context: {
    credential?: () => Promise<string | undefined>;
    credentialRejected?: () => Promise<boolean>;
    credentialOrigins?: readonly string[];
    endpoint?: string;
  } | null;
}
const adapterLog = () =>
  (globalThis as unknown as { __sandboxAdapterLog: AdapterLog })
    .__sandboxAdapterLog;

describe("a custom adapter's own sandboxCredential", () => {
  const custom = {
    provider: "custom" as const,
    adapter: "./sandbox/adapter.mjs",
    endpoint: `\${ACME_SANDBOX_URL}`,
  };
  const identity = (subject = "alice"): IdentitySession => ({
    issuer: ALICE.issuer,
    subject,
  });
  beforeEach(() => {
    delete (globalThis as { __sandboxAdapterLog?: unknown })
      .__sandboxAdapterLog;
  });

  it("is acquired per launch for the launch's identity, in memory only, and revoked at the end", async () => {
    writeAdapter({ expiresInMs: 3_600_000 });
    const events: AccessEvent[] = [];
    let current = identity();
    const backend = await sandboxBackend(
      options(custom, {
        sandboxIdentity: { principal: ALICE, current: async () => current },
        onSandboxCredentialEvent: (event) => events.push(event),
      } as Partial<GovernanceOptions>),
    );
    const log = adapterLog();
    expect(log.acquired).toEqual(["alice"]);
    expect(log.context?.credentialOrigins).toEqual([
      "https://sandbox-api.test.invalid",
    ]);
    expect(await log.context?.credential?.()).toBe("fake-adapter-token-1");
    expect(await log.context?.credential?.()).toBe("fake-adapter-token-1");
    expect(log.refreshed).toBe(0);
    // A rejection renews once and allows one retry.
    expect(await log.context?.credentialRejected?.()).toBe(true);
    expect(log.refreshed).toBe(1);
    expect(await log.context?.credential?.()).toBe("fake-adapter-token-2");
    // Nothing reached the state directory.
    expect(existsSync(stateDir())).toBe(false);
    // Another principal under the session is refused.
    current = identity("bob");
    await expect(log.context?.credential?.()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    current = identity();
    await run(backend);
    expect(log.revoked).toEqual(["fake-adapter-token-2"]);
    await expect(log.context?.credential?.()).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    expect(events.map((event) => event.event)).toEqual([
      "credential.acquire",
      "credential.refresh",
      "credential.revoke",
    ]);
    expect(events[0]?.detail).toMatchObject({
      purpose: "sandbox",
      source: "adapter",
      kind: "bearer",
    });
    expect(JSON.stringify(events)).not.toContain("fake-adapter-token");
  });

  it("is renewed in memory before it expires", async () => {
    writeAdapter({ expiresInMs: 30_000 });
    await sandboxBackend(options(custom));
    const log = adapterLog();
    expect(log.acquired).toEqual([null]);
    expect(await log.context?.credential?.()).toBe("fake-adapter-token-2");
    expect(log.refreshed).toBe(1);
  });

  it.each(["runtime", "stored"] as const)(
    "fails closed when the manifest also declares credential: %s",
    async (credential) => {
      writeAdapter({ expiresInMs: 3_600_000 });
      // A usable stored credential, so only the double declaration fails.
      await save(["https://sandbox-api.test.invalid"]);
      await expect(
        sandboxBackend(
          options({ ...custom, credential }, {
            credential: async () => "fake-runtime",
            credentialOrigins: ["https://sandbox-api.test.invalid"],
            ...stored(ALICE),
          } as Partial<GovernanceOptions>),
        ),
      ).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringMatching(/exports sandboxCredential/),
      });
      expect(adapterLog()?.context ?? null).toBeNull();
    },
  );
});
