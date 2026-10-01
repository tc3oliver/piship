import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type SecretStore, SecretValue } from "@piship/contracts";
import { MemorySecretStore } from "@piship/credentials";
import { identityMetadata, identitySecret } from "@piship/identity";
import {
  type AccessManifest,
  type Manifest,
  readManifest,
} from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { type AccessEvent, DistributionAccess } from "./access/index.js";
import { readPreferences, setPreference } from "./config.js";

// Headless and workload path: a managed distribution whose identity adapter
// declares `interactive: false` activates with no stored login and no
// browser, holds the workload session in memory only, and puts the workload
// principal through the same credential binding and no-residue rules as a
// person.

const demo = readManifest(
  fileURLToPath(
    new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
  ),
);
const access = demo.access as AccessManifest;

type Services = Awaited<ReturnType<typeof startLocalServices>>;

/** What the workload platform currently hands the adapter. */
interface WorkloadSource {
  issuer: string;
  subject: string;
  token: string;
  expiresAt?: string;
  openBrowser?: boolean;
  /** Call openUrl, catch its refusal, and return a session anyway. */
  swallowBrowser?: boolean;
  /** Never answer. */
  hang?: boolean;
  fail?: string;
  calls: number;
  openUrlSeen: number;
  /** Sessions handed to the adapter's logout (it must never get any). */
  logouts: number;
}

declare global {
  var __pishipWorkload: WorkloadSource | undefined;
}

const WORKLOAD_ADAPTER = `export default () => ({
  kind: "test-workload",
  interactive: false,
  async login(ctx) {
    const source = globalThis.__pishipWorkload;
    source.calls += 1;
    if (source.hang) await new Promise(() => {});
    if (source.fail) throw new Error(source.fail);
    if (source.openBrowser) {
      source.openUrlSeen += 1;
      await ctx.openUrl("https://idp.example/authorize");
    }
    if (source.swallowBrowser)
      try {
        await ctx.openUrl("https://idp.example/authorize");
      } catch {}
    await Promise.resolve();
    return {
      issuer: source.issuer,
      subject: source.subject,
      accessToken: source.token,
      ...(source.expiresAt ? { expiresAt: source.expiresAt } : {}),
      claims: { sub: source.subject, iss: source.issuer },
    };
  },
  async logout() {
    globalThis.__pishipWorkload.logouts += 1;
  },
});`;

let temp: string;
let services: Services;
let events: AccessEvent[];
let clock: number;
let minted = 0;

beforeEach(async () => {
  temp = mkdtempSync(join(tmpdir(), "piship-workload-"));
  services = await startLocalServices();
  events = [];
  clock = Date.now();
  mkdirSync(join(temp, "resources", "adapters"), { recursive: true });
  writeFileSync(
    join(temp, "resources", "adapters", "workload.mjs"),
    WORKLOAD_ADAPTER,
  );
  globalThis.__pishipWorkload = {
    issuer: "https://workload.example/",
    subject: "svc-build-1",
    token: mint("svc-build-1"),
    // A workload session must say when it expires.
    expiresAt: new Date(clock + 3600_000).toISOString(),
    calls: 0,
    openUrlSeen: 0,
    logouts: 0,
  };
});
afterEach(async () => {
  globalThis.__pishipWorkload = undefined;
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

const source = (): WorkloadSource => {
  const value = globalThis.__pishipWorkload;
  if (!value) throw new Error("no workload source");
  return value;
};

/**
 * Issue an access token the fixture broker accepts, the way a workload
 * platform issues one to a job. No authorization endpoint is involved.
 */
function mint(subject: string, ttlSeconds = 3600): string {
  minted += 1;
  const token = `demo-wt-${minted}-${Math.random().toString(36).slice(2)}`;
  services.state.accessTokens.set(token, {
    subject,
    expires: Math.floor(Date.now() / 1000) + ttlSeconds,
  });
  return token;
}

function workloadAs(subject: string, models: string[]): void {
  source().subject = subject;
  source().token = mint(subject);
  services.knobs.entitledModels = [...models];
}

const stateDir = () => join(temp, "state");

function open(
  store: SecretStore,
  identity: AccessManifest["identity"] = {
    mode: "adapter",
    adapter: "./adapters/workload.mjs",
  },
): DistributionAccess {
  return DistributionAccess.open({
    app: demo.app as Manifest["app"],
    mode: "managed",
    access: { ...access, identity } as AccessManifest,
    stateDir: stateDir(),
    distributionDir: temp,
    env: services.env(),
    secretStore: store,
    now: () => clock,
    onEvent: (event) => events.push(event),
  });
}

const identityRequests = () =>
  services.state.requests.filter((item: { path: string }) =>
    item.path.startsWith("/idp/"),
  );
const brokerRequests = () =>
  services.state.requests.filter(
    (item: { path: string }) => item.path === "/broker/v1/llm-credential",
  );
const credentialFile = () =>
  join(stateDir(), "credentials-metadata", "inference.json");

/** Every sentinel found in the state directory or the secret store. */
async function residue(
  store: MemorySecretStore,
  sentinels: readonly string[],
): Promise<string[]> {
  const hits: string[] = [];
  const visit = (directory: string) => {
    if (!existsSync(directory)) return;
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      if (statSync(path).isDirectory()) visit(path);
      else {
        const text = readFileSync(path, "utf8");
        for (const sentinel of sentinels)
          if (text.includes(sentinel)) hits.push(`${path}: ${sentinel}`);
      }
    }
  };
  visit(stateDir());
  for (const ref of store.refs()) {
    const text = (await store.get(ref))?.reveal() ?? "";
    for (const sentinel of sentinels)
      if (text.includes(sentinel)) hits.push(`store ${ref}: ${sentinel}`);
  }
  return hits;
}

describe("workload identity (fixtures)", () => {
  it("activates with no stored login and no browser, and never stores the workload session", async () => {
    const store = new MemorySecretStore();
    const distribution = open(store);
    const activated = await distribution.activate();
    expect(activated.identity).toMatchObject({
      subject: "svc-build-1",
      issuer: "https://workload.example/",
    });
    expect(activated.credential.ref).toMatchObject({
      mode: "http-broker",
      credentialId: "vk_demo_1",
    });
    expect(activated.selectedModel).toBe("acme/coder");
    // The broker saw the workload token as the bearer; no identity provider
    // endpoint, authorization page, or token grant was ever used.
    expect(brokerRequests()).toHaveLength(1);
    expect(brokerRequests()[0].authorization).toBe(`Bearer ${source().token}`);
    expect(identityRequests()).toEqual([]);
    expect(services.state.authorizations).toEqual([]);
    expect(source().openUrlSeen).toBe(0);
    // Memory only: no session file and no identity secret.
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(
      false,
    );
    expect(store.refs().some((ref) => ref.includes(":identity#"))).toBe(false);
    expect(await residue(store, [source().token])).toEqual([]);
    // The credential is bound to the workload principal like a person's.
    expect(JSON.parse(readFileSync(credentialFile(), "utf8"))).toMatchObject({
      principal: {
        issuer: "https://workload.example/",
        subject: "svc-build-1",
      },
    });
    expect(distribution.readPrincipalBinding()).toMatchObject({
      issuer: "https://workload.example/",
      subject: "svc-build-1",
    });
    expect(events.map((event) => event.event)).toEqual([
      "identity.login",
      "credential.acquire",
    ]);
    expect(events[0]?.detail).toMatchObject({ workload: true });
    // The session is held for the process: a request-time secret needs no
    // second session.
    expect((await distribution.requestSecret())?.reveal()).toBe(
      activated.credential.secret?.reveal(),
    );
    expect(source().calls).toBe(1);
  });

  it("fails closed when the adapter tries to open a browser or has no session, and acquires nothing", async () => {
    source().openBrowser = true;
    await expect(
      open(new MemorySecretStore()).activate(),
    ).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
      message: expect.stringContaining("tried to open a browser"),
    });
    source().openBrowser = false;
    // Whatever the adapter throws becomes a coded error without its text,
    // which may quote the token source (a JSON parse error quotes the file).
    source().fail = 'Unexpected token "demo-wt-leaked-sentinel" in JSON';
    const failed = await open(new MemorySecretStore())
      .activate()
      .catch((error: unknown) => error);
    expect(failed).toMatchObject({
      code: "IDENTITY_INVALID",
      message: "The workload identity adapter could not obtain a session",
    });
    expect(JSON.stringify(failed)).not.toContain("demo-wt-leaked-sentinel");
    expect(String(failed)).not.toContain("demo-wt-leaked-sentinel");
    delete source().fail;
    // An adapter that catches the refusal and returns a session anyway still
    // fails the run.
    source().swallowBrowser = true;
    await expect(
      open(new MemorySecretStore()).activate(),
    ).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
      message: expect.stringContaining("tried to open a browser"),
    });
    source().swallowBrowser = false;
    // A session without an expiry is refused.
    const expiry = source().expiresAt;
    delete source().expiresAt;
    await expect(
      open(new MemorySecretStore()).activate(),
    ).rejects.toMatchObject({
      code: "IDENTITY_INVALID",
      message: expect.stringContaining("without an expiry"),
    });
    source().expiresAt = expiry;
    source().expiresAt = new Date(clock - 1000).toISOString();
    await expect(
      open(new MemorySecretStore()).activate(),
    ).rejects.toMatchObject({ code: "IDENTITY_EXPIRED" });
    expect(brokerRequests()).toEqual([]);
    expect(existsSync(credentialFile())).toBe(false);
  });

  it("logs in without a browser and without storing the session", async () => {
    const store = new MemorySecretStore();
    const distribution = open(store);
    let opened = 0;
    const result = await distribution.login({
      openUrl: () => {
        opened += 1;
      },
    });
    expect(opened).toBe(0);
    expect(result.identity?.subject).toBe("svc-build-1");
    expect(result.credential.state).toBe("valid");
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(
      false,
    );
    expect(store.refs().some((ref) => ref.includes(":identity#"))).toBe(false);
    expect(events.find((event) => event.event === "identity.login")).toEqual(
      expect.objectContaining({
        detail: expect.objectContaining({ workload: true }),
      }),
    );
    // The login's session serves the activation of the same process.
    await distribution.activate();
    expect(source().calls).toBe(1);
  });

  it("obtains an expiring session again, and never switches the principal inside a process", async () => {
    source().expiresAt = new Date(clock + 10 * 60_000).toISOString();
    const distribution = open(new MemorySecretStore());
    await distribution.activate();
    expect(source().calls).toBe(1);
    // Rotation by the workload platform: the next session has a new token.
    clock += 9.5 * 60_000;
    source().token = mint("svc-build-1");
    source().expiresAt = new Date(clock + 10 * 60_000).toISOString();
    await distribution.requestSecret({ force: true });
    expect(source().calls).toBe(2);
    expect(
      events.filter((event) => event.event === "identity.refresh"),
    ).toEqual([
      {
        event: "identity.refresh",
        detail: expect.objectContaining({
          reason: "expiring",
          workload: true,
        }),
      },
    ]);
    expect(brokerRequests().at(-1)?.authorization).toBe(
      `Bearer ${source().token}`,
    );
    // A new session for another principal is refused in the same process.
    clock += 9.5 * 60_000;
    workloadAs("svc-other-9", ["acme/coder"]);
    source().expiresAt = new Date(clock + 10 * 60_000).toISOString();
    await expect(
      distribution.requestSecret({ force: true }),
    ).rejects.toMatchObject({ code: "IDENTITY_INVALID" });
  });

  it("obtains the session once more after the broker rejects the workload token, then fails closed", async () => {
    const store = new MemorySecretStore();
    const expired = source().token;
    services.state.accessTokens.delete(expired);
    // The platform has already rotated the token: the second session works.
    let rotated = "";
    const adapterSource = source();
    const original = adapterSource.token;
    Object.defineProperty(adapterSource, "token", {
      configurable: true,
      get() {
        if (adapterSource.calls <= 1) return original;
        rotated ||= mint("svc-build-1");
        return rotated;
      },
    });
    const activated = await open(store).activate();
    expect(adapterSource.calls).toBe(2);
    expect(activated.credential.ref?.credentialId).toBe("vk_demo_1");
    expect(
      events.find((event) => event.event === "identity.refresh")?.detail,
    ).toMatchObject({ reason: "rejected", workload: true });
    // A platform that keeps handing out a dead token fails the launch.
    Object.defineProperty(adapterSource, "token", {
      configurable: true,
      writable: true,
      value: expired,
    });
    rmSync(credentialFile(), { force: true });
    await expect(
      open(new MemorySecretStore()).activate(),
    ).rejects.toMatchObject({ code: "IDENTITY_EXPIRED" });
  });

  it("rotates the runtime credential on expiry, and fails closed when an expired one cannot be renewed", async () => {
    const store = new MemorySecretStore();
    const first = await open(store).activate();
    const firstSecret = first.credential.secret?.reveal() ?? "";
    expect(first.credential.ref?.credentialId).toBe("vk_demo_1");
    // A later run, within refresh.beforeExpiry of the credential's expiry.
    clock += 3600_000 - 60_000;
    const second = await open(store).activate();
    expect(second.credential.ref?.credentialId).toBe("vk_demo_2");
    expect(second.credential.secret?.reveal()).not.toBe(firstSecret);
    expect(await residue(store, [firstSecret])).toEqual([]);
    expect(
      events.filter((event) => event.event === "credential.refresh"),
    ).toHaveLength(1);
    expect(JSON.parse(readFileSync(credentialFile(), "utf8"))).toMatchObject({
      principal: { subject: "svc-build-1" },
    });
    // Past its expiry, with the broker down: the launch fails closed, as a
    // retryable broker outage rather than a revoked or expired credential.
    clock += 3 * 3600_000;
    // The platform has issued the workload a current token by then.
    source().expiresAt = new Date(clock + 3600_000).toISOString();
    services.knobs.brokerStatus = 503;
    const outage = await open(store)
      .activate()
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    expect(outage).toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
      retryable: true,
    });
    expect(String((outage as { action?: string }).action)).not.toMatch(
      /login/i,
    );
  });

  it("gives a new workload principal nothing of the previous one between runs", async () => {
    const store = new MemorySecretStore();
    workloadAs("svc-build-1", ["acme/coder", "acme/general"]);
    const first = await open(store).activate();
    const firstSecret = first.credential.secret?.reveal() ?? "";
    setPreference(
      join(stateDir(), "config", "preferences.json"),
      access,
      undefined,
      "model",
      "acme/general",
    );
    expect((await open(store).activate()).selectedModel).toBe("acme/general");

    // The next run's workload identity is another service principal.
    workloadAs("svc-deploy-2", ["acme/coder"]);
    events = [];
    const second = await open(store).activate();
    expect(second.identity?.subject).toBe("svc-deploy-2");
    expect(services.state.revokedCredentials).toEqual(["vk_demo_1"]);
    expect(second.credential.ref?.credentialId).toBe("vk_demo_2");
    expect(second.config.allowedModels).toEqual(["acme/coder"]);
    expect(second.selectedModel).toBe("acme/coder");
    expect(second.notices).toEqual(
      expect.arrayContaining([
        "The model selection of a previously signed-in identity was cleared",
        "A stored credential that was not issued to the signed-in identity was discarded",
      ]),
    );
    expect(
      readPreferences(join(stateDir(), "config", "preferences.json")).values
        .model,
    ).toBeUndefined();
    expect(
      events.find((event) => event.event === "credential.revoke")?.detail,
    ).toMatchObject({ reason: "principal-change" });
    expect(await residue(store, [firstSecret])).toEqual([]);
  });

  it("clears a stored session of another principal before the workload runs, and fails closed when that deletion fails", async () => {
    const seed = async (store: SecretStore) => {
      const ref = "piship:acmecode:identity#1";
      await store.put(
        ref,
        identitySecret({
          subject: "alice-0001",
          issuer: services.issuer,
          accessToken: new SecretValue("demo-at-alice-sentinel"),
          refreshToken: new SecretValue("demo-rt-alice-sentinel"),
        }),
      );
      mkdirSync(join(stateDir(), "identity"), { recursive: true });
      writeFileSync(
        join(stateDir(), "identity", "session.json"),
        JSON.stringify(
          identityMetadata(
            { subject: "alice-0001", issuer: services.issuer },
            ref,
          ),
        ),
      );
    };
    const store = new MemorySecretStore();
    await seed(store);
    const activated = await open(store).activate();
    expect(activated.identity?.subject).toBe("svc-build-1");
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(
      false,
    );
    expect(
      await residue(store, [
        "demo-at-alice-sentinel",
        "demo-rt-alice-sentinel",
      ]),
    ).toEqual([]);

    // A store that cannot delete her tokens blocks the workload.
    rmSync(stateDir(), { recursive: true, force: true });
    const locked = new MemorySecretStore();
    await seed(locked);
    locked.delete = async () => {
      throw new Error("the keyring is locked");
    };
    const before = brokerRequests().length;
    await expect(open(locked).activate()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    expect(brokerRequests()).toHaveLength(before);
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(true);
    // A person's tokens are never handed to the workload adapter's logout.
    expect(source().logouts).toBe(0);
  });

  it("gives the adapter 30 s, then fails with a retryable coded error; a cancelled login stops at once", async () => {
    // Load the adapter first: its import is real I/O, not a timer.
    const first = open(new MemorySecretStore());
    const second = open(new MemorySecretStore());
    await first.identityProvider();
    await second.identityProvider();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      source().hang = true;
      const hanging = first.activate().catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(29_000);
      let settled = false;
      void hanging.then(() => {
        settled = true;
      });
      await Promise.resolve();
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(await hanging).toMatchObject({
        code: "GATEWAY_UNREACHABLE",
        retryable: true,
        message: "The workload identity adapter did not answer",
      });
      const controller = new AbortController();
      const cancelled = second
        .login({ openUrl: () => undefined, signal: controller.signal })
        .catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(10);
      controller.abort();
      expect(await cancelled).toMatchObject({ code: "IDENTITY_REQUIRED" });
    } finally {
      vi.useRealTimers();
      source().hang = false;
    }
    expect(brokerRequests()).toEqual([]);
    expect(existsSync(credentialFile())).toBe(false);
  });

  it("obtains the session again after five minutes even when it is valid longer, and shares one adapter call", async () => {
    const distribution = open(new MemorySecretStore());
    const [first, second] = await Promise.all([
      distribution.currentIdentity({ required: true }),
      distribution.currentIdentity({ required: true }),
    ]);
    // Concurrent callers share one adapter call.
    expect(source().calls).toBe(1);
    expect(second).toBe(first);
    clock += 4 * 60_000;
    await distribution.currentIdentity({ required: true });
    expect(source().calls).toBe(1);
    // The platform rotated the token; the session is an hour long, but the
    // next use after five minutes picks up the new one.
    clock += 60_000 + 1;
    source().token = mint("svc-build-1");
    const rotated = await distribution.currentIdentity({ required: true });
    expect(source().calls).toBe(2);
    expect(rotated?.accessToken?.reveal()).toBe(source().token);
    expect(
      events.find((event) => event.event === "identity.refresh")?.detail,
    ).toMatchObject({ reason: "age", workload: true });
  });

  it("never hands a stored session to the workload adapter's logout", async () => {
    const store = new MemorySecretStore();
    const distribution = open(store);
    await distribution.activate();
    // A person's session stored beside the workload (same principal, so the
    // workload leaves it in place), then a logout.
    const ref = "piship:acmecode:identity#1";
    await store.put(
      ref,
      identitySecret({
        subject: "svc-build-1",
        issuer: "https://workload.example/",
        accessToken: new SecretValue("demo-at-person-sentinel"),
      }),
    );
    writeFileSync(
      join(stateDir(), "identity", "session.json"),
      JSON.stringify(
        identityMetadata(
          { subject: "svc-build-1", issuer: "https://workload.example/" },
          ref,
        ),
      ),
    );
    events = [];
    expect(await open(store).logout()).toEqual([]);
    expect(source().logouts).toBe(0);
    expect(
      events.find((event) => event.event === "identity.logout")?.detail,
    ).toMatchObject({ revocation: "unsupported" });
    expect(await residue(store, ["demo-at-person-sentinel"])).toEqual([]);
  });

  it("deletes the token bundle of an unreadable stored session before the workload runs, and fails closed when it cannot", async () => {
    const seed = async (store: SecretStore) => {
      await store.put(
        "piship:acmecode:identity#1",
        identitySecret({
          subject: "alice-0001",
          issuer: services.issuer,
          accessToken: new SecretValue("demo-at-alice-unreadable"),
        }),
      );
      mkdirSync(join(stateDir(), "identity"), { recursive: true });
      writeFileSync(
        join(stateDir(), "identity", "session.json"),
        JSON.stringify({
          ...identityMetadata(
            { subject: "alice-0001", issuer: services.issuer },
            "piship:acmecode:identity#1",
          ),
          schema: "piship-identity-metadata/v9",
        }),
      );
    };
    const store = new MemorySecretStore();
    await seed(store);
    await open(store).activate();
    expect(existsSync(join(stateDir(), "identity", "session.json"))).toBe(
      false,
    );
    expect(await residue(store, ["demo-at-alice-unreadable"])).toEqual([]);

    rmSync(stateDir(), { recursive: true, force: true });
    const locked = new MemorySecretStore();
    await seed(locked);
    locked.delete = async () => {
      throw new Error("the keyring is locked");
    };
    const before = brokerRequests().length;
    await expect(open(locked).activate()).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    expect(brokerRequests()).toHaveLength(before);
    expect(
      JSON.parse(
        readFileSync(join(stateDir(), "identity", "session.json"), "utf8"),
      ),
    ).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: expect.arrayContaining(["piship:acmecode:identity#1"]),
    });
  });

  it("keeps the interactive path: an adapter that does not declare itself non-interactive still needs a stored login", async () => {
    writeFileSync(
      join(temp, "resources", "adapters", "interactive.mjs"),
      WORKLOAD_ADAPTER.replace("interactive: false,", ""),
    );
    await expect(
      open(new MemorySecretStore(), {
        mode: "adapter",
        adapter: "./adapters/interactive.mjs",
      }).activate(),
    ).rejects.toMatchObject({ code: "IDENTITY_REQUIRED" });
    expect(source().calls).toBe(0);
    writeFileSync(
      join(temp, "resources", "adapters", "typo.mjs"),
      WORKLOAD_ADAPTER.replace("interactive: false,", 'interactive: "false",'),
    );
    await expect(
      open(new MemorySecretStore(), {
        mode: "adapter",
        adapter: "./adapters/typo.mjs",
      }).activate(),
    ).rejects.toMatchObject({ code: "CONFIG_INVALID" });
    expect(brokerRequests()).toEqual([]);
  });
});
