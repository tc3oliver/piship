// The branded logout against the deterministic fixture services, with the
// restricted file store under a temporary state directory. Faults are
// injected at the store itself: a secret file that cannot be read or
// removed, or (POSIX) a store directory that refuses every change.
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditConfig } from "@piship/audit";
import {
  type AuditEvent,
  PiShipError,
  principalId,
  type SecretStore,
  type SecretValue,
} from "@piship/contracts";
import {
  MemorySecretStore,
  RestrictedFileSecretStore,
  SecretServiceSecretStore,
  type SecretStoreSelection,
  withFileLock,
} from "@piship/credentials";
import type { AccessManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { type AccessEvent, DistributionAccess } from "./access/index.js";
import type { BrandedContext } from "./branded/context.js";
import { runLogout } from "./branded/login.js";
import { resolveLock } from "./index.js";

// The platform store is stood in for by a memory store the test sets, so that
// no test reaches the real one. Unset, it is not available, as on a machine
// without a keychain or secret service.
const platform = vi.hoisted(() => ({ store: null as SecretStore | null }));
vi.mock("@piship/credentials", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@piship/credentials")>();
  return {
    ...actual,
    createSecretStore: (selection: SecretStoreSelection) => {
      if (selection.provider !== "system")
        return actual.createSecretStore(selection);
      if (!platform.store)
        throw new Error("the platform secret store is not available");
      return platform.store;
    },
  };
});

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const ID = "acmecode";
const POSIX_USER = process.platform !== "win32" && process.getuid?.() !== 0;

let temp: string;
let services: Awaited<ReturnType<typeof startLocalServices>>;
let savedEnv: NodeJS.ProcessEnv;
beforeEach(async () => {
  platform.store = null;
  savedEnv = { ...process.env };
  temp = mkdtempSync(join(tmpdir(), "piship-branded-logout-"));
  services = await startLocalServices();
  Object.assign(process.env, services.env());
});
afterEach(async () => {
  process.env = savedEnv;
  // runLogout applies the distribution's network policy to this process.
  const { Agent, setGlobalDispatcher } = await import("undici");
  setGlobalDispatcher(new Agent());
  await services.close();
  // Undo a permission fault so the directory can be removed.
  const secrets = join(temp, "state", "secrets");
  if (existsSync(secrets)) chmodSync(secrets, 0o700);
  rmSync(temp, { recursive: true, force: true });
});

function context(provider: "file" | "system" = "file") {
  const lock = resolveLock(DEMO);
  const access = lock.access as AccessManifest;
  const out: string[] = [];
  const err: string[] = [];
  const ctx: BrandedContext = {
    metadata: {
      ...lock,
      access: {
        ...access,
        identity: {
          ...access.identity,
          oidc: {
            ...(access.identity as { oidc: object }).oidc,
            redirectUri: "http://127.0.0.1/callback",
          },
        },
        credential: {
          ...access.credential,
          storage:
            provider === "file"
              ? { provider, acknowledgePlaintext: true }
              : { provider },
        },
      } as AccessManifest,
    },
    distributionDir: temp,
    stateDir: join(temp, "state"),
    mode: "managed",
    out: (message) => out.push(message),
    err: (message) => err.push(message),
  };
  const path = (...parts: string[]) => join(ctx.stateDir, ...parts);
  return { ctx, out, err, path };
}

async function signIn(ctx: BrandedContext): Promise<string[]> {
  const access = DistributionAccess.open({
    app: ctx.metadata.app,
    mode: ctx.mode,
    access: ctx.metadata.access,
    stateDir: ctx.stateDir,
    distributionDir: ctx.distributionDir,
    env: services.env(),
  });
  await access.login({ openUrl: (url) => void services.approve(url) });
  const { state } = services;
  return [
    ...state.credentials.keys(),
    ...state.accessTokens.keys(),
    ...state.refreshTokens.keys(),
  ];
}

/** The restricted file store's file for a reference. */
function secretFile(ctx: BrandedContext, ref: string): string {
  return join(
    ctx.stateDir,
    "secrets",
    `${createHash("sha256").update(ref).digest("hex")}.secret`,
  );
}

function auditEvents(ctx: BrandedContext): AuditEvent[] {
  return readFileSync(join(ctx.stateDir, "logs", "audit.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as AuditEvent);
}

function stateText(ctx: BrandedContext): string {
  const texts: string[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir, { withFileTypes: true })) {
      const child = join(dir, name.name);
      if (name.isDirectory()) visit(child);
      else texts.push(readFileSync(child, "latin1"));
    }
  };
  visit(ctx.stateDir);
  return texts.join("\n");
}

/**
 * Move the identity's token bundle to another store and record that store in
 * the session, as a release configured for the other storage provider leaves
 * it (a Pi session of the old release refreshing the identity after the
 * switch, say).
 */
async function moveIdentityTokens(
  ctx: BrandedContext,
  from: SecretStore,
  to: SecretStore,
  recorded: "file" | "system",
): Promise<string> {
  const file = join(ctx.stateDir, "identity", "session.json");
  const metadata = JSON.parse(readFileSync(file, "utf8"));
  await to.put(
    metadata.secretRef,
    (await from.get(metadata.secretRef)) as SecretValue,
  );
  await from.delete(metadata.secretRef);
  writeFileSync(file, JSON.stringify({ ...metadata, secret_store: recorded }));
  return metadata.secretRef;
}

const fileStoreOf = (ctx: BrandedContext) =>
  new RestrictedFileSecretStore(join(ctx.stateDir, "secrets"));

/** A local URL nothing listens on. */
async function closedUrl(): Promise<string> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return `http://127.0.0.1:${port}/ingest`;
}

async function rejection(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    return error as Error & { code?: string };
  }
  throw new Error("expected a rejection");
}

describe("branded logout", () => {
  it("clears local credentials and attributes the audit to the (issuer, subject) principal", async () => {
    const { ctx, out, err, path } = context();
    const secrets = await signIn(ctx);
    await runLogout(ctx);
    expect(err).toEqual([]);
    expect(out).toEqual([
      "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
    ]);
    expect(readdirSync(path("secrets"))).toEqual([]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
      false,
    );
    const user = principalId({
      issuer: services.issuer,
      subject: services.knobs.subject,
    });
    const events = auditEvents(ctx);
    expect(events.map((event) => [event.event, event.user])).toEqual([
      ["credential.revoke", user],
      ["identity.logout", user],
    ]);
    const text = stateText(ctx);
    for (const secret of secrets) expect(text).not.toContain(secret);
  });

  it("clears local secrets without the runtime variables, and records the revocation it could not send", async () => {
    const { ctx, out, err, path } = context();
    const secrets = await signIn(ctx);
    const [credentialId] = [...services.state.credentials.values()].map(
      (entry: { id: string }) => entry.id,
    );
    for (const name of Object.keys(services.env())) delete process.env[name];
    await runLogout(ctx);
    // Nothing remote was contacted.
    expect(services.state.revokedCredentials).toEqual([]);
    expect(services.state.revokedTokens).toEqual([]);
    expect(err[0]).toMatch(
      /^Warning: CONFIG_UNAVAILABLE: Runtime variable ACMECODE_OIDC_ISSUER for identity\.oidc\.issuer is not set.*; signing out locally without contacting the identity provider or credential broker$/s,
    );
    expect(err.slice(1)).toEqual([
      expect.stringMatching(/^Warning: revocation: not attempted: /),
      expect.stringMatching(/^Warning: identity revocation: not attempted: /),
    ]);
    expect(out).toEqual([
      "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
    ]);
    expect(readdirSync(path("secrets"))).toEqual([]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
      false,
    );
    // The credential may still be valid at the broker: it stays reported.
    const retry = JSON.parse(
      readFileSync(
        path("credentials-metadata", "revocation-retry.json"),
        "utf8",
      ),
    );
    expect(retry).toMatchObject({
      schema: "piship-revocation-retry/v1",
      entries: [
        {
          credential_id: credentialId,
          mode: "http-broker",
          generation: 1,
          reason: "logout",
        },
      ],
    });
    const events = auditEvents(ctx);
    expect(events.map((event) => [event.event, event.detail])).toEqual([
      [
        "credential.revoke",
        expect.objectContaining({
          mode: "http-broker",
          reason: "logout",
          revocation: "failed",
          retryPending: true,
        }),
      ],
      ["identity.logout", { mode: "http-broker", revocation: "failed" }],
    ]);
    const text = stateText(ctx);
    for (const secret of secrets) expect(text).not.toContain(secret);
  });

  it.each([
    ["with", true],
    ["without", false],
  ])(
    "says which references it dropped when the system store is not installed, %s the runtime variables",
    async (_name, variables) => {
      const { ctx, out, err, path } = context("system");
      platform.store = new SecretServiceSecretStore(() => ({
        status: null,
        stdout: "",
        stderr: "spawnSync secret-tool ENOENT",
        missing: true,
      }));
      // The discarded marker v0.8.0 left: it cannot say whether a secret
      // was ever written under the reference.
      mkdirSync(path("credentials-metadata"), { recursive: true });
      writeFileSync(
        path("credentials-metadata", "inference.json"),
        JSON.stringify({
          schema: "piship-credential-discarded/v1",
          orphans: [`piship:${ID}:inference#1`],
          secret_store: "system",
        }),
      );
      if (!variables)
        for (const name of Object.keys(services.env()))
          delete process.env[name];
      await runLogout(ctx);
      expect(err).toContainEqual(
        `Warning: Secret references an earlier sign-in or sign-out left behind (piship:${ID}:inference#1) were dropped without deleting anything: the secret store that recorded them is not installed here, and no secret was confirmed written under them`,
      );
      expect(out).toEqual([
        "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
      ]);
      expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
        false,
      );
    },
  );

  it("deletes the secrets damaged metadata still names when signing out without the runtime variables", async () => {
    const { ctx, path } = context();
    await signIn(ctx);
    for (const file of [
      path("identity", "session.json"),
      path("credentials-metadata", "inference.json"),
    ]) {
      const text = readFileSync(file, "utf8");
      // Cut short after the first secret reference: no longer JSON.
      const end = text.indexOf(`piship:${ID}:`);
      writeFileSync(file, text.slice(0, text.indexOf('"', end) + 1));
    }
    expect(readdirSync(path("secrets")).length).toBeGreaterThan(0);
    for (const name of Object.keys(services.env())) delete process.env[name];
    await runLogout(ctx);
    expect(readdirSync(path("secrets"))).toEqual([]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
      false,
    );
  });

  it("says what was cleared and fails when the runtime credential cannot be deleted", async () => {
    const { ctx, out, err, path } = context();
    const secrets = await signIn(ctx);
    // The credential's secret file can be neither read nor removed.
    const file = secretFile(ctx, `piship:${ID}:inference#1`);
    rmSync(file);
    mkdirSync(join(file, "blocked"), { recursive: true });
    writeFileSync(join(file, "blocked", "x"), "x");
    const error = await rejection(runLogout(ctx));
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(error.message).toBe(
      "Signed out of AcmeCode only in part: the identity session was cleared, but the runtime credential could not be deleted from the secret store. It is never used and stays tracked, so the next login or logout deletes it; sessions were preserved",
    );
    expect(out).toEqual([]);
    expect(err).toEqual([
      expect.stringMatching(
        /^Warning: revocation: the stored credential could not be read/,
      ),
      expect.stringMatching(
        new RegExp(`^Warning: delete piship:${ID}:inference#1: `),
      ),
    ]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(
      JSON.parse(
        readFileSync(path("credentials-metadata", "inference.json"), "utf8"),
      ),
    ).toMatchObject({
      schema: "piship-credential-discarded/v1",
      orphans: [`piship:${ID}:inference#1`],
    });
    // Repaired, the next logout finishes the deletion.
    rmSync(file, { recursive: true });
    out.length = 0;
    err.length = 0;
    await runLogout(ctx);
    expect(out).toEqual([
      "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
    ]);
    expect(existsSync(path("credentials-metadata", "inference.json"))).toBe(
      false,
    );
    expect(readdirSync(path("secrets"))).toEqual([]);
    const text = stateText(ctx);
    for (const secret of secrets) expect(text).not.toContain(secret);
  });

  it("fails instead of signing out around a process that still holds a lock", async () => {
    const { ctx, err, path } = context();
    await signIn(ctx);
    const refs = readdirSync(path("secrets")).length;
    const spy = vi
      .spyOn(DistributionAccess.prototype, "logout")
      .mockRejectedValueOnce(
        new PiShipError(
          "CREDENTIAL_ACQUIRE_FAILED",
          "Another process is still updating session.json; gave up after 90 s",
          {
            retryable: true,
            sanitizedDetail: { reason: "lock-timeout" },
          },
        ),
      );
    try {
      await expect(runLogout(ctx)).rejects.toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
      });
    } finally {
      spy.mockRestore();
    }
    // Nothing was deleted around the holder, and no local fallback ran.
    expect(existsSync(path("identity", "session.json"))).toBe(true);
    expect(readdirSync(path("secrets"))).toHaveLength(refs);
    expect(err.join("\n")).not.toContain("signing out locally");
  });

  it("still audits what it did before a lock wait ran out", async () => {
    const { ctx } = context();
    await signIn(ctx);
    const spy = vi
      .spyOn(DistributionAccess.prototype, "logout")
      .mockImplementationOnce(async function (this: DistributionAccess) {
        // The credential was revoked and cleared; the identity lock ran out.
        (
          this as unknown as {
            options: { onEvent: (event: AccessEvent) => void };
          }
        ).options.onEvent({
          event: "credential.revoke",
          detail: { revocation: "revoked" },
        });
        throw new PiShipError("CREDENTIAL_ACQUIRE_FAILED", "lock wait", {
          retryable: true,
          sanitizedDetail: { reason: "lock-timeout" },
        });
      });
    try {
      await expect(runLogout(ctx)).rejects.toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
      });
    } finally {
      spy.mockRestore();
    }
    expect(auditEvents(ctx).map((event) => event.event)).toEqual([
      "credential.revoke",
    ]);
  });

  it("reports an identity provider that cannot be loaded as a failed revocation, not an unsupported one", async () => {
    const { ctx, err, out, path } = context();
    await signIn(ctx);
    const spy = vi
      .spyOn(DistributionAccess.prototype, "identityProvider")
      .mockRejectedValue(
        new PiShipError(
          "CONFIG_INVALID",
          "The identity adapter failed to load",
        ),
      );
    try {
      await runLogout(ctx);
    } finally {
      spy.mockRestore();
    }
    // The tokens are cleared locally, and the warning says nothing was sent.
    expect(err).toEqual([
      expect.stringMatching(
        /^Warning: identity revocation: not attempted: .*failed to load/,
      ),
    ]);
    expect(out).toHaveLength(1);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(
      auditEvents(ctx)
        .filter((event) => event.event === "identity.logout")
        .map((event) => event.detail),
    ).toEqual([expect.objectContaining({ revocation: "failed" })]);
  });

  it("waits for a holder of the identity lock before it signs out locally", async () => {
    const { ctx, path } = context();
    await signIn(ctx);
    for (const name of Object.keys(services.env())) delete process.env[name];
    const session = path("identity", "session.json");
    let release = () => {};
    const holding = withFileLock(
      session,
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    let finished = false;
    const logout = runLogout(ctx).finally(() => {
      finished = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 600));
    // A refresh in another process is still using the session: the sign-out
    // has not deleted it from under that refresh.
    expect(finished).toBe(false);
    expect(existsSync(session)).toBe(true);
    release();
    await holding;
    await logout;
    expect(existsSync(session)).toBe(false);
    expect(readdirSync(path("secrets"))).toEqual([]);
  });

  it.runIf(POSIX_USER)(
    "leaves a discarded marker, not usable metadata, when the identity tokens cannot be deleted without the runtime variables",
    async () => {
      const { ctx, path } = context();
      await signIn(ctx);
      for (const name of Object.keys(services.env())) delete process.env[name];
      for (const name of readdirSync(path("secrets")))
        chmodSync(path("secrets", name), 0o644);
      chmodSync(path("secrets"), 0o500);
      const error = await rejection(runLogout(ctx));
      expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
      expect(
        JSON.parse(readFileSync(path("identity", "session.json"), "utf8")),
      ).toMatchObject({
        schema: "piship-identity-discarded/v1",
        orphans: expect.arrayContaining([`piship:${ID}:identity#1`]),
      });
      chmodSync(path("secrets"), 0o700);
      for (const name of readdirSync(path("secrets")))
        chmodSync(path("secrets", name), 0o600);
      await runLogout(ctx);
      expect(readdirSync(path("secrets"))).toEqual([]);
      expect(existsSync(path("identity", "session.json"))).toBe(false);
    },
  );

  it.runIf(POSIX_USER)(
    "fails and keeps every secret tracked while the store is locked",
    async () => {
      const { ctx, out, path } = context();
      await signIn(ctx);
      // Locked: every read and every removal fails.
      for (const name of readdirSync(path("secrets")))
        chmodSync(path("secrets", name), 0o644);
      chmodSync(path("secrets"), 0o500);
      const error = await rejection(runLogout(ctx));
      expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
      expect(error.message).toBe(
        "Signed out of AcmeCode only in part: the identity session and the runtime credential could not be deleted from the secret store. They are never used and stay tracked, so the next login or logout deletes them; sessions were preserved",
      );
      expect(out).toEqual([]);
      // The identity session is signed out all the same: a discarded marker
      // tracks its tokens, and nothing restores it as a session.
      expect(
        JSON.parse(readFileSync(path("identity", "session.json"), "utf8")),
      ).toMatchObject({
        schema: "piship-identity-discarded/v1",
        orphans: expect.arrayContaining([`piship:${ID}:identity#1`]),
      });
      await expect(
        DistributionAccess.open({
          app: ctx.metadata.app,
          mode: ctx.mode,
          access: ctx.metadata.access,
          stateDir: ctx.stateDir,
          distributionDir: ctx.distributionDir,
          env: services.env(),
        }).activate(),
      ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
      expect(
        JSON.parse(
          readFileSync(path("credentials-metadata", "inference.json"), "utf8"),
        ).schema,
      ).toBe("piship-credential-discarded/v1");
      // The unreadable credential may still be live: it is recorded.
      expect(
        existsSync(path("credentials-metadata", "revocation-retry.json")),
      ).toBe(true);
      // Unlocked, logout completes.
      chmodSync(path("secrets"), 0o700);
      for (const name of readdirSync(path("secrets")))
        chmodSync(path("secrets", name), 0o600);
      await runLogout(ctx);
      expect(out).toEqual([
        "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
      ]);
      expect(readdirSync(path("secrets"))).toEqual([]);
      expect(existsSync(path("identity", "session.json"))).toBe(false);
    },
  );

  it("deletes the identity tokens from the store its session records when signing out without the runtime variables", async () => {
    const { ctx, out, path } = context("file");
    await signIn(ctx);
    // The session records the platform store, the configured one is the file.
    const system = new MemorySecretStore();
    platform.store = system;
    const ref = await moveIdentityTokens(
      ctx,
      fileStoreOf(ctx),
      system,
      "system",
    );
    expect(system.refs()).toEqual([ref]);
    for (const name of Object.keys(services.env())) delete process.env[name];
    await runLogout(ctx);
    expect(system.refs()).toEqual([]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(readdirSync(path("secrets"))).toEqual([]);
    expect(out).toEqual([
      "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
    ]);
  });

  it("deletes the identity tokens from the file store when the session records it and the platform store is configured", async () => {
    const system = new MemorySecretStore();
    platform.store = system;
    const { ctx, path } = context("system");
    await signIn(ctx);
    const file = fileStoreOf(ctx);
    const ref = await moveIdentityTokens(ctx, system, file, "file");
    expect(await file.get(ref)).not.toBeNull();
    for (const name of Object.keys(services.env())) delete process.env[name];
    await runLogout(ctx);
    expect(await file.get(ref)).toBeNull();
    expect(system.refs()).toEqual([]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(readdirSync(path("secrets"))).toEqual([]);
  });

  it("keeps identity tokens tracked in a marker that names their store while that store is not available", async () => {
    const { ctx, out, err, path } = context("file");
    await signIn(ctx);
    const system = new MemorySecretStore();
    const ref = await moveIdentityTokens(
      ctx,
      fileStoreOf(ctx),
      system,
      "system",
    );
    for (const name of Object.keys(services.env())) delete process.env[name];
    // No platform store here: the file store is not looked in instead, where
    // nothing would be found and the deletion would count as confirmed.
    const error = await rejection(runLogout(ctx));
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(error.message).toBe(
      "Signed out of AcmeCode only in part: the runtime credential was cleared, but the identity session could not be deleted from the secret store. It is never used and stays tracked, so the next login or logout deletes it; sessions were preserved",
    );
    expect(out).toEqual([]);
    expect(err).toEqual(
      expect.arrayContaining([
        `Warning: identity secret ${ref}: the system secret store that holds it is not available`,
      ]),
    );
    expect(
      JSON.parse(readFileSync(path("identity", "session.json"), "utf8")),
    ).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: expect.arrayContaining([ref]),
      secret_store: "system",
    });
    expect(system.refs()).toEqual([ref]);
    // Once the store is reachable, the next logout deletes them.
    platform.store = system;
    err.length = 0;
    await runLogout(ctx);
    expect(system.refs()).toEqual([]);
    expect(existsSync(path("identity", "session.json"))).toBe(false);
    expect(out).toEqual([
      "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
    ]);
  });

  it("names the store that could not delete identity tokens in the marker it leaves", async () => {
    const { ctx, path } = context("file");
    await signIn(ctx);
    const system = new MemorySecretStore();
    const ref = await moveIdentityTokens(
      ctx,
      fileStoreOf(ctx),
      system,
      "system",
    );
    system.delete = async () => {
      throw new Error("the keychain is locked");
    };
    platform.store = system;
    for (const name of Object.keys(services.env())) delete process.env[name];
    const error = await rejection(runLogout(ctx));
    expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
    expect(
      JSON.parse(readFileSync(path("identity", "session.json"), "utf8")),
    ).toMatchObject({
      schema: "piship-identity-discarded/v1",
      orphans: expect.arrayContaining([ref]),
      secret_store: "system",
    });
    expect(system.refs()).toEqual([ref]);
  });

  it("keeps the lock timeout as the error, and shows what it found, when a required audit sink is down", async () => {
    const { ctx, err } = context();
    await signIn(ctx);
    const governance = ctx.metadata.governance as NonNullable<
      typeof ctx.metadata.governance
    >;
    const governed: BrandedContext = {
      ...ctx,
      auditCloseDeadlineMs: 300,
      metadata: {
        ...ctx.metadata,
        governance: {
          ...governance,
          manifest: {
            ...governance.manifest,
            audit: {
              ...governance.manifest.audit,
              enabled: true,
              sinks: [
                { id: "local", type: "file", required: false },
                {
                  id: "company",
                  type: "http",
                  url: await closedUrl(),
                  required: true,
                },
              ] as AuditConfig["sinks"],
            },
          },
        },
      },
    };
    const spy = vi
      .spyOn(DistributionAccess.prototype, "logout")
      .mockImplementationOnce(async function (
        this: DistributionAccess,
        problems: string[] = [],
      ) {
        // The credential could not be revoked; the identity lock ran out.
        (
          this as unknown as {
            options: { onEvent: (event: AccessEvent) => void };
          }
        ).options.onEvent({
          event: "credential.revoke",
          detail: { revocation: "failed" },
        });
        problems.push("revocation: the broker refused the request");
        throw new PiShipError("CREDENTIAL_ACQUIRE_FAILED", "lock wait", {
          retryable: true,
          sanitizedDetail: { reason: "lock-timeout" },
        });
      });
    try {
      // The retryable lock timeout is what the user sees, not the audit.
      await expect(runLogout(governed)).rejects.toMatchObject({
        code: "CREDENTIAL_ACQUIRE_FAILED",
        retryable: true,
      });
    } finally {
      spy.mockRestore();
    }
    expect(err).toEqual([
      "Warning: revocation: the broker refused the request",
      expect.stringMatching(
        /^Error: AUDIT_UNAVAILABLE: .*Required audit sink company \(http\) is unavailable/,
      ),
    ]);
  });

  it("drops what a logout that failed for another reason had found, since the local sign-out redoes it", async () => {
    const { ctx, err, out } = context();
    await signIn(ctx);
    const spy = vi
      .spyOn(DistributionAccess.prototype, "logout")
      .mockImplementationOnce(async (problems: string[] = []) => {
        problems.push("revocation: found by the attempt that then failed");
        throw new PiShipError("CONFIG_UNAVAILABLE", "a variable is not set");
      });
    try {
      await runLogout(ctx);
    } finally {
      spy.mockRestore();
    }
    expect(err.join("\n")).toContain("signing out locally");
    expect(err.join("\n")).not.toContain("found by the attempt");
    expect(out).toHaveLength(1);
  });
});
