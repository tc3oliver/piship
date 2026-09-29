// The branded logout against the deterministic fixture services, with the
// restricted file store under a temporary state directory. Faults are
// injected at the store itself: a secret file that cannot be read or
// removed, or (POSIX) a store directory that refuses every change.
import { createHash } from "node:crypto";
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
import { type AuditEvent, principalId } from "@piship/contracts";
import type { AccessManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { DistributionAccess } from "./access/index.js";
import type { BrandedContext } from "./branded/context.js";
import { runLogout } from "./branded/login.js";
import { resolveLock } from "./index.js";

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const ID = "acmecode";
const POSIX_USER = process.platform !== "win32" && process.getuid?.() !== 0;

let temp: string;
let services: Awaited<ReturnType<typeof startLocalServices>>;
let savedEnv: NodeJS.ProcessEnv;
beforeEach(async () => {
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

function context() {
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
          storage: { provider: "file", acknowledgePlaintext: true },
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

  it.runIf(POSIX_USER)(
    "fails and keeps every secret tracked while the store is locked",
    async () => {
      const { ctx, out, path } = context();
      await signIn(ctx);
      // Locked: every read and every removal fails.
      for (const name of readdirSync(path("secrets")))
        chmodSync(path("secrets", name), 0o644);
      chmodSync(path("secrets"), 0o500);
      const identity = readFileSync(path("identity", "session.json"), "utf8");
      const error = await rejection(runLogout(ctx));
      expect(error.code).toBe("SECRET_STORE_UNAVAILABLE");
      expect(error.message).toBe(
        "Signed out of AcmeCode only in part: the identity session and the runtime credential could not be deleted from the secret store. They are never used and stay tracked, so the next login or logout deletes them; sessions were preserved",
      );
      expect(out).toEqual([]);
      expect(readFileSync(path("identity", "session.json"), "utf8")).toBe(
        identity,
      );
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
});
