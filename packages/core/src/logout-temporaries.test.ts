// Logout and the temporaries a writer killed before its rename leaves beside
// identity and credential state: none survives the sign-out, with or
// without the runtime variables, while the principal binding and the
// pending-revocation record (which logout keeps) lose only abandoned ones.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
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

let temp: string;
let services: Awaited<ReturnType<typeof startLocalServices>>;
let savedEnv: NodeJS.ProcessEnv;
const children: ChildProcess[] = [];
beforeEach(async () => {
  savedEnv = { ...process.env };
  temp = mkdtempSync(join(tmpdir(), "piship-logout-temporaries-"));
  services = await startLocalServices();
  Object.assign(process.env, services.env());
});
afterEach(async () => {
  process.env = savedEnv;
  const { Agent, setGlobalDispatcher } = await import("undici");
  setGlobalDispatcher(new Agent());
  await services.close();
  for (const child of children.splice(0)) child.kill();
  rmSync(temp, { recursive: true, force: true });
});

function context() {
  const lock = resolveLock(DEMO);
  const access = lock.access as AccessManifest;
  const out: string[] = [];
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
    err: () => {},
  };
  const path = (...parts: string[]) => join(ctx.stateDir, ...parts);
  return { ctx, out, path };
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

function deadPid(): number {
  return spawnSync(process.execPath, ["-e", ""]).pid as number;
}
function livePid(): number {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  children.push(child);
  return child.pid as number;
}
function temporaries(dir: string): string[] {
  return existsSync(dir)
    ? readdirSync(dir)
        .filter((name) => name.endsWith(".tmp"))
        .sort()
    : [];
}
function stateText(dir: string): string {
  const texts: string[] = [];
  const visit = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true }))
      if (entry.isDirectory()) visit(join(path, entry.name));
      else texts.push(readFileSync(join(path, entry.name), "latin1"));
  };
  visit(dir);
  return texts.join("\n");
}

/**
 * Leave what writers killed before their rename would: copies of the
 * signed-in identity and credential metadata and of a stored secret, under
 * every temporary name shape, from dead, live, and unrecorded writers.
 */
function killedWriters(path: (...parts: string[]) => string) {
  const dead = deadPid();
  const live = livePid();
  const session = path("identity", "session.json");
  const credential = path("credentials-metadata", "inference.json");
  const [secret] = readdirSync(path("secrets"));
  const copies = [
    [session, `${session}.p${dead}-0123456789ab.tmp`],
    [session, `${session}.fedcba987654.tmp`],
    [credential, `${credential}.0123456789ab.tmp`],
    [credential, `${credential}.p${live}-0123456789ab.tmp`],
    [
      path("secrets", secret as string),
      path("secrets", `${secret}.0123456789ab.tmp`),
    ],
    [
      session,
      `${path("identity", "principal.json")}.p${dead}-0123456789ab.tmp`,
    ],
    [
      credential,
      `${path("credentials-metadata", "revocation-retry.json")}.p${dead}-0123456789ab.tmp`,
    ],
  ] as const;
  for (const [from, to] of copies) copyFileSync(from, to);
  // A principal binding being written right now by a live process.
  const livePrincipal = `${path("identity", "principal.json")}.p${live}-0123456789ab.tmp`;
  copyFileSync(session, livePrincipal);
  return { livePrincipal };
}

describe("logout and abandoned temporaries", () => {
  it("leaves no identity or credential temporary behind", async () => {
    const { ctx, out, path } = context();
    const secrets = await signIn(ctx);
    const { livePrincipal } = killedWriters(path);
    await runLogout(ctx);
    expect(out).toEqual([
      "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
    ]);
    expect(temporaries(path("identity"))).toEqual([
      livePrincipal.split(/[/\\]/).at(-1),
    ]);
    expect(temporaries(path("credentials-metadata"))).toEqual([]);
    expect(temporaries(path("secrets"))).toEqual([]);
    rmSync(livePrincipal);
    const text = stateText(ctx.stateDir);
    for (const secret of secrets) expect(text).not.toContain(secret);
  });

  it("leaves none behind when it signs out locally without the runtime variables", async () => {
    const { ctx, out, path } = context();
    const secrets = await signIn(ctx);
    const { livePrincipal } = killedWriters(path);
    for (const name of Object.keys(services.env())) delete process.env[name];
    await runLogout(ctx);
    expect(out).toEqual([
      "Signed out of AcmeCode. Local runtime and identity credentials were cleared; sessions were preserved.",
    ]);
    expect(temporaries(path("identity"))).toEqual([
      livePrincipal.split(/[/\\]/).at(-1),
    ]);
    expect(temporaries(path("credentials-metadata"))).toEqual([]);
    expect(temporaries(path("secrets"))).toEqual([]);
    rmSync(livePrincipal);
    const text = stateText(ctx.stateDir);
    for (const secret of secrets) expect(text).not.toContain(secret);
  });
});
