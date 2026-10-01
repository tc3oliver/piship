// `<command> sandbox login|logout` against the deterministic fixture services
// with the restricted file store under a temporary state directory. The
// secret comes only from a no-echo prompt or the first line of stdin.
import { Readable } from "node:stream";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditEvent, PiShipError } from "@piship/contracts";
import { RestrictedFileSecretStore } from "@piship/credentials";
import type { AccessManifest, SandboxConfig } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { DistributionAccess } from "./access/index.js";
import type { BrandedContext } from "./branded/context.js";
import { runLogout } from "./branded/login.js";
import { runSandbox } from "./branded/sandbox.js";
import { resolveLock } from "./index.js";

// A TTY double: what readline was asked for, and the answer it gives, or
// the event it emits instead (Ctrl-C is SIGINT, Ctrl-D is close).
const tty = vi.hoisted(() => ({
  options: [] as Record<string, unknown>[],
  answer: "",
  cancel: undefined as "close" | "SIGINT" | undefined,
}));
vi.mock("node:readline", async (original) => {
  const actual = await original<typeof import("node:readline")>();
  return {
    ...actual,
    createInterface: (options: Record<string, unknown>) => {
      tty.options.push(options);
      const handlers = new Map<string, () => void>();
      return {
        once: (event: string, handler: () => void) =>
          handlers.set(event, handler),
        question: (_query: string, answer: (value: string) => void) =>
          tty.cancel ? handlers.get(tty.cancel)?.() : answer(tty.answer),
        close: () => {},
      };
    },
  };
});

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);
const SECRET = "fake-sandbox-key-SENTINEL-0001";
const ENDPOINT = "https://sandbox-api.test.invalid:8443";

let temp: string;
let services: Awaited<ReturnType<typeof startLocalServices>>;
let savedEnv: NodeJS.ProcessEnv;
beforeEach(async () => {
  savedEnv = { ...process.env };
  temp = mkdtempSync(join(tmpdir(), "piship-branded-sandbox-"));
  services = await startLocalServices();
  Object.assign(process.env, services.env(), {
    ACMECODE_SANDBOX_URL: ENDPOINT,
  });
  tty.options.length = 0;
  tty.answer = "";
  tty.cancel = undefined;
});
afterEach(async () => {
  vi.restoreAllMocks();
  process.env = savedEnv;
  // The commands apply the distribution's network policy to this process.
  const { Agent, setGlobalDispatcher } = await import("undici");
  setGlobalDispatcher(new Agent());
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

function context(sandbox: Partial<SandboxConfig> | null = {}) {
  const lock = resolveLock(DEMO);
  const access = lock.access as AccessManifest;
  if (access.identity.mode !== "oidc")
    throw new Error("the demo signs in with OIDC");
  const governance = lock.governance;
  if (!governance) throw new Error("the demo declares governance");
  const out: string[] = [];
  const err: string[] = [];
  const ctx: BrandedContext = {
    metadata: {
      ...lock,
      access: {
        ...access,
        variables: [...access.variables, "ACMECODE_SANDBOX_URL"],
        identity: {
          ...access.identity,
          oidc: {
            ...access.identity.oidc,
            redirectUri: "http://127.0.0.1/callback",
          },
        },
        credential: {
          ...access.credential,
          storage: { provider: "file", acknowledgePlaintext: true },
        },
      } as AccessManifest,
      governance: {
        ...governance,
        manifest: {
          ...governance.manifest,
          sandbox:
            sandbox === null
              ? governance.manifest.sandbox
              : ({
                  ...governance.manifest.sandbox,
                  provider: "e2b-compatible",
                  endpoint: `\${ACMECODE_SANDBOX_URL}`,
                  credential: "stored",
                  ...sandbox,
                } as unknown as SandboxConfig),
        },
      },
    },
    distributionDir: temp,
    stateDir: join(temp, "state"),
    mode: "managed",
    out: (message) => out.push(message),
    err: (message) => err.push(message),
  };
  const store = new RestrictedFileSecretStore(join(ctx.stateDir, "secrets"));
  return { ctx, out, err, store };
}

async function signIn(ctx: BrandedContext): Promise<void> {
  await DistributionAccess.open({
    app: ctx.metadata.app,
    mode: ctx.mode,
    access: ctx.metadata.access,
    stateDir: ctx.stateDir,
    distributionDir: ctx.distributionDir,
    env: services.env(),
  }).login({ openUrl: (url) => void services.approve(url) });
}

/** Stdin as a pipe: the first line is the secret. */
function pipe(text: string): void {
  const stream = Readable.from([text]) as Readable & { isTTY?: boolean };
  vi.spyOn(process, "stdin", "get").mockReturnValue(
    stream as unknown as typeof process.stdin,
  );
}

function auditEvents(ctx: BrandedContext): AuditEvent[] {
  return readFileSync(join(ctx.stateDir, "logs", "audit.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as AuditEvent);
}

const sandboxFile = (ctx: BrandedContext) =>
  join(ctx.stateDir, "credentials-metadata", "sandbox.json");

function scan(directory: string, value: string): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      // The opted-in plaintext file store is where the secret belongs.
      if (statSync(child).isDirectory()) {
        if (name !== "secrets") visit(child);
      } else if (readFileSync(child, "latin1").includes(value))
        hits.push(child);
    }
  };
  visit(directory);
  return hits;
}

describe("sandbox login", () => {
  it("reads the first line of piped stdin, stores it for the signed-in user, and prints nothing secret", async () => {
    const { ctx, out, err, store } = context();
    await signIn(ctx);
    pipe(`${SECRET}\nsecond-line-ignored\n`);
    await runSandbox(ctx, ["login"]);
    expect((await store.get("piship:acmecode:sandbox#1"))?.reveal()).toBe(
      SECRET,
    );
    expect(out.join("\n")).toMatch(/^Sandbox API key stored in file/);
    expect(`${out.join("\n")}${err.join("\n")}`).not.toContain(SECRET);
    // The file store opt-in is called out, as for login.
    expect(err.join("\n")).toMatch(/plaintext file fallback/);
    const [event] = auditEvents(ctx).filter(
      (item) => item.event === "credential.acquire",
    );
    expect(event).toMatchObject({
      user: expect.stringMatching(/#.+/),
      detail: { purpose: "sandbox", source: "stored", kind: "api_key" },
    });
    expect(event?.detail).not.toHaveProperty("mode");
    const log = readFileSync(join(ctx.stateDir, "logs", "audit.jsonl"), "utf8");
    for (const value of [SECRET, "sandbox-api.test.invalid", "8443"])
      expect(log).not.toContain(value);
    expect(scan(ctx.stateDir, SECRET)).toEqual([]);
  });

  it("prompts on a TTY with no echo: readline gets no output stream and the prompt goes to stderr", async () => {
    const { ctx, out, store } = context();
    await signIn(ctx);
    const stream = new Readable({ read() {} }) as Readable & {
      isTTY?: boolean;
    };
    stream.isTTY = true;
    vi.spyOn(process, "stdin", "get").mockReturnValue(
      stream as unknown as typeof process.stdin,
    );
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const stdout = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    tty.answer = SECRET;
    await runSandbox(ctx, ["login"]);
    expect(tty.options).toHaveLength(1);
    expect(tty.options[0]).toMatchObject({ terminal: true });
    expect(tty.options[0]?.output).toBeUndefined();
    expect(stderr.mock.calls.map(([chunk]) => String(chunk)).join("")).toBe(
      "Sandbox API key: \n",
    );
    expect(stdout).not.toHaveBeenCalled();
    expect(out.join("\n")).not.toContain(SECRET);
    expect((await store.get("piship:acmecode:sandbox#1"))?.reveal()).toBe(
      SECRET,
    );
  });

  it.each([
    ["Ctrl-C", "SIGINT"],
    ["Ctrl-D", "close"],
  ] as const)(
    "fails with no lock left when %s cancels the prompt",
    async (_key, event) => {
      const { ctx } = context();
      await signIn(ctx);
      const stream = new Readable({ read() {} }) as Readable & {
        isTTY?: boolean;
      };
      stream.isTTY = true;
      vi.spyOn(process, "stdin", "get").mockReturnValue(
        stream as unknown as typeof process.stdin,
      );
      vi.spyOn(process.stderr, "write").mockImplementation(() => true);
      tty.cancel = event;
      await expect(runSandbox(ctx, ["login"])).rejects.toMatchObject({
        code: "CREDENTIAL_REQUIRED",
      });
      expect(existsSync(sandboxFile(ctx))).toBe(false);
      expect(
        readdirSync(ctx.stateDir, { recursive: true }).filter((name) =>
          String(name).endsWith(".lock"),
        ),
      ).toEqual([]);
    },
  );

  it("fails at the end of a piped stdin with nothing on it, and reads a line from a pipe left open", async () => {
    const { ctx, store } = context();
    await signIn(ctx);
    const stderr = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    pipe("");
    await expect(runSandbox(ctx, ["login"])).rejects.toMatchObject({
      code: "CREDENTIAL_REQUIRED",
    });
    expect(existsSync(sandboxFile(ctx))).toBe(false);
    // A pipe that is never closed after the line still completes the login.
    const open = new Readable({ read() {} }) as Readable & { isTTY?: boolean };
    open.push(`${SECRET}\n`);
    vi.spyOn(process, "stdin", "get").mockReturnValue(
      open as unknown as typeof process.stdin,
    );
    await runSandbox(ctx, ["login"]);
    expect((await store.get("piship:acmecode:sandbox#1"))?.reveal()).toBe(
      SECRET,
    );
    // The prompt is on stderr for a pipe too, never the secret.
    const written = stderr.mock.calls.map(([chunk]) => String(chunk)).join("");
    expect(written).toContain("Sandbox API key: ");
    expect(written).not.toContain(SECRET);
  });

  it("takes no secret from argv or the environment", async () => {
    const { ctx, store } = context();
    await signIn(ctx);
    const argv = "fake-argv-secret-0001";
    const error = await runSandbox(ctx, ["login", "--secret", argv]).catch(
      (caught: unknown) => caught,
    );
    expect(error).toMatchObject({ code: "CONFIG_INVALID" });
    expect(String((error as Error).message)).not.toContain(argv);
    expect(existsSync(sandboxFile(ctx))).toBe(false);
    process.env.PISHIP_SANDBOX_API_KEY = "fake-env-secret-0001";
    process.env.PISHIP_SANDBOX_CREDENTIAL = "fake-env-secret-0002";
    pipe(`${SECRET}\n`);
    await runSandbox(ctx, ["login"]);
    expect((await store.get("piship:acmecode:sandbox#1"))?.reveal()).toBe(
      SECRET,
    );
  });

  it("stores nothing for a malformed entry", async () => {
    const { ctx } = context();
    await signIn(ctx);
    pipe("has a space\n");
    await expect(runSandbox(ctx, ["login"])).rejects.toMatchObject({
      code: "CREDENTIAL_ACQUIRE_FAILED",
    });
    expect(existsSync(sandboxFile(ctx))).toBe(false);
  });

  it("refuses a distribution without sandbox.credential: stored", async () => {
    for (const sandbox of [null, { credential: "runtime" }]) {
      const { ctx } = context(sandbox as Partial<SandboxConfig> | null);
      pipe(`${SECRET}\n`);
      await expect(runSandbox(ctx, ["login"])).rejects.toMatchObject({
        code: "POLICY_DENIED",
      });
      expect(existsSync(sandboxFile(ctx))).toBe(false);
    }
  });

  it("refuses an unset endpoint variable, naming it", async () => {
    const { ctx } = context();
    await signIn(ctx);
    delete process.env.ACMECODE_SANDBOX_URL;
    pipe(`${SECRET}\n`);
    const error = (await runSandbox(ctx, ["login"]).catch(
      (caught: unknown) => caught,
    )) as PiShipError;
    expect(error.code).toBe("SANDBOX_UNAVAILABLE");
    expect(error.userAction).toMatch(/ACMECODE_SANDBOX_URL/);
    expect(existsSync(sandboxFile(ctx))).toBe(false);
  });

  it("requires a signed-in user when identity is configured", async () => {
    const { ctx } = context();
    pipe(`${SECRET}\n`);
    await expect(runSandbox(ctx, ["login"])).rejects.toMatchObject({
      code: "IDENTITY_REQUIRED",
    });
    expect(existsSync(sandboxFile(ctx))).toBe(false);
  });
});

describe("sandbox logout and logout", () => {
  it("sandbox logout deletes it, confirmed, and audits the revocation", async () => {
    const { ctx, out, store } = context();
    await signIn(ctx);
    pipe(`${SECRET}\n`);
    await runSandbox(ctx, ["login"]);
    // Works even when the endpoint variable is gone.
    delete process.env.ACMECODE_SANDBOX_URL;
    await runSandbox(ctx, ["logout"]);
    expect(out.at(-1)).toBe("The sandbox credential was deleted.");
    expect(existsSync(sandboxFile(ctx))).toBe(false);
    expect(await store.get("piship:acmecode:sandbox#1")).toBeNull();
    expect(
      auditEvents(ctx).find((event) => event.event === "credential.revoke"),
    ).toMatchObject({
      detail: { purpose: "sandbox", reason: "logout" },
    });
    await runSandbox(ctx, ["logout"]);
    expect(out.at(-1)).toBe("No sandbox credential is stored.");
  });

  it("logout deletes the sandbox credential too", async () => {
    const { ctx, out, store } = context();
    await signIn(ctx);
    pipe(`${SECRET}\n`);
    await runSandbox(ctx, ["login"]);
    await runLogout(ctx);
    expect(out.at(-1)).toMatch(/^Signed out of /);
    expect(existsSync(sandboxFile(ctx))).toBe(false);
    expect(await store.get("piship:acmecode:sandbox#1")).toBeNull();
    const revoke = auditEvents(ctx).filter(
      (event) =>
        event.event === "credential.revoke" &&
        event.detail?.purpose === "sandbox",
    );
    expect(revoke).toHaveLength(1);
    expect(revoke[0]?.detail).not.toHaveProperty("mode");
    expect(scan(ctx.stateDir, SECRET)).toEqual([]);
  });
});
