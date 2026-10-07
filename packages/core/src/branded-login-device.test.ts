// `<command> login` for identity.oidc.flow: device_code against the
// deterministic fixture services: what it prints, when it opens a browser,
// and how Ctrl-C ends it. Not live evidence: no real identity provider.
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AccessManifest } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import type { BrandedContext } from "./branded/context.js";
import { deviceCodeMessage, runLogin } from "./branded/login.js";
import { resolveLock } from "./index.js";

const browser = vi.hoisted(() => ({ spawned: [] as string[][] }));
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (command: string, args: string[]) => {
      browser.spawned.push([command, ...args]);
      return { on: () => {}, unref: () => {} };
    },
  };
});

const DEMO = fileURLToPath(
  new URL("../../../examples/demo-company/piship.yaml", import.meta.url),
);

let temp: string;
let services: Awaited<ReturnType<typeof startLocalServices>>;
let savedEnv: NodeJS.ProcessEnv;
beforeEach(async () => {
  savedEnv = { ...process.env };
  temp = mkdtempSync(join(tmpdir(), "piship-branded-login-device-"));
  services = await startLocalServices();
  Object.assign(process.env, services.env());
  for (const name of [
    "PISHIP_NO_BROWSER",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
  ])
    delete process.env[name];
  browser.spawned.length = 0;
});
afterEach(async () => {
  process.env = savedEnv;
  const { Agent, setGlobalDispatcher } = await import("undici");
  setGlobalDispatcher(new Agent());
  await services.close();
  rmSync(temp, { recursive: true, force: true });
});

function context() {
  const lock = resolveLock(DEMO);
  const access = lock.access as AccessManifest;
  if (access.identity.mode !== "oidc")
    throw new Error("the demo signs in with OIDC");
  const { redirectUri: _redirect, ...oidc } = access.identity.oidc;
  const out: string[] = [];
  const err: string[] = [];
  const ctx: BrandedContext = {
    metadata: {
      ...lock,
      access: {
        ...access,
        identity: { mode: "oidc", oidc: { ...oidc, flow: "device_code" } },
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
  return { ctx, out, err };
}

/** Every file under `directory` that contains `value`. */
function scan(directory: string, value: string): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) visit(child);
      else if (readFileSync(child, "latin1").includes(value)) hits.push(child);
    }
  };
  visit(directory);
  return hits;
}

describe("login with identity.oidc.flow: device_code", () => {
  it("prints the URL, the code, the wait, and Ctrl-C, and no token", async () => {
    process.env.PISHIP_NO_BROWSER = "1";
    services.knobs.devicePolls = ["authorization_pending"];
    const { ctx, out, err } = context();
    await runLogin(ctx);
    const shown = err.join("\n");
    expect(shown).toContain(`${services.issuer}/device`);
    expect(shown).toContain("enter this code: DEMO-CODE");
    expect(shown).toContain("Waiting up to 5 minutes");
    expect(shown).toContain("Press Ctrl-C to cancel");
    expect(shown).not.toMatch(/redirect|Open this URL in your browser/);
    expect(out.join("\n")).toContain("Signed in as Demo Developer");
    // Neither the tokens nor the device code reach the terminal output.
    const secrets = [
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
      ...services.state.idTokens,
      ...services.state.devicePolls.map(
        (poll: { deviceCode: string }) => poll.deviceCode,
      ),
    ];
    expect(secrets.length).toBeGreaterThan(3);
    for (const secret of secrets) {
      expect(shown).not.toContain(secret);
      expect(out.join("\n")).not.toContain(secret);
    }
    // The one-time user code is shown to the person only: it is not written
    // to the state directory, the audit log included.
    expect(scan(join(temp, "state"), "DEMO-CODE")).toEqual([]);
  });

  it("opens no browser with PISHIP_NO_BROWSER=1 or in a remote shell, and prints either way", async () => {
    process.env.PISHIP_NO_BROWSER = "1";
    const first = context();
    await runLogin(first.ctx);
    expect(browser.spawned).toEqual([]);
    expect(first.err.join("\n")).toContain("DEMO-CODE");

    delete process.env.PISHIP_NO_BROWSER;
    process.env.SSH_CONNECTION = "10.0.0.2 52000 10.0.0.9 22";
    services.knobs.devicePolls = [];
    const second = context();
    await runLogin(second.ctx);
    expect(browser.spawned).toEqual([]);
    expect(second.err.join("\n")).toContain("DEMO-CODE");
    expect(second.err.join("\n")).not.toMatch(/ssh -N -L/);
  });

  it.each(["SSH_CLIENT", "SSH_TTY"])(
    "opens no browser when %s alone marks a remote shell",
    async (name) => {
      process.env[name] = "set";
      const { ctx, err } = context();
      await runLogin(ctx);
      expect(browser.spawned).toEqual([]);
      expect(err.join("\n")).toContain("DEMO-CODE");
    },
  );

  it("opens the verification URL, with the code in it when there is one, otherwise", async () => {
    services.knobs.deviceComplete = true;
    await runLogin(context().ctx);
    expect(browser.spawned).toHaveLength(1);
    expect(browser.spawned[0]?.at(-1)).toBe(
      `${services.issuer}/device?user_code=DEMO-CODE`,
    );
  });

  it("ends as a cancelled sign-in on Ctrl-C, and leaves no SIGINT handler", async () => {
    process.env.PISHIP_NO_BROWSER = "1";
    services.knobs.devicePolls = Array(50).fill("authorization_pending");
    const before = process.listenerCount("SIGINT");
    const { ctx, err } = context();
    const login = runLogin(ctx).catch((caught: unknown) => caught);
    while (!err.join("").includes("DEMO-CODE"))
      await new Promise((resolve) => setTimeout(resolve, 20));
    process.emit("SIGINT");
    expect(await login).toMatchObject({
      code: "IDENTITY_REQUIRED",
      message: "Sign-in was cancelled",
    });
    expect(process.listenerCount("SIGINT")).toBe(before);
  });

  describe("text from the identity provider", () => {
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the point.
    const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/;

    it("is stripped of control characters and cut short when printed", () => {
      const message = deviceCodeMessage({
        verificationUri: "https://login.example/\u001b[2Jdevice",
        userCode: "AB\rCD\u009b",
        verificationUriComplete: `https://login.example/${"a".repeat(3000)}`,
        expiresInSeconds: 300,
      });
      expect(message).not.toMatch(CONTROL);
      expect(message).toContain("https://login.example/[2Jdevice");
      expect(message).toContain("ABCD");
      expect(message.length).toBeLessThan(2500 * 2);
    });

    it.each([
      ["a file: URL", "deviceVerificationUri", "file:///etc/passwd"],
      [
        "a URL with credentials",
        "deviceVerificationUri",
        "https://user:secret@login.example/device",
      ],
      [
        "a URL with an escape sequence",
        "deviceVerificationUriComplete",
        "https://login.example/\u001b[31mdevice",
      ],
      ["a user code with an escape sequence", "deviceUserCode", "\u001b[2JAB"],
    ])(
      "is refused, with no browser and nothing printed, for %s",
      async (_name, knob, value) => {
        services.knobs[knob] = value;
        const { ctx, err } = context();
        await expect(runLogin(ctx)).rejects.toMatchObject({
          code: "IDENTITY_INVALID",
        });
        expect(browser.spawned).toEqual([]);
        const printed = err.join("\n");
        expect(printed).not.toMatch(CONTROL);
        expect(printed).not.toMatch(/file:|secret|login\.example/);
      },
    );
  });
});
