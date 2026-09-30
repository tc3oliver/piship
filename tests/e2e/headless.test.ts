import { spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
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
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher, type Result } from "../helpers/distribution.js";

// Headless and workload path on the local fixtures: the AcmeCode demo with
// its identity replaced by a workload identity adapter. No step signs in
// through a browser, nothing in the process approves an authorization page,
// and no browser opener may run. The fixture broker, gateway, and token
// store are test infrastructure; this proves PiShip's contracts, not a live
// workload identity provider.

const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const windows = process.platform === "win32";
const temporary: string[] = [];
const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

type Services = Awaited<ReturnType<typeof startLocalServices>>;

// A workload identity adapter as a distribution author would ship it: it
// reads the token the workload platform provides (here a token document at a
// path named by a non-secret variable, as a projected service account token
// is), and never involves a person. PiShip removes credential-named
// environment variables before adapters load, so a token in an environment
// variable would not reach it.
const WORKLOAD_ADAPTER = `import { readFileSync } from "node:fs";

export default (context) => ({
  kind: "acme-workload",
  interactive: false,
  async login() {
    const path = process.env.ACMECODE_WORKLOAD_IDENTITY_PATH;
    if (!path) throw new Error("ACMECODE_WORKLOAD_IDENTITY_PATH is not set");
    const document = JSON.parse(readFileSync(path, "utf8"));
    // Test hook: reach a host the network policy does not declare.
    if (document.probe) await context.fetch(document.probe);
    return {
      issuer: document.issuer,
      subject: document.subject,
      accessToken: document.token,
      ...(document.expiresAt ? { expiresAt: document.expiresAt } : {}),
      claims: { iss: document.issuer, sub: document.subject },
    };
  },
});
`;

const WORKLOAD_ISSUER = "https://workload.acme.example";

// Obviously fake personal credentials that must never reach the managed run.
const PERSONAL = {
  envOpenAI: "sk-personal-sentinel-env-openai-0000",
  envAnthropic: "sk-ant-personal-sentinel-env-0000",
  envPi: "pi-personal-sentinel-env-0000",
  authJson: "sk-personal-sentinel-auth-json-0000",
  otherDistribution: "sk-personal-sentinel-mypi-auth-0000",
};

function scan(directory: string, secrets: readonly string[]): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    if (!existsSync(path)) return;
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) {
        if (name !== "node_modules") visit(child);
      } else {
        const text = readFileSync(child, "latin1");
        for (const [index, secret] of secrets.entries())
          if (secret && text.includes(secret))
            hits.push(`${child} contains protected secret #${index + 1}`);
      }
    }
  };
  visit(directory);
  return hits;
}

/**
 * Tripwires named like the browser openers `login` would start. They record
 * any call; they approve nothing. POSIX only: Windows starts `rundll32`,
 * which is resolved from the system directory.
 */
function browserTripwires(directory: string, log: string): void {
  mkdirSync(directory, { recursive: true });
  for (const name of [
    "open",
    "xdg-open",
    "x-www-browser",
    "sensible-browser",
    "wslview",
  ]) {
    const path = join(directory, name);
    writeFileSync(
      path,
      `#!/bin/sh\necho "$0 $*" >> ${JSON.stringify(log)}\nexit 1\n`,
    );
    chmodSync(path, 0o755);
  }
}

describe("headless workload distribution (local fixtures)", () => {
  it("runs with no browser and no stored login, rotates and expires credentials, enforces managed policy, and inherits no personal credential", async () => {
    const services: Services = await startLocalServices();
    closers.push(() => services.close());
    const temp = mkdtempSync(join(tmpdir(), "piship-headless-e2e-"));
    temporary.push(temp);

    // The demo distribution with a workload identity adapter. Credentials
    // use the plaintext file store with the explicit acknowledgement: a
    // headless Linux runner has no Secret Service.
    const directory = join(temp, "distribution");
    cpSync(join(root, "examples", "demo-company"), directory, {
      recursive: true,
    });
    mkdirSync(join(directory, "adapters"));
    writeFileSync(
      join(directory, "adapters", "workload-identity.mjs"),
      WORKLOAD_ADAPTER,
    );
    const manifest = join(directory, "piship.yaml");
    let source = readFileSync(manifest, "utf8");
    const identityBlock = /^identity:\n(?: {2}.*\n)+/m;
    expect(source).toMatch(identityBlock);
    source = source
      .replace(
        identityBlock,
        "identity:\n  mode: adapter\n  adapter: ./adapters/workload-identity.mjs\n",
      )
      .replace("  - ACMECODE_OIDC_ISSUER\n  - ACMECODE_OIDC_CLIENT_ID\n", "")
      .replace(
        "provider: system",
        "provider: file\n    acknowledgePlaintext: true",
      );
    if (windows)
      source = source.replace(
        "  required: true\n  filesystem:",
        "  required: false\n  filesystem:",
      );
    writeFileSync(manifest, source);

    const home = join(temp, "home");
    const stateHome = join(temp, "state");
    // A personal Pi sign-in and a personal pi-native distribution on the
    // same machine, both holding credentials.
    mkdirSync(join(home, ".pi", "agent"), { recursive: true });
    writeFileSync(
      join(home, ".pi", "agent", "auth.json"),
      JSON.stringify({
        openai: { type: "api_key", key: PERSONAL.authJson },
        anthropic: { type: "api_key", key: PERSONAL.authJson },
      }),
    );
    mkdirSync(join(stateHome, "mypi", "agent"), { recursive: true });
    writeFileSync(
      join(stateHome, "mypi", "agent", "auth.json"),
      JSON.stringify({
        openai: { type: "api_key", key: PERSONAL.otherDistribution },
      }),
    );
    const tripwire = join(temp, "tripwire");
    const tripwireLog = join(temp, "browser-opened.log");
    if (!windows) browserTripwires(tripwire, tripwireLog);

    const identityPath = join(temp, "workload", "identity.json");
    mkdirSync(join(temp, "workload"));
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...services.env(),
      ACMECODE_WORKLOAD_IDENTITY_PATH: identityPath,
      PISHIP_STATE_HOME: stateHome,
      HOME: home,
      USERPROFILE: home,
      PATH: windows
        ? process.env.PATH
        : `${tripwire}${delimiter}${process.env.PATH ?? ""}`,
      OPENAI_API_KEY: PERSONAL.envOpenAI,
      ANTHROPIC_API_KEY: PERSONAL.envAnthropic,
      PI_API_KEY: PERSONAL.envPi,
    };
    // Nothing suppresses or replaces the browser opener.
    delete env.PISHIP_NO_BROWSER;
    delete env.PISHIP_BUILD_INPUT;
    delete env.ACMECODE_OIDC_ISSUER;
    delete env.ACMECODE_OIDC_CLIENT_ID;

    const cli = (...args: string[]) =>
      spawnSync(process.execPath, [bin, ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
    const validated = cli("validate", manifest);
    expect(validated.status, validated.stderr).toBe(0);
    const locked = cli("lock", manifest);
    expect(locked.status, locked.stderr).toBe(0);
    expect(readFileSync(join(directory, "piship.lock"), "utf8")).toContain(
      "adapters/workload-identity.mjs",
    );
    const built = cli("build", manifest);
    expect(built.status, built.stderr).toBe(0);
    const command = launcher(join(temp, "dist", "acmecode"), "acmecode");
    // No `approve`: nothing in this process acts as a browser.
    const run = (args: string[]): Promise<Result> =>
      branded(command, args, { cwd: temp, env });
    const smoke = async (args: string[] = []) => {
      const result = await run(["--smoke", ...args]);
      expect(result.status, result.stderr).toBe(0);
      return JSON.parse(result.stdout);
    };

    /** The workload platform issues a token and hands it to the job. */
    let minted = 0;
    const issue = (
      subject: string,
      extra: Record<string, unknown> = {},
    ): string => {
      minted += 1;
      const token = `demo-wt-headless-${minted}-${subject}`;
      services.state.accessTokens.set(token, {
        subject,
        expires: Math.floor(Date.now() / 1000) + 3600,
      });
      writeFileSync(
        identityPath,
        JSON.stringify({
          issuer: WORKLOAD_ISSUER,
          subject,
          token,
          // A workload session must say when it expires.
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
          ...extra,
        }),
      );
      return token;
    };
    const brokerCalls = () =>
      services.state.requests.filter(
        (item: { path: string }) => item.path === "/broker/v1/llm-credential",
      );
    const gatewayCalls = () =>
      services.state.requests.filter((item: { path: string }) =>
        item.path.startsWith("/gateway/"),
      );
    const credentialSecret = (id: string): string =>
      [...services.state.credentials].find(
        ([, entry]: [string, { id: string }]) => entry.id === id,
      )?.[0] ?? "";
    const acmeState = join(stateHome, "acmecode");

    // 1. Without a workload identity the launch fails closed. It never
    //    falls back to the personal credentials around it.
    const missing = await run(["--smoke"]);
    expect(missing.status).toBe(1);
    // A coded error; the adapter's own message (here a file error naming
    // the token path) is never passed on, since it may quote the token.
    expect(missing.stderr).toContain("IDENTITY_INVALID");
    expect(missing.stderr).toContain(
      "The workload identity adapter could not obtain a session",
    );
    expect(missing.stderr).not.toMatch(/ENOENT|no such file/);
    expect(missing.stderr).not.toContain(identityPath);
    expect(gatewayCalls()).toEqual([]);
    expect(brokerCalls()).toEqual([]);

    // 2. First headless run: no login, no browser, a scoped credential.
    const firstToken = issue("svc-build-1");
    const first = await smoke();
    expect(first.access).toMatchObject({
      mode: "managed",
      identity: { subject: "svc-build-1", issuer: WORKLOAD_ISSUER },
      credential: { mode: "http-broker", credentialId: "vk_demo_1" },
      selectedModel: "acmecode/acme/coder",
      allowedModels: ["acme/coder", "acme/general"],
    });
    expect(first.access.removedEnvironment).toEqual(
      expect.arrayContaining([
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "PI_API_KEY",
      ]),
    );
    expect(brokerCalls().at(-1)?.authorization).toBe(`Bearer ${firstToken}`);
    // The workload session is never stored.
    expect(existsSync(join(acmeState, "identity", "session.json"))).toBe(false);
    expect(scan(stateHome, [firstToken])).toEqual([]);
    expect(
      JSON.parse(
        readFileSync(
          join(acmeState, "credentials-metadata", "inference.json"),
          "utf8",
        ),
      ).principal,
    ).toEqual({ issuer: WORKLOAD_ISSUER, subject: "svc-build-1" });

    // A real model request through the gateway with the broker credential.
    const request = await run(["--smoke-model"]);
    expect(request.status, request.stderr).toBe(0);
    expect(JSON.parse(request.stdout).modelRequest).toMatchObject({
      model: "acmecode/acme/coder",
      stopReason: "stop",
    });
    const chat = services.state.requests
      .filter((item: { path: string }) =>
        item.path.endsWith("/chat/completions"),
      )
      .at(-1);
    expect(chat?.authorization).toBe(`Bearer ${credentialSecret("vk_demo_1")}`);

    // doctor sees a healthy workload run: no stored session, none needed.
    const doctor = await run(["doctor"]);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).toMatch(
      /Identity\n {2}✓ mode\s+adapter\n {2}✓ session\s+workload identity, obtained per run/,
    );
    expect(doctor.stdout).toMatch(
      /Secret Store\n(?:.*\n)*? {2}✓ revocation retries\s+none pending/,
    );
    expect(doctor.stdout + doctor.stderr).not.toContain(firstToken);

    // 3. Managed policy stays enforced: model allowlist and entitlement,
    //    and the network policy for the adapter's own requests.
    const personalModel = await run(["--model", "openai/gpt-4o", "--smoke"]);
    expect(personalModel.status).toBe(1);
    expect(personalModel.stderr).toContain("MODEL_DENIED");
    const unentitled = await run(["--model", "acme/review", "--smoke"]);
    expect(unentitled.status).toBe(1);
    expect(unentitled.stderr).toContain("MODEL_UNAVAILABLE");
    issue("svc-build-1", { probe: "https://public.example/v1/models" });
    const before = services.state.requests.length;
    const denied = await run(["--smoke"]);
    expect(denied.status).toBe(1);
    expect(denied.stderr).toContain("NETWORK_DENIED");
    expect(services.state.requests.length).toBe(before);

    // 4. Rotation. The broker now issues short-lived credentials, so each
    //    run renews within refresh.beforeExpiry (5m), and the workload
    //    platform rotates its token, so renewals present the current one.
    //    `login` replaces the credential and needs no browser either.
    services.knobs.credentialTtl = 120;
    issue("svc-build-1");
    const login = await run(["login"]);
    expect(login.status, login.stderr).toBe(0);
    expect(login.stdout).toContain("Signed in as svc-build-1");
    expect(login.stderr).not.toContain("Open this URL");
    expect(existsSync(join(acmeState, "identity", "session.json"))).toBe(false);
    expect(services.state.revokedCredentials).toEqual(["vk_demo_1"]);
    const rotatedToken = issue("svc-build-1");
    const renewed = await smoke();
    expect(renewed.access.credential.credentialId).toBe("vk_demo_3");
    expect(brokerCalls().at(-1)?.authorization).toBe(`Bearer ${rotatedToken}`);
    const rotated = await smoke();
    expect(rotated.access.credential.credentialId).toBe("vk_demo_4");
    expect(rotated.access.identity.subject).toBe("svc-build-1");
    // Replaced generations leave no secret behind.
    expect(
      scan(stateHome, [
        credentialSecret("vk_demo_1"),
        credentialSecret("vk_demo_2"),
        credentialSecret("vk_demo_3"),
      ]),
    ).toEqual([]);

    // 5. Expiry. A credential past its expiry is never used: with the
    //    broker down the launch fails closed, and with a dead workload
    //    token it fails closed on the identity.
    services.knobs.credentialTtl = 2;
    expect((await smoke()).access.credential.credentialId).toBe("vk_demo_5");
    await new Promise((resolve) => setTimeout(resolve, 3500));
    services.knobs.brokerStatus = 503;
    const brokerDown = await run(["--smoke"]);
    expect(brokerDown.status).toBe(1);
    expect(brokerDown.stderr).toContain("CREDENTIAL_EXPIRED");
    services.knobs.brokerStatus = undefined;
    const deadToken = issue("svc-build-1");
    services.state.accessTokens.delete(deadToken);
    const expiredIdentity = await run(["--smoke"]);
    expect(expiredIdentity.status).toBe(1);
    expect(expiredIdentity.stderr).toContain("IDENTITY_EXPIRED");
    // The platform's next token recovers the run.
    services.knobs.credentialTtl = 3600;
    issue("svc-build-1");
    const recovered = await smoke();
    expect(recovered.access.credential.credentialId).toBe("vk_demo_6");

    // 6. The workload principal changes between runs: nothing of the
    //    previous one is used or left behind.
    const previousSecrets = [...services.state.credentials]
      .filter(
        ([, entry]: [string, { subject: string }]) =>
          entry.subject === "svc-build-1",
      )
      .map(([secret]: [string]) => secret);
    services.knobs.entitledModels = ["acme/coder"];
    issue("svc-deploy-2");
    const switched = await smoke();
    expect(switched.access).toMatchObject({
      identity: { subject: "svc-deploy-2" },
      credential: { credentialId: "vk_demo_7" },
      allowedModels: ["acme/coder"],
    });
    expect(services.state.revokedCredentials).toContain("vk_demo_6");
    expect(scan(stateHome, previousSecrets)).toEqual([]);

    // 7. No browser, no authorization page, no identity provider request,
    //    and no personal credential anywhere, in any run.
    expect(services.state.authorizations).toEqual([]);
    expect(
      services.state.requests.filter((item: { path: string }) =>
        item.path.startsWith("/idp/"),
      ),
    ).toEqual([]);
    if (!windows) expect(existsSync(tripwireLog)).toBe(false);
    const personal = Object.values(PERSONAL);
    expect(
      JSON.stringify(services.state.requests).match(
        /sentinel|api\.openai\.com|api\.anthropic\.com/,
      ),
    ).toBeNull();
    for (const item of gatewayCalls())
      expect(item.authorization).toMatch(/^Bearer sk-demo-/);
    expect(scan(acmeState, personal)).toEqual([]);
    expect(scan(join(temp, "dist"), personal)).toEqual([]);

    // Logout clears the workload's credential like a person's.
    const logout = await run(["logout"]);
    expect(logout.status, logout.stderr).toBe(0);
    expect(services.state.revokedCredentials).toContain("vk_demo_7");
    expect(
      scan(stateHome, [...services.state.credentials.keys()] as string[]),
    ).toEqual([]);
  }, 600000);
});
