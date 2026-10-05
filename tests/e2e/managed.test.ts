import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
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
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";

// Deterministic CI evidence only: the local identity, broker, and gateway are
// fixtures. They prove PiShip's contracts, not a live identity provider or
// gateway integration.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const temporary: string[] = [];
const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

type Services = Awaited<ReturnType<typeof startLocalServices>>;
interface Result {
  status: number | null;
  stdout: string;
  stderr: string;
}

function launcher(artifact: string, command: string) {
  return join(
    artifact,
    "bin",
    process.platform === "win32" ? `${command}.cmd` : command,
  );
}

/** Run a branded command; acts as the browser for any printed sign-in URL. */
function branded(
  command: string,
  args: string[],
  options: {
    cwd: string;
    env: NodeJS.ProcessEnv;
    services?: Services;
    input?: string;
  },
): Promise<Result> {
  return new Promise((resolve) => {
    const child =
      process.platform === "win32"
        ? spawn(
            "cmd.exe",
            ["/d", "/s", "/c", `call "${command}" ${args.join(" ")}`],
            {
              cwd: options.cwd,
              env: options.env,
              windowsVerbatimArguments: true,
            },
          )
        : spawn(command, args, { cwd: options.cwd, env: options.env });
    let stdout = "";
    let stderr = "";
    let approved = false;
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      const match = /(http:\/\/127\.0\.0\.1:\d+\/idp\/authorize\S+)/.exec(
        stderr,
      );
      if (match?.[1] && options.services && !approved) {
        approved = true;
        void options.services.approve(match[1]);
      }
    });
    child.stdin.end(options.input ?? "");
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

function scan(directory: string, secrets: readonly string[]): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) {
        // The explicitly opted-in file store is where secrets belong; it is
        // checked separately to be empty after logout.
        if (name !== "node_modules" && name !== "secrets") visit(child);
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

function prepare(example: string, patch: (source: string) => string) {
  const temp = mkdtempSync(join(tmpdir(), "piship-managed-e2e-"));
  temporary.push(temp);
  const directory = join(temp, "distribution");
  cpSync(join(root, "examples", example), directory, { recursive: true });
  const manifest = join(directory, "piship.yaml");
  let source = readFileSync(manifest, "utf8");
  // Windows has no sandbox adapter, so a required sandbox refuses to launch
  // there (covered by the governance E2E); this flow tests managed access.
  if (process.platform === "win32")
    source = source.replace(
      "  required: true\n  filesystem:",
      "  required: false\n  filesystem:",
    );
  writeFileSync(manifest, patch(source));
  const cli = (env: NodeJS.ProcessEnv, ...args: string[]) =>
    spawnSync(process.execPath, [bin, ...args], {
      cwd: temp,
      env,
      encoding: "utf8",
    });
  return { temp, directory, manifest, cli };
}

describe("managed distribution (local fixtures)", () => {
  it("initializes, locks, builds, logs in, enforces policy, resumes, and logs out", async () => {
    const services: Services = await startLocalServices();
    closers.push(() => services.close());
    const { temp, manifest, cli } = prepare("demo-company", (source) =>
      source
        // CI runners may lack a platform secret service; this copy explicitly
        // opts in to the diagnosed plaintext fallback. The demo uses system storage.
        .replace(
          "provider: system",
          "provider: file\n    acknowledgePlaintext: true",
        )
        .replace("127.0.0.1:8765", "127.0.0.1")
        // --smoke-model runs the demo extension's tool; Plan mode (the demo's
        // default) refuses every tool but read and ask_user.
        .replace("defaultMode: plan", "defaultMode: build"),
    );
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...services.env(),
      PISHIP_STATE_HOME: join(temp, "state"),
      PISHIP_NO_BROWSER: "1",
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
      OPENAI_API_KEY: "sk-ambient-personal-key-e2e",
      ANTHROPIC_API_KEY: "sk-ant-ambient-personal-key-e2e",
    };
    delete env.PISHIP_BUILD_INPUT;

    // Fresh managed profile from init.
    const fresh = join(temp, "fresh-agent");
    expect(cli(env, "init", fresh, "--managed").status).toBe(0);
    const freshValidate = cli(env, "validate", join(fresh, "piship.yaml"));
    expect(freshValidate.status, freshValidate.stderr).toBe(0);
    expect(freshValidate.stdout).toContain(
      "Schema piship/v1alpha6, mode managed.",
    );
    expect(cli(env, "lock", join(fresh, "piship.yaml")).status).toBe(0);
    const freshLock = readFileSync(join(fresh, "piship.lock"), "utf8");
    expect(freshLock).toContain('"schema": "piship-lock/v1alpha6"');
    expect(freshLock).toContain(`\${FRESH_AGENT_LLM_GATEWAY_URL}`);

    // Demo company: lock records templates only, never resolved endpoints or secrets.
    expect(cli(env, "validate", manifest).status).toBe(0);
    expect(cli(env, "lock", manifest).status).toBe(0);
    const lock = readFileSync(
      join(temp, "distribution", "piship.lock"),
      "utf8",
    );
    expect(lock).toContain(`\${ACMECODE_LLM_GATEWAY_URL}`);
    expect(lock).not.toContain(services.base);
    expect(lock).toContain("resources/extensions/enterprise-context/index.ts");
    const built = cli(env, "build", manifest);
    expect(built.status, built.stderr).toBe(0);
    const artifact = join(temp, "dist", "acmecode");
    const command = launcher(artifact, "acmecode");
    const run = (args: string[], input?: string) =>
      branded(command, args, {
        cwd: temp,
        env,
        services,
        ...(input ? { input } : {}),
      });

    const version = await run(["version"]);
    expect(version.stdout).toContain("AcmeCode 1.0.0");
    const before = await run(["--smoke"]);
    expect(before.status).toBe(1);
    expect(before.stderr).toContain("IDENTITY_REQUIRED");
    expect(before.stderr).toContain("acmecode login");

    const login = await run(["login"]);
    expect(login.status, login.stderr).toBe(0);
    expect(login.stdout).toContain("Signed in as Demo Developer");
    expect(login.stderr).toContain("code_challenge_method=S256");
    expect(login.stderr).toContain("plaintext file fallback");

    const first = await run(["--smoke"]);
    expect(first.status, first.stderr).toBe(0);
    const firstResult = JSON.parse(first.stdout);
    expect(firstResult).toMatchObject({
      resumed: false,
      skills: ["release-notes", "acme-review"],
      extensions: 1,
      access: {
        mode: "managed",
        identity: { subject: "demo-user-1" },
        credential: { mode: "http-broker", credentialId: "vk_demo_1" },
        selectedModel: "acmecode/acme/coder",
        allowedModels: ["acme/coder", "acme/general"],
      },
    });
    expect(firstResult.access.removedEnvironment).toEqual(
      expect.arrayContaining(["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]),
    );
    // One managed launch leaves metadata-only operational metrics.
    const metricsText = readFileSync(
      join(temp, "state", "acmecode", "logs", "metrics.json"),
      "utf8",
    );
    const metrics = JSON.parse(metricsText);
    expect(metrics).toMatchObject({
      schema: "piship-metrics/v1",
      versions: {
        distribution: "1.0.0",
        pi: "1.0.3",
        node: process.versions.node,
      },
      latency: {
        identity: { count: expect.any(Number) },
        "credential.acquire": { count: 1 },
      },
      gateway: { reachable: true, reachableCount: expect.any(Number) },
      modelCatalog: { models: 3 },
      startupLatency: { count: 1 },
      startupFailures: {},
    });
    expect(metrics.versions.piship).toMatch(/^\d+\.\d+\.\d+/);
    // Load failures are counted only when one happens.
    expect(metrics.resourceLoadFailures).toBeUndefined();
    expect(metrics.providerLoadFailures).toBeUndefined();
    expect(metricsText).not.toContain(services.base);
    expect(metricsText).not.toContain("demo-user-1");
    expect(metricsText).not.toMatch(/sk-demo|demo-at-|demo-rt-/);
    const resumed = JSON.parse((await run(["--smoke"])).stdout);
    expect(resumed).toMatchObject({
      sessionId: firstResult.sessionId,
      resumed: true,
    });

    // Real Pi request through the managed gateway, including a tool call served by
    // the demo extension from the token-free enterprise context.
    services.knobs.gatewayMode = "tool";
    const request = await run(["--smoke-model"]);
    expect(request.status, request.stderr).toBe(0);
    const requestResult = JSON.parse(request.stdout);
    expect(requestResult.modelRequest).toMatchObject({
      model: "acmecode/acme/coder",
      stopReason: "stop",
      toolResults: 1,
    });
    expect(requestResult.modelRequest.text).toContain(
      '"subject":"demo-user-1"',
    );
    expect(requestResult.modelRequest.text).toContain(
      '"selectedModel":"acme/coder"',
    );
    const chats = services.state.requests.filter((item: { path: string }) =>
      item.path.endsWith("/chat/completions"),
    );
    expect(chats.length).toBe(2);
    expect(JSON.stringify(services.state.requests)).not.toContain("sk-ambient");
    expect(JSON.stringify(services.state.requests)).not.toContain(
      "api.openai.com",
    );

    // Model policy at startup and selection.
    const unentitled = await run(["--model", "acme/review", "--smoke"]);
    expect(unentitled.stderr).toContain("MODEL_UNAVAILABLE");
    const personalModel = await run(["--model", "openai/gpt-4o", "--smoke"]);
    expect(personalModel.status).toBe(1);
    expect(personalModel.stderr).toContain("MODEL_DENIED");

    // Configuration precedence and explanation.
    expect((await run(["config", "set", "theme", "light"])).stderr).toContain(
      "enforced by the distribution",
    );
    expect(
      (
        await run([
          "config",
          "set",
          "inference.baseUrl",
          "https://public.example/v1",
        ])
      ).stderr,
    ).toContain("security-sensitive");
    expect(
      (await run(["config", "set", "model", "openai/gpt-4o"])).stderr,
    ).toContain("MODEL_DENIED");
    expect((await run(["config", "set", "model", "acme/general"])).status).toBe(
      0,
    );
    const selected = JSON.parse((await run(["--smoke"])).stdout);
    expect(selected.access.selectedModel).toBe("acmecode/acme/general");
    expect(selected.resumed).toBe(true);
    const explain = await run(["config", "explain"]);
    expect(explain.status, explain.stderr).toBe(0);
    expect(explain.stdout).toMatch(
      /model\s+"acme\/general"\s+\[user-preference/,
    );
    expect(explain.stdout).toMatch(
      /theme\s+"dark"\s+\[distribution-enforced\]/,
    );
    expect(explain.stdout).toContain("plaintext fallback");
    const cliExplain = cli(env, "config", "explain", artifact);
    expect(cliExplain.status, cliExplain.stderr).toBe(0);
    expect(cliExplain.stdout).toContain("models.allowed");

    const doctor = await run(["doctor"]);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).toMatch(
      /Gateway\n(?:.*\n)*? {2}✓ gateway\s+reachable/,
    );
    expect(doctor.stdout).toMatch(
      /Identity\n {2}✓ mode\s+oidc\n {2}✓ session\s+signed in\n {2}✓ issuer\s+\S+ answers/,
    );
    expect(doctor.stdout).toMatch(
      /Secret Store\n {2}! backend\s+restricted plaintext file/,
    );
    expect(doctor.stdout).toMatch(
      /✓ outbound\s+private-only: declared hosts only/,
    );
    expect(doctor.stdout).toMatch(/Network\n(?:.*\n)*? {2}✓ proxy\s+/);
    expect(doctor.stdout).toMatch(
      /✓ agent commands\s+approved network variables only/,
    );
    expect(doctor.stdout).toMatch(
      process.platform === "win32"
        ? /Workspace\n {2}- consistency\s+none: no sandbox is enforced/
        : /Workspace\n {2}✓ consistency\s+shared \(commands run on this host's files\)/,
    );
    expect(doctor.stdout).toMatch(/Audit\n {2}. state\s+/);
    expect(doctor.stdout).toMatch(/Release\n {2}. release\s+/);
    // The fixture lives in this process, so network-using CLI calls must not block it.
    const cliDoctor = await new Promise<Result>((resolve) => {
      const child = spawn(process.execPath, [bin, "doctor", artifact], {
        cwd: temp,
        env,
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("close", (status) => resolve({ status, stdout, stderr }));
    });
    expect(cliDoctor.status, cliDoctor.stdout + cliDoctor.stderr).toBe(0);
    const inspected = JSON.parse(
      cli(env, "inspect", artifact, "--json").stdout,
    );
    expect(inspected.access.credential.provider).toBe("http-broker");

    // A gateway-rejected runtime credential is renewed once automatically.
    services.knobs.gatewayMode = "text";
    for (const entry of services.state.credentials.values())
      entry.revoked = true;
    const renewed = await run(["--smoke-model"]);
    expect(renewed.status, renewed.stderr).toBe(0);
    const renewedResult = JSON.parse(renewed.stdout);
    expect(renewedResult.access.credential.credentialId).toBe("vk_demo_2");
    expect(renewedResult.access.notices).toContain(
      "The gateway rejected the stored credential; a new credential was acquired",
    );
    // If renewal cannot help (the broker is down), the launch fails visibly.
    for (const entry of services.state.credentials.values())
      entry.revoked = true;
    services.knobs.brokerStatus = 503;
    const rejected = await run(["--smoke"]);
    expect(rejected.status).toBe(1);
    // The broker outage is what stops the renewal: retryable, not "log in".
    expect(rejected.stderr).toContain("CREDENTIAL_ACQUIRE_FAILED");
    expect(rejected.stderr).toContain("could not be renewed");
    expect(rejected.stderr).not.toMatch(/run \S+ login/i);
    services.knobs.brokerStatus = undefined;
    const recovered = await run(["--smoke"]);
    expect(recovered.status, recovered.stderr).toBe(0);
    expect(JSON.parse(recovered.stdout).access.credential.credentialId).toBe(
      "vk_demo_3",
    );

    // Secrets never reach manifest, lock, payload metadata, state, sessions, or output.
    const secrets = [
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    ];
    expect(secrets.length).toBeGreaterThan(3);
    const outputs = [first, request, explain, doctor, rejected, renewed, login]
      .map((item) => item.stdout + item.stderr)
      .join("\n");
    for (const secret of secrets) expect(outputs).not.toContain(secret);
    expect(scan(join(temp, "state"), secrets)).toEqual([]);
    expect(scan(join(temp, "distribution"), secrets)).toEqual([]);
    expect(scan(join(artifact, "metadata"), secrets)).toEqual([]);
    expect(readFileSync(join(artifact, "piship.lock"), "utf8")).not.toMatch(
      /sk-demo|demo-at-|demo-rt-/,
    );

    // Logout revokes and clears credentials but keeps sessions.
    const logout = await run(["logout"]);
    expect(logout.status, logout.stderr).toBe(0);
    expect(services.state.revokedCredentials).toContain("vk_demo_3");
    expect(
      existsSync(join(temp, "state", "acmecode", "sessions", "acceptance")),
    ).toBe(true);
    expect(readdirSync(join(temp, "state", "acmecode", "secrets"))).toEqual([]);
    expect((await run(["--smoke"])).stderr).toContain("IDENTITY_REQUIRED");

    // Unavailable gateway, missing configuration, and disabled TLS fail visibly.
    await run(["login"]);
    await services.close();
    const outage = await run(["--smoke"]);
    expect(outage.status).toBe(1);
    expect(outage.stderr).toMatch(/GATEWAY_UNREACHABLE|CREDENTIAL/);
    const missing = await branded(command, ["--smoke"], {
      cwd: temp,
      env: { ...env, ACMECODE_LLM_GATEWAY_URL: "" },
    });
    expect(missing.stderr).toContain("ACMECODE_LLM_GATEWAY_URL");
    const insecure = await branded(command, ["--smoke"], {
      cwd: temp,
      env: { ...env, NODE_TLS_REJECT_UNAUTHORIZED: "0" },
    });
    expect(insecure.status).toBe(1);
    expect(insecure.stderr).toContain("TLS_POLICY_VIOLATION");
    // Doctor reports the same refusal instead of passing after sanitizing.
    const insecureDoctor = await branded(command, ["doctor"], {
      cwd: temp,
      env: { ...env, NODE_TLS_REJECT_UNAUTHORIZED: "0" },
    });
    expect(insecureDoctor.status).toBe(1);
    expect(insecureDoctor.stdout).toMatch(
      /✗ TLS verification\s+DISABLED in environment/,
    );
    expect(insecureDoctor.stdout).toContain("TLS_POLICY_VIOLATION");
  }, 600000);
});
