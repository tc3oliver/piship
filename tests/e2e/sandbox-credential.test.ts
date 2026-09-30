import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
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
import { kubernetesServer } from "../../packages/sandbox/src/testing/kubernetes-server.js";
import {
  closeMockServers,
  leaks,
} from "../../packages/sandbox/src/testing/mock-server.js";
import { branded, launcher, type Result } from "../helpers/distribution.js";

// The stored sandbox credential end to end: a remote sandbox service that
// requires a bearer token (a mock Kubernetes Agent Sandbox API and router),
// `sandbox login` over stdin, a governed launch whose agent runs bash in the
// remote sandbox, and the origin rule when the endpoint variable changes.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const temporary: string[] = [];
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  await closeMockServers();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

type Services = Awaited<ReturnType<typeof startLocalServices>>;
// An obvious fake; never a real token.
const TOKEN = "fake-sandbox-token-SENTINEL-e2e-0001";

function build(services: Services) {
  const temp = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-sandbox-credential-e2e-")),
  );
  temporary.push(temp);
  const directory = join(temp, "distribution");
  cpSync(join(root, "examples", "demo-company"), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  const original = readFileSync(manifest, "utf8");
  const source = original
    .replace(
      "provider: system",
      "provider: file\n    acknowledgePlaintext: true",
    )
    .replace("127.0.0.1:8765", "127.0.0.1")
    .replace(
      "  - ACMECODE_LLM_GATEWAY_URL\n",
      "  - ACMECODE_LLM_GATEWAY_URL\n  - ACMECODE_SANDBOX_URL\n  - ACMECODE_SANDBOX_ROUTER_URL\n",
    )
    .replace(
      /sandbox:\n {2}required: (true|false)\n/,
      [
        "sandbox:",
        "  required: true",
        "  provider: kubernetes-agent-sandbox",
        `  endpoint: \${ACMECODE_SANDBOX_URL}`,
        `  router: \${ACMECODE_SANDBOX_ROUTER_URL}`,
        "  namespace: agents",
        "  template: python-pool",
        "  credential: stored",
        "",
      ].join("\n"),
    )
    // The Kubernetes backend cannot verify the warm pool's NetworkPolicy, so it
    // does not offer network deny and a required deny profile fails closed.
    .replace("  network:\n    mode: deny\n", "  network:\n    mode: allow\n")
    .replace("defaultMode: plan", "defaultMode: build")
    .replace(
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: ask',
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: allow',
    );
  for (const marker of [
    "credential: stored",
    "  network:\n    mode: allow\n",
    "ACMECODE_SANDBOX_URL\n",
    "defaultMode: build",
    "effect: allow",
  ])
    if (!source.includes(marker)) throw new Error(`patch failed: ${marker}`);
  writeFileSync(manifest, source);
  const home = join(temp, "home");
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...services.env(),
    PISHIP_STATE_HOME: join(temp, "state"),
    PISHIP_NO_BROWSER: "1",
    HOME: home,
    USERPROFILE: home,
  };
  delete env.PISHIP_BUILD_INPUT;
  delete env.PISHIP_SANDBOX_ADAPTER;
  for (const step of ["lock", "build"]) {
    const done = spawnSync(process.execPath, [bin, step, manifest], {
      cwd: temp,
      env,
      encoding: "utf8",
    });
    expect(done.status, done.stderr).toBe(0);
  }
  const command = launcher(join(temp, "dist", "acmecode"), "acmecode");
  const project = join(temp, "project");
  mkdirSync(project, { recursive: true });
  return {
    temp,
    env,
    project,
    state: join(temp, "state", "acmecode"),
    run: (
      args: string[],
      extra: NodeJS.ProcessEnv = {},
      input?: string,
    ): Promise<Result> =>
      branded(command, args, {
        cwd: project,
        env: { ...env, ...extra },
        approve: (url) => services.approve(url),
        ...(input === undefined ? {} : { input }),
      }),
  };
}

/** Files under `directory` (outside the opted-in file store) holding `value`. */
function scan(directory: string, value: string): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) {
        if (name !== "secrets") visit(child);
      } else if (readFileSync(child, "latin1").includes(value))
        hits.push(child);
    }
  };
  if (existsSync(directory)) visit(directory);
  return hits;
}

describe("stored sandbox credential (local fixtures)", () => {
  it("sandbox login over stdin, a launch whose bash runs remotely, and a fail-closed endpoint change", async () => {
    const services: Services = await startLocalServices();
    closers.push(() => services.close());
    const cluster = await kubernetesServer(
      (command) =>
        command.includes("remote-ok")
          ? { stdout: "remote-ok\n", exit_code: 0 }
          : { stdout: "", exit_code: 0 },
      { token: TOKEN },
    );
    const dist = build(services);
    const sandbox = {
      ACMECODE_SANDBOX_URL: cluster.url,
      ACMECODE_SANDBOX_ROUTER_URL: cluster.url,
    };
    const login = await dist.run(["login"], sandbox);
    expect(login.status, login.stderr).toBe(0);

    // Before a credential is stored the launch fails closed.
    const missing = await dist.run(["--smoke"], sandbox);
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("SANDBOX_UNAVAILABLE");
    expect(missing.stderr).toMatch(/acmecode sandbox login/);

    // Never from argv: refused without echoing the value.
    const argv = await dist.run(
      ["sandbox", "login", "--secret", "fake-argv-token-0001"],
      sandbox,
    );
    expect(argv.status).toBe(1);
    expect(`${argv.stdout}${argv.stderr}`).not.toContain(
      "fake-argv-token-0001",
    );

    const stored = await dist.run(["sandbox", "login"], sandbox, `${TOKEN}\n`);
    expect(stored.status, stored.stderr).toBe(0);
    expect(stored.stdout).toMatch(/^Sandbox token stored in file/);
    expect(`${stored.stdout}${stored.stderr}`).not.toContain(TOKEN);

    // The agent's bash runs in the remote sandbox with the stored token.
    cluster.requests.length = 0;
    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = [
      { name: "bash", arguments: { command: "echo remote-ok" } },
    ];
    services.state.toolResults = [];
    const launched = await dist.run(["--smoke-model"], sandbox);
    expect(launched.status, launched.stderr).toBe(0);
    expect(services.state.toolResults[0]).toContain("remote-ok");
    expect(
      cluster.requests.some((request) => request.path === "/execute"),
    ).toBe(true);
    for (const request of cluster.requests)
      expect(request.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(leaks(cluster.requests, TOKEN, ["authorization"])).toEqual([]);
    expect(`${launched.stdout}${launched.stderr}`).not.toContain(TOKEN);

    // Doctor reads it through the same checks and never prints it.
    const doctor = await dist.run(["doctor"], sandbox);
    expect(`${doctor.stdout}${doctor.stderr}`).not.toContain(TOKEN);

    // The endpoint variable pointed elsewhere: nothing is sent there.
    const elsewhere = await kubernetesServer();
    const moved = await dist.run(["--smoke"], {
      ...sandbox,
      ACMECODE_SANDBOX_URL: elsewhere.url,
    });
    expect(moved.status).toBe(1);
    expect(moved.stderr).toContain("SANDBOX_UNAVAILABLE");
    expect(elsewhere.requests).toEqual([]);
    expect(`${moved.stdout}${moved.stderr}`).not.toContain(TOKEN);

    // Nothing but the opted-in secret store holds the token, and the
    // manifest, lock, audit log, and metrics never do.
    expect(scan(dist.state, TOKEN)).toEqual([]);
    expect(scan(join(dist.temp, "dist"), TOKEN)).toEqual([]);
    expect(scan(join(dist.temp, "distribution"), TOKEN)).toEqual([]);
    const audit = readFileSync(join(dist.state, "logs", "audit.jsonl"), "utf8");
    expect(audit).toContain('"purpose":"sandbox"');

    // logout deletes it with everything else.
    const logout = await dist.run(["logout"], sandbox);
    expect(logout.status, logout.stderr).toBe(0);
    expect(
      existsSync(join(dist.state, "credentials-metadata", "sandbox.json")),
    ).toBe(false);
    expect(
      readdirSync(join(dist.state, "secrets")).filter((name) =>
        readFileSync(join(dist.state, "secrets", name), "utf8").includes(
          "sandbox#",
        ),
      ),
    ).toEqual([]);
  }, 600000);
});
