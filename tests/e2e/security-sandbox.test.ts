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
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import {
  type Cluster,
  kubernetesServer,
} from "../../packages/sandbox/src/testing/kubernetes-server.js";
import {
  closeMockServers,
  leaks,
  type MockServer,
} from "../../packages/sandbox/src/testing/mock-server.js";
import { branded, launcher, type Result } from "../helpers/distribution.js";
import {
  describeSightings,
  SecretLedger,
  scanTree,
  sightings,
} from "../helpers/security.js";

// Security case 7 (docs/security.md, security test map), sandbox credential leakage, and the sandbox
// control of case 13, at the launcher. A remote sandbox (a mock Kubernetes
// Agent Sandbox API and router that require a bearer token) holds the agent's
// commands; the token is stored with `sandbox login`. The stored-credential
// happy path, argv refusal, origin rule and wire check are in
// tests/e2e/sandbox-credential.test.ts. This file follows the token through
// what that test does not: a change of user, a service that rejects the token
// and echoes it, replacing a rejected token, a service that is down (the
// agent's command must not run on the host instead), and sign-out.
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
// Obvious fakes; never real tokens.
const ALICE_TOKEN = "fake-sandbox-token-SENTINEL-alice-0001";
const BOB_TOKEN = "fake-sandbox-token-SENTINEL-bob-0002";
const BOB_NEXT_TOKEN = "fake-sandbox-token-SENTINEL-bob-0003";

function build(services: Services) {
  const temp = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-security-sandbox-")),
  );
  temporary.push(temp);
  const directory = join(temp, "distribution");
  cpSync(join(root, "examples", "demo-company"), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  const source = readFileSync(manifest, "utf8")
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
  // What a run writes to the system temp directory lands inside `temp`,
  // where the scans look.
  const tmp = join(temp, "tmp");
  mkdirSync(tmp, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...services.env(),
    PISHIP_STATE_HOME: join(temp, "state"),
    PISHIP_NO_BROWSER: "1",
    HOME: home,
    USERPROFILE: home,
    TMPDIR: tmp,
    TMP: tmp,
    TEMP: tmp,
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

const bash = (command: string) => ({ name: "bash", arguments: { command } });

describe("stored sandbox credential across users, rejection, and outage (local fixtures)", () => {
  it("never outlives its user, never appears in what a rejecting service echoes, and never lets the command run on the host instead", async () => {
    const services: Services = await startLocalServices();
    closers.push(() => services.close());
    const cluster: Cluster = { token: ALICE_TOKEN };
    // What the sandbox service was asked to run, as the service parsed it: the
    // raw request body is JSON, so a native path in it (a Windows one has
    // backslashes) is escaped on the wire and never matches as written.
    const commands: string[] = [];
    const service: MockServer = await kubernetesServer((command) => {
      commands.push(command);
      return command.includes("remote-ok")
        ? { stdout: "remote-ok\n", exit_code: 0 }
        : { stdout: "", exit_code: 0 };
    }, cluster);
    const dist = build(services);
    const sandbox = {
      ACMECODE_SANDBOX_URL: service.url,
      ACMECODE_SANDBOX_ROUTER_URL: service.url,
    };
    const ledger = new SecretLedger();
    ledger.add(ALICE_TOKEN, BOB_TOKEN, BOB_NEXT_TOKEN);
    const outputs = new Map<string, string>();
    const secrets = join(dist.state, "secrets");
    const step = async (
      label: string,
      args: string[],
      extra: NodeJS.ProcessEnv = {},
      input?: string,
    ): Promise<Result> => {
      const done = await dist.run(args, { ...sandbox, ...extra }, input);
      outputs.set(label, `${done.stdout}\n${done.stderr}`);
      ledger.observeServices(services);
      if (existsSync(secrets)) ledger.observeFileStore(secrets);
      return done;
    };
    const as = (subject: string) => {
      services.knobs.subject = subject;
    };
    // The agent's command: it says where it ran, and leaves a marker file
    // where it runs.
    const agentCommand = (marker: string) =>
      `echo remote-ok; touch ${JSON.stringify(marker)}`;
    const remote = async (label: string, marker: string) => {
      // The same user resumes their session, and the fixture takes the tool
      // calls of the resumed history for steps of its script already done: it
      // would answer in text and the command would never be asked for. Every
      // launch starts a new session.
      rmSync(join(dist.state, "sessions"), { recursive: true, force: true });
      services.knobs.gatewayMode = "script";
      services.knobs.toolScript = [bash(agentCommand(marker))];
      services.state.toolResults = [];
      const done = await step(label, ["--smoke-model"]);
      services.knobs.gatewayMode = "text";
      // The service received the agent's command, unchanged: that is where it
      // ran. (The marker is quoted inside it by JSON.stringify, which is also
      // how it appears once the service has parsed the request.)
      expect(
        commands.some((command) => command.includes(agentCommand(marker))),
      ).toBe(true);
      return done;
    };
    // The control for every "not on the host" assertion below: run on the host
    // itself, the same command does create its marker. (A host without a POSIX
    // shell, such as a Windows runner, cannot run it, so it cannot have run it
    // in place of the sandbox either.)
    const control = join(dist.temp, "host-control");
    const onHost = spawnSync("bash", [
      "-c",
      'echo remote-ok; touch "$1"',
      "bash",
      control,
    ]);
    if (onHost.status === 0) expect(existsSync(control)).toBe(true);
    const sandboxMetadata = join(
      dist.state,
      "credentials-metadata",
      "sandbox.json",
    );
    const held = () =>
      existsSync(secrets)
        ? readdirSync(secrets).filter((name) =>
            readFileSync(join(secrets, name), "utf8").includes("sandbox#"),
          )
        : [];

    // Alice stores her token and her agent's command runs in the sandbox.
    as("alice-0001");
    expect((await step("login-alice", ["login"])).status).toBe(0);
    const stored = await step(
      "sandbox-login-alice",
      ["sandbox", "login"],
      {},
      `${ALICE_TOKEN}\n`,
    );
    expect(stored.status, stored.stderr).toBe(0);
    const markerAlice = join(dist.temp, "host-alice");
    const first = await remote("launch-alice", markerAlice);
    expect(first.status, first.stderr).toBe(0);
    expect(services.state.toolResults[0]).toContain("remote-ok");
    expect(service.requests.length).toBeGreaterThan(0);
    for (const request of service.requests)
      expect(request.headers.authorization).toBe(`Bearer ${ALICE_TOKEN}`);
    expect(leaks(service.requests, ALICE_TOKEN, ["authorization"])).toEqual([]);
    expect(existsSync(sandboxMetadata)).toBe(true);
    expect(held()).toHaveLength(1);
    // The command ran remotely: the host has no marker.
    expect(existsSync(markerAlice)).toBe(false);

    // Bob signs in over Alice: her sandbox credential is deleted, and his
    // first launch cannot reach the service with it.
    as("bob-0002");
    expect((await step("login-bob", ["login"])).status).toBe(0);
    expect(existsSync(sandboxMetadata)).toBe(false);
    expect(held()).toEqual([]);
    const requests = service.requests.length;
    const bobFirst = await step("launch-bob", ["--smoke"]);
    expect(bobFirst.status).toBe(1);
    expect(bobFirst.stderr).toContain("SANDBOX_UNAVAILABLE");
    expect(bobFirst.stderr).toMatch(/acmecode sandbox login/);
    expect(service.requests.slice(requests)).toEqual([]);
    expect(describeSightings(scanTree(dist.temp, [ALICE_TOKEN]))).toEqual([]);

    // Bob stores his own; the service takes only that token.
    cluster.token = BOB_TOKEN;
    expect(
      (
        await step(
          "sandbox-login-bob",
          ["sandbox", "login"],
          {},
          `${BOB_TOKEN}\n`,
        )
      ).status,
    ).toBe(0);
    const markerBob = join(dist.temp, "host-bob");
    const second = await remote("launch-bob-2", markerBob);
    expect(second.status, second.stderr).toBe(0);
    expect(services.state.toolResults[0]).toContain("remote-ok");
    expect(existsSync(markerBob)).toBe(false);

    // The service now rejects Bob's token and echoes what it was sent, as a
    // careless API does. The launch stops, and the echo goes nowhere.
    cluster.token = "rotated-away-SENTINEL-not-a-real-token";
    const marks = service.requests.length;
    const rejected = await step("launch-rejected", ["--smoke"]);
    expect(rejected.status).toBe(1);
    expect(rejected.stderr).toContain("SANDBOX_UNAVAILABLE");
    expect(service.requests.length).toBeGreaterThan(marks);
    expect(
      describeSightings(
        sightings(
          "output of launch-rejected",
          `${rejected.stdout}\n${rejected.stderr}`,
          [BOB_TOKEN],
        ),
      ),
    ).toEqual([]);
    // Bob replaces the rejected token, and the agent's command runs remotely again.
    cluster.token = BOB_NEXT_TOKEN;
    expect(
      (
        await step(
          "sandbox-login-bob-2",
          ["sandbox", "login"],
          {},
          `${BOB_NEXT_TOKEN}\n`,
        )
      ).status,
    ).toBe(0);
    const markerNext = join(dist.temp, "host-bob-2");
    const third = await remote("launch-bob-3", markerNext);
    expect(third.status, third.stderr).toBe(0);
    expect(existsSync(markerNext)).toBe(false);

    // The service goes down: the launch fails closed, and the command the
    // agent asked for does not run on the host in its place.
    service.server.closeAllConnections();
    await new Promise<void>((done) => service.server.close(() => done()));
    const markerDown = join(dist.temp, "host-down");
    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = [bash(agentCommand(markerDown))];
    services.state.toolResults = [];
    const down = await step("launch-down", ["--smoke-model"]);
    services.knobs.gatewayMode = "text";
    expect(down.status).toBe(1);
    expect(down.stderr).toContain("SANDBOX_UNAVAILABLE");
    expect(existsSync(markerDown)).toBe(false);
    expect(services.state.toolResults).toEqual([]);

    // Nothing anywhere holds any token while Bob is signed in (the store's
    // own directory aside), and nothing at all once he signs out.
    const everything = ledger.all();
    expect(
      describeSightings(
        scanTree(dist.temp, everything, ["state/acmecode/secrets"]),
      ),
    ).toEqual([]);
    expect(
      [...outputs].flatMap(([label, text]) =>
        describeSightings(sightings(`output of ${label}`, text, everything)),
      ),
    ).toEqual([]);
    const audit = readFileSync(join(dist.state, "logs", "audit.jsonl"), "utf8");
    expect(audit).toContain('"purpose":"sandbox"');
    const out = await step("logout", ["logout"]);
    expect(out.status, out.stderr).toBe(0);
    expect(existsSync(sandboxMetadata)).toBe(false);
    expect(describeSightings(scanTree(dist.temp, ledger.all()))).toEqual([]);
  }, 900000);
});
