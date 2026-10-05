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
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher, type Result } from "../helpers/distribution.js";

// Security cases 1-3, 8 and 13 (docs/security.md, security test map) at the launcher: the six mandatory
// controls (identity, credential, sandbox, policy, integrity, audit) each stop
// the launch, or the action, when their configuration or implementation is
// missing or broken, and a user, project, or team policy cannot widen what the
// distribution enforces or defaults. Every case runs the real branded command
// against the local fixtures; what a fixture would do if the control were
// missing is asserted as well (nothing reached the gateway, no marker file, no
// state written).
//
// Where an existing test already proves a control at the launcher, this file
// does not repeat it: the sandbox adapter that cannot be enforced is
// tests/e2e/governance.test.ts ("enforces Plan mode, MCP policy, project
// trust, and certified integrity"), a remote sandbox backend that is down is
// tests/e2e/security-sandbox.test.ts, and the payload inventory is
// tests/e2e/cli.test.ts and lifecycle-integrity.test.ts.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const windows = process.platform === "win32";

type Services = Awaited<ReturnType<typeof startLocalServices>>;

// An obvious fake; never a real key.
const AMBIENT = "sk-ambient-personal-key-SENTINEL-security";
const PRIVATE_CANARY = "private-workspace-canary-SENTINEL";
/** The audit buffer of the built distribution, in events. */
const AUDIT_BUFFER = 60;

/**
 * A team policy adapter whose behavior each run picks with an environment
 * variable, so one build serves every case. It records that it was loaded.
 */
const TEAM_ADAPTER = `import { writeFileSync } from "node:fs";
const mode = process.env.SECURITY_TEAM_MODE ?? "narrow";
if (process.env.SECURITY_TEAM_MARKER)
  writeFileSync(process.env.SECURITY_TEAM_MARKER, "loaded");
const widen = [
  { id: "team.private", action: "filesystem.read", resource: "workspace/private/**", effect: "allow" },
  { id: "team.shell", action: "shell.execute", resource: "**", effect: "allow" },
];
export default () => {
  if (mode === "throw") throw new Error("team policy service is unreachable");
  if (mode === "shape") return { rulez: [] };
  if (mode === "widen") return widen;
  return [{ id: "team.notes", action: "filesystem.read", resource: "workspace/team-only.txt", effect: "deny", reason: "the team keeps this file out" }];
};
`;

interface Fixture {
  readonly services: Services;
  readonly temp: string;
  readonly artifact: string;
  /** The team adapter as packaged, to tamper with and restore. */
  readonly adapter: string;
  readonly home: string;
  readonly project: string;
  readonly company: string;
  /** A fresh state home per case, so cases never see each other's sign-in. */
  session(extra?: NodeJS.ProcessEnv): Session;
}

interface Session {
  readonly state: string;
  run(args: string[], extra?: NodeJS.ProcessEnv, cwd?: string): Promise<Result>;
  login(): Promise<Result>;
  /** `login`, approved in the fixture browser, then Ctrl-C. */
  loginInterrupted(): Promise<Result>;
  /** One scripted model turn with `steps` as the agent's tool calls. */
  script(
    steps: { name: string; arguments: Record<string, unknown> }[],
    cwd?: string,
    extra?: NodeJS.ProcessEnv,
  ): Promise<{ result: Result; toolResults: string[] }>;
}

let fixture: Fixture;
let closeServices: (() => Promise<void>) | undefined;
let audit: Awaited<ReturnType<typeof auditSink>>;
const cleanup: string[] = [];

// Each case runs the real launcher a few times: on a busy machine that is
// well past the 15 s default.
vi.setConfig({ testTimeout: 300_000 });

/**
 * A company audit collector that can start refusing every batch from the one
 * that carries a named event on.
 */
async function auditSink() {
  const events: Record<string, unknown>[] = [];
  const control = {
    status: 200,
    /** Refuse this batch and every later one: the sink has stopped taking events. */
    failOnEvent: undefined as string | undefined,
    failing: false,
    requests: 0,
  };
  const server: Server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      control.requests += 1;
      const parsed = JSON.parse(body || "{}") as {
        events?: Record<string, unknown>[];
      };
      if (
        control.failOnEvent &&
        (parsed.events ?? []).some(
          (event) => event.event === control.failOnEvent,
        )
      )
        control.failing = true;
      const status = control.failing ? 503 : control.status;
      if (status === 200) events.push(...(parsed.events ?? []));
      response.writeHead(status, { "content-type": "application/json" });
      response.end("{}");
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  return {
    events,
    control,
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}/audit`,
    close: () =>
      new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}

function build(services: Services, auditUrl: string): Fixture {
  const temp = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-security-controls-")),
  );
  cleanup.push(temp);
  const directory = join(temp, "distribution");
  cpSync(join(root, "examples", "demo-company"), directory, {
    recursive: true,
  });
  mkdirSync(join(directory, "resources", "policy"), { recursive: true });
  writeFileSync(
    join(directory, "resources", "policy", "team.mjs"),
    TEAM_ADAPTER,
  );
  const manifest = join(directory, "piship.yaml");
  let source = readFileSync(manifest, "utf8")
    .replace(
      "provider: system",
      "provider: file\n    acknowledgePlaintext: true",
    )
    .replace("127.0.0.1:8765", "127.0.0.1")
    .replace(
      'path: "/srv/src/**"',
      `path: ${JSON.stringify(`${temp.replaceAll("\\", "/")}/**`)}`,
    )
    .replace("defaultMode: plan", "defaultMode: build")
    .replace(
      "  - ACMECODE_LLM_GATEWAY_URL\n",
      "  - ACMECODE_LLM_GATEWAY_URL\n  - ACMECODE_AUDIT_URL\n",
    )
    .replace(
      "  id: acme-engineering\n  version: 1\n",
      "  id: acme-engineering\n  version: 1\n  adapter: ./resources/policy/team.mjs\n",
    )
    // The distribution forbids reading a workspace directory outright. The
    // default for shell commands stays `ask`: with no approval channel, deny.
    .replace(
      "  enforced:\n    - id: acme.secrets.read\n",
      '  enforced:\n    - id: acme.private\n      action: filesystem.read\n      resource: "workspace/private/**"\n      effect: deny\n      reason: The private directory is not delegated to the agent\n    - id: acme.secrets.read\n',
    )
    // A buffer a required sink that has stopped taking events fills within a
    // short session; a healthy sink drains it every second.
    .replace(
      "audit:\n  enabled: true\n",
      `audit:\n  enabled: true\n  buffer:\n    maxEvents: ${AUDIT_BUFFER}\n    flushInterval: 1s\n`,
    )
    .replace(
      "    - id: local\n      type: file\n      required: false",
      `    - id: local\n      type: file\n      required: false\n    - id: company\n      type: http\n      url: \${ACMECODE_AUDIT_URL}\n      required: true`,
    );
  for (const marker of [
    "adapter: ./resources/policy/team.mjs",
    "acme.private",
    "type: http",
    "defaultMode: build",
    `maxEvents: ${AUDIT_BUFFER}`,
    temp.replaceAll("\\", "/"),
  ])
    if (!source.includes(marker)) throw new Error(`patch failed: ${marker}`);
  if (windows)
    source = source.replace(
      "  required: true\n  filesystem:",
      "  required: false\n  filesystem:",
    );
  writeFileSync(manifest, source);
  const home = join(temp, "home");
  mkdirSync(join(home, ".ssh"), { recursive: true });
  writeFileSync(join(home, ".ssh", "id_rsa"), "ssh-private-key-canary\n");
  const tmp = join(temp, "tmp");
  mkdirSync(tmp, { recursive: true });
  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ...services.env(),
    ACMECODE_AUDIT_URL: auditUrl,
    OPENAI_API_KEY: AMBIENT,
    PISHIP_NO_BROWSER: "1",
    HOME: home,
    USERPROFILE: home,
    TMPDIR: tmp,
    TMP: tmp,
    TEMP: tmp,
  };
  delete baseEnv.PISHIP_BUILD_INPUT;
  delete baseEnv.PISHIP_SANDBOX_ADAPTER;
  for (const step of ["lock", "build"]) {
    const done = spawnSync(process.execPath, [bin, step, manifest], {
      cwd: temp,
      env: { ...baseEnv, PISHIP_STATE_HOME: join(temp, "build-state") },
      encoding: "utf8",
    });
    expect(done.status, done.stderr).toBe(0);
  }
  const artifact = join(temp, "dist", "acmecode");
  const command = launcher(artifact, "acmecode");

  const project = join(temp, "project");
  mkdirSync(join(project, "private"), { recursive: true });
  writeFileSync(join(project, "notes.txt"), "project notes\n");
  writeFileSync(join(project, "private", "key.txt"), `${PRIVATE_CANARY}\n`);
  // A company project: the git remote and the checkout path both match.
  const company = join(temp, "company-project");
  mkdirSync(join(company, ".git"), { recursive: true });
  mkdirSync(join(company, ".piship"), { recursive: true });
  mkdirSync(join(company, "private"), { recursive: true });
  writeFileSync(
    join(company, ".git", "config"),
    '[remote "origin"]\n\turl = https://git.acme.example/acme/app.git\n',
  );
  writeFileSync(join(company, "notes.txt"), "project notes\n");
  writeFileSync(join(company, "private", "key.txt"), `${PRIVATE_CANARY}\n`);

  let sessions = 0;
  return {
    services,
    temp,
    artifact,
    adapter: join(artifact, "resources", "resources", "policy", "team.mjs"),
    home,
    project,
    company,
    session(extra = {}) {
      sessions += 1;
      const state = join(temp, `state-${sessions}`);
      const run = (
        args: string[],
        more: NodeJS.ProcessEnv = {},
        cwd = project,
      ): Promise<Result> =>
        branded(command, args, {
          cwd,
          env: { ...baseEnv, PISHIP_STATE_HOME: state, ...extra, ...more },
          approve: (url) => services.approve(url),
        });
      return {
        state: join(state, "acmecode"),
        run: (args, more, cwd) => run(args, more, cwd),
        async login() {
          const done = await run(["login"]);
          expect(done.status, done.stderr).toBe(0);
          return done;
        },
        loginInterrupted: () =>
          branded(command, ["login"], {
            cwd: project,
            env: { ...baseEnv, PISHIP_STATE_HOME: state, ...extra },
            approve: (url) => services.approve(url),
            interruptAfterApprove: true,
            timeoutMs: 60_000,
          }),
        async script(steps, cwd = project, more = {}) {
          services.knobs.gatewayMode = "script";
          services.knobs.toolScript = steps;
          services.state.toolResults = [];
          const result = await run(["--smoke-model"], more, cwd);
          services.knobs.gatewayMode = "text";
          return { result, toolResults: [...services.state.toolResults] };
        },
      };
    },
  };
}

function auditEvents(state: string): Record<string, unknown>[] {
  const path = join(state, "logs", "audit.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

const gatewayCalls = (services: Services) =>
  (services.state.requests as { path: string }[]).filter((request) =>
    request.path.startsWith("/gateway/"),
  );
/** The requests that carried a prompt to the model. */
const chatCalls = (services: Services) =>
  gatewayCalls(services).filter((request) =>
    request.path.endsWith("/chat/completions"),
  );
const brokerCalls = (services: Services) =>
  (services.state.requests as { path: string }[]).filter((request) =>
    request.path.startsWith("/broker/"),
  );

/** No request the fixture saw ever carried the ambient personal key. */
function expectAmbientKeyUnused(services: Services): void {
  expect(JSON.stringify(services.state.requests)).not.toContain(AMBIENT);
}

let defaults: Record<string, unknown>;
beforeAll(async () => {
  const services: Services = await startLocalServices();
  closeServices = () => services.close();
  audit = await auditSink();
  fixture = build(services, audit.url);
  defaults = structuredClone(services.knobs);
}, 600000);
afterAll(async () => {
  await audit?.close();
  await closeServices?.();
  for (const path of cleanup) rmSync(path, { recursive: true, force: true });
}, 180000);
beforeEach(() => {
  const { services } = fixture;
  for (const key of Object.keys(services.knobs))
    services.knobs[key] = structuredClone(defaults[key]);
  // What the fixture recorded belongs to the case that ran.
  services.state.requests.length = 0;
  audit.control.status = 200;
  audit.control.failOnEvent = undefined;
  audit.control.failing = false;
  audit.control.requests = 0;
  audit.events.length = 0;
});

describe("identity: an invalid sign-in is refused and stores nothing (cases 1-3)", () => {
  // Each response an identity provider or a hostile browser can send that
  // PiShip must not accept. The fixture knob produces it; the launcher's
  // `login` is the boundary. tests/security/oidc-invalid.test.ts runs the
  // same cases (and the browser attacks) against the library with the
  // signed-in user preserved, and a live Keycloak runs them in
  // tests/enterprise-reference/security-oidc.test.ts.
  it.each([
    [
      "an ID token from another issuer",
      "idTokenIssuer",
      "https://evil.example/idp",
      "IDENTITY_INVALID",
    ],
    [
      "an ID token for another audience",
      "idTokenAudience",
      "another-client",
      "IDENTITY_INVALID",
    ],
    [
      "an ID token with another nonce",
      "idTokenNonce",
      "replayed-nonce",
      "IDENTITY_INVALID",
    ],
    // A callback with another state is its own case below: the listener
    // refuses it and the login keeps waiting, so the case ends it with Ctrl-C.
    [
      "an ID token signed with an unpublished key",
      "signWithRogueKey",
      true,
      "IDENTITY_INVALID",
    ],
    ["an expired ID token", "idTokenExpired", true, "IDENTITY_EXPIRED"],
  ])(
    "refuses %s, leaves nothing signed in, and asks the broker for nothing",
    async (_name, knob, value, code) => {
      const { services } = fixture;
      const session = fixture.session();
      services.knobs[knob as string] = value;
      const refused = await session.run(["login"]);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain(code);
      expect(refused.stderr).not.toMatch(/demo-(at|rt|code)-/);
      expect(brokerCalls(services)).toEqual([]);
      expect(gatewayCalls(services)).toEqual([]);
      expect(existsSync(join(session.state, "identity", "session.json"))).toBe(
        false,
      );
      expect(
        existsSync(
          join(session.state, "credentials-metadata", "inference.json"),
        ),
      ).toBe(false);
      const secrets = join(session.state, "secrets");
      expect(existsSync(secrets) ? readdirSync(secrets) : []).toEqual([]);
      // The next launch is still signed out, and the ambient key is not used.
      services.knobs[knob as string] = defaults[knob as string];
      const launch = await session.run(["--smoke"]);
      expect(launch.status).toBe(1);
      expect(launch.stderr).toMatch(/IDENTITY_REQUIRED/);
      expectAmbientKeyUnused(services);
    },
  );

  // Ctrl-C cannot be delivered to a Windows child; the refusal itself is
  // covered there by tests/security/oidc-invalid.test.ts.
  it.skipIf(windows)(
    "refuses a callback with another state, keeps waiting, and stores nothing when cancelled",
    async () => {
      const { services } = fixture;
      const session = fixture.session();
      services.knobs.stateOverride = "attacker-state";
      const before = (services.state.requests as { path: string }[]).length;
      const refused = await session.loginInterrupted();
      // The listener answered the forged callback with 400 and went on
      // waiting until Ctrl-C, which ends the login as a cancelled sign-in
      // that names the refusal.
      expect(refused.approval).toBe(400);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain("IDENTITY_REQUIRED");
      expect(refused.stderr).toMatch(
        /cancelled; refused 1 callback without this sign-in's state/,
      );
      expect(refused.stderr).not.toMatch(/demo-(at|rt|code)-/);
      // The forged callback's code was never exchanged.
      expect(
        (services.state.requests as { path: string }[])
          .slice(before)
          .filter((request) => request.path === "/idp/token"),
      ).toEqual([]);
      expect(brokerCalls(services)).toEqual([]);
      expect(gatewayCalls(services)).toEqual([]);
      expect(existsSync(join(session.state, "identity", "session.json"))).toBe(
        false,
      );
      expect(
        existsSync(
          join(session.state, "credentials-metadata", "inference.json"),
        ),
      ).toBe(false);
      const secrets = join(session.state, "secrets");
      expect(existsSync(secrets) ? readdirSync(secrets) : []).toEqual([]);
      services.knobs.stateOverride = defaults.stateOverride;
      const launch = await session.run(["--smoke"]);
      expect(launch.status).toBe(1);
      expect(launch.stderr).toMatch(/IDENTITY_REQUIRED/);
      expectAmbientKeyUnused(services);
    },
  );

  it("refuses to sign in when the issuer variable is not set, without asking anyone", async () => {
    const { services } = fixture;
    const session = fixture.session();
    const refused = await session.run(["login"], { ACMECODE_OIDC_ISSUER: "" });
    expect(refused.status).toBe(1);
    expect(refused.stderr).toContain("ACMECODE_OIDC_ISSUER");
    expect(services.state.requests).toEqual([]);
    expect(existsSync(join(session.state, "identity", "session.json"))).toBe(
      false,
    );
  });
});

describe("credential: no credential means no launch, and never a personal one (case 13)", () => {
  it("keeps the identity but issues nothing when the broker is down, and never falls back to the ambient key", async () => {
    const { services } = fixture;
    const session = fixture.session();
    services.knobs.brokerStatus = 503;
    const login = await session.run(["login"]);
    expect(login.status).toBe(1);
    expect(login.stderr).toMatch(/CREDENTIAL_/);
    services.knobs.brokerStatus = undefined;
    // Signed in but without a credential: the launch acquires one or stops.
    // Take the broker down again: it stops, and the gateway never sees the
    // ambient key.
    services.knobs.brokerStatus = 503;
    const launch = await session.run(["--smoke"]);
    expect(launch.status).toBe(1);
    expect(launch.stderr).toMatch(/CREDENTIAL_/);
    expect(gatewayCalls(services)).toEqual([]);
    expectAmbientKeyUnused(services);
  });

  it("refuses a credential whose gateway is not the declared one, and sends nothing there", async () => {
    const { services } = fixture;
    const session = fixture.session();
    const seen: string[] = [];
    const elsewhere: Server = createServer((request, response) => {
      seen.push(request.url ?? "");
      response.writeHead(404).end();
    });
    await new Promise<void>((done) => elsewhere.listen(0, "127.0.0.1", done));
    try {
      services.knobs.brokerBaseUrl = `http://127.0.0.1:${(elsewhere.address() as { port: number }).port}/v1`;
      const login = await session.run(["login"]);
      expect(login.status).toBe(1);
      expect(login.stderr).toContain("undeclared gateway base_url");
      expect(seen).toEqual([]);
      expect(gatewayCalls(services)).toEqual([]);
      const metadata = join(
        session.state,
        "credentials-metadata",
        "inference.json",
      );
      expect(existsSync(metadata)).toBe(false);
    } finally {
      await new Promise<void>((done) => {
        elsewhere.close(() => done());
        elsewhere.closeAllConnections();
      });
    }
  });
});

describe("policy: a broken policy stops the launch; a widening one is ignored (cases 8, 13)", () => {
  it.each([
    ["a user policy file that is not JSON", "not json {"],
    [
      "a user policy file with an unknown field",
      JSON.stringify({ rules: [], extra: true }),
    ],
    [
      "a user policy rule with an unknown effect",
      JSON.stringify({
        rules: [
          {
            id: "me.x",
            action: "filesystem.read",
            resource: "**",
            effect: "maybe",
          },
        ],
      }),
    ],
  ])("refuses to launch with %s", async (_name, content) => {
    const { services } = fixture;
    const session = fixture.session();
    await session.login();
    mkdirSync(join(session.state, "config"), { recursive: true });
    writeFileSync(join(session.state, "config", "policy.json"), content);
    const launch = await session.run(["--smoke-model"]);
    expect(launch.status).toBe(1);
    expect(launch.stderr).toContain("CONFIG_INVALID");
    // The launch stopped before the model was asked anything.
    expect(chatCalls(services)).toEqual([]);
  });

  it("refuses to launch in a company project whose restriction file is not valid", async () => {
    const { services } = fixture;
    const session = fixture.session();
    await session.login();
    writeFileSync(join(fixture.company, ".piship", "policy.json"), "{ nope");
    try {
      // The control: the same company project launches without the file.
      rmSync(join(fixture.company, ".piship", "policy.json"));
      const fine = await session.run(["--smoke-model"], {}, fixture.company);
      expect(fine.status, fine.stderr).toBe(0);
      expect(chatCalls(services)).toHaveLength(1);
      writeFileSync(join(fixture.company, ".piship", "policy.json"), "{ nope");
      const refused = await session.run(["--smoke-model"], {}, fixture.company);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain("CONFIG_INVALID");
      expect(chatCalls(services)).toHaveLength(1);
    } finally {
      rmSync(join(fixture.company, ".piship", "policy.json"), { force: true });
    }
  });

  it("stops the launch when the team policy cannot be loaded or is not a rule list", async () => {
    const { services } = fixture;
    const session = fixture.session();
    await session.login();
    const marker = join(fixture.temp, "team-adapter-loaded");
    rmSync(marker, { force: true });
    // The control: the adapter loads, and the launch works.
    const narrow = await session.run(["--smoke"], {
      SECURITY_TEAM_MARKER: marker,
    });
    expect(narrow.status, narrow.stderr).toBe(0);
    expect(readFileSync(marker, "utf8")).toBe("loaded");
    rmSync(marker);
    const thrown = await session.run(["--smoke-model"], {
      SECURITY_TEAM_MODE: "throw",
      SECURITY_TEAM_MARKER: marker,
    });
    expect(thrown.status).toBe(1);
    expect(thrown.stderr).toContain("CONFIG_UNAVAILABLE");
    expect(thrown.stderr).toContain("team policy service is unreachable");
    expect(existsSync(marker)).toBe(true);
    const shape = await session.run(["--smoke-model"], {
      SECURITY_TEAM_MODE: "shape",
    });
    expect(shape.status).toBe(1);
    expect(shape.stderr).toContain("CONFIG_INVALID");
    // No model request was made by either.
    expect(chatCalls(services)).toEqual([]);
  });

  it("does not let a team, a project, or a user rule allow what the distribution denies or leaves to ask", async () => {
    const session = fixture.session();
    await session.login();
    // The three layers below the distribution all try to allow the enforced
    // deny (the private directory) and the default ask (shell commands).
    const allow = [
      {
        id: "widen.private",
        action: "filesystem.read",
        resource: "workspace/private/**",
        effect: "allow",
      },
      {
        id: "widen.shell",
        action: "shell.execute",
        resource: "**",
        effect: "allow",
      },
    ];
    writeFileSync(
      join(fixture.company, ".piship", "policy.json"),
      JSON.stringify({ rules: allow }),
    );
    mkdirSync(join(session.state, "config"), { recursive: true });
    writeFileSync(
      join(session.state, "config", "policy.json"),
      JSON.stringify({
        rules: allow.map((rule) => ({
          ...rule,
          id: rule.id.replace("widen", "mine"),
        })),
      }),
    );
    const scriptEnv = { SECURITY_TEAM_MODE: "widen" };
    try {
      const steps = [
        { name: "read", arguments: { path: "notes.txt" } },
        { name: "read", arguments: { path: "private/key.txt" } },
        { name: "bash", arguments: { command: "echo widened > widened.txt" } },
      ];
      const { result, toolResults } = await session.script(
        steps,
        fixture.company,
        scriptEnv,
      );
      expect(result.status, result.stderr).toBe(0);
      expect(toolResults).toHaveLength(3);
      // The control: an allowed read works, so the tools do run.
      expect(toolResults[0]).toContain("project notes");
      // The enforced deny holds against all three widening layers.
      expect(toolResults[1]).not.toContain(PRIVATE_CANARY);
      expect(toolResults[1]).toContain("acme.private");
      // The default ask has no approval channel, so it is a denial, not an allow.
      expect(existsSync(join(fixture.company, "widened.txt"))).toBe(false);
      expect(toolResults[2]).toMatch(/approval|not allowed|denied/i);
      const events = auditEvents(session.state);
      expect(
        events.some(
          (event) =>
            event.event === "tool.denied" && event.rule === "acme.private",
        ),
      ).toBe(true);
      // Each layer's allow is reported as ignored, not applied.
      const explained = await session.run(
        ["policy", "explain", "filesystem.read", "private/key.txt", "--json"],
        scriptEnv,
        fixture.company,
      );
      expect(explained.status, explained.stderr).toBe(0);
      const explanation = JSON.parse(explained.stdout);
      expect(explanation).toMatchObject({
        effect: "deny",
        ruleId: "acme.private",
        layer: "distribution-enforced",
      });
      const text = JSON.stringify(explanation);
      for (const id of ["team.private", "widen.private", "mine.private"])
        expect(text).toContain(id);
    } finally {
      rmSync(join(fixture.company, ".piship", "policy.json"), { force: true });
      rmSync(join(fixture.company, "widened.txt"), { force: true });
    }
  });

  it("keeps an enforced setting and an entitled model against a hand-edited preferences file", async () => {
    const { services } = fixture;
    const session = fixture.session();
    await session.login();
    mkdirSync(join(session.state, "config"), { recursive: true });
    writeFileSync(
      join(session.state, "config", "preferences.json"),
      JSON.stringify({
        schema: "piship-preferences/v1",
        values: { theme: "light", model: "acme/review" },
        modelsAllowed: [
          "acme/coder",
          "acme/general",
          "acme/review",
          "acme/unlisted",
        ],
      }),
    );
    const explained = await session.run(["config", "explain", "--json"]);
    expect(explained.status, explained.stderr).toBe(0);
    const config = JSON.parse(explained.stdout);
    expect(JSON.stringify(config)).toContain("dark");
    expect(JSON.stringify(config)).not.toContain('"light"');
    // acme/review is in the distribution's list but not in the credential's
    // entitlement (acme/coder and acme/general): the launch refuses it.
    const launch = await session.run(["--smoke-model"]);
    expect(launch.status).toBe(1);
    expect(launch.stderr).toContain("MODEL_UNAVAILABLE");
    const chats = (
      services.state.requests as { path: string; body: string }[]
    ).filter((request) => request.path.endsWith("/chat/completions"));
    expect(
      chats.filter((request) => request.body.includes("acme/review")),
    ).toEqual([]);
  });
});

describe("integrity: a payload that changed does not run (case 13)", () => {
  it("refuses a tampered policy adapter before it executes, and runs it again once restored", async () => {
    const session = fixture.session();
    await session.login();
    const marker = join(fixture.temp, "tampered-adapter-ran");
    const original = readFileSync(fixture.adapter);
    rmSync(marker, { force: true });
    try {
      writeFileSync(
        fixture.adapter,
        `${original.toString("utf8")}\nimport { writeFileSync as w } from "node:fs";\nw(${JSON.stringify(marker)}, "ran");\n`,
      );
      const refused = await session.run(["--smoke"]);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain("INTEGRITY_FAILED");
      expect(existsSync(marker)).toBe(false);
      const doctor = await session.run(["doctor"]);
      expect(doctor.status).toBe(1);
      expect(`${doctor.stdout}${doctor.stderr}`).toContain(
        "integrity mismatch",
      );
    } finally {
      writeFileSync(fixture.adapter, original);
    }
    const restored = await session.run(["--smoke"]);
    expect(restored.status, restored.stderr).toBe(0);
    expect(existsSync(marker)).toBe(false);
  });

  it("refuses a payload whose inventory is missing", async () => {
    const { services } = fixture;
    const session = fixture.session();
    await session.login();
    const inventory = join(fixture.artifact, "metadata", "inventory.json");
    const original = readFileSync(inventory);
    services.state.requests.length = 0;
    try {
      rmSync(inventory);
      const refused = await session.run(["--smoke-model"]);
      expect(refused.status).toBe(1);
      expect(refused.stdout).not.toContain('"initialized"');
      // The launcher could not read the inventory it verifies the payload
      // against, and went no further: no gateway, no broker, no model.
      expect(refused.stderr).toContain("inventory.json");
      expect(services.state.requests).toEqual([]);
    } finally {
      writeFileSync(inventory, original);
    }
    expect((await session.run(["--smoke"])).status).toBe(0);
  });
});

describe("audit: a required sink that stops taking events (case 13)", () => {
  /** `count` reads of a file the agent may read: a step that ran answers with the file. */
  const reads = (count: number) =>
    Array.from({ length: count }, () => ({
      name: "read",
      arguments: { path: "notes.txt" },
    }));

  it("fails the launch before the agent does anything when the collector answers the readiness probe with an error", async () => {
    const { services } = fixture;
    const session = fixture.session();
    await session.login();
    audit.control.status = 503;
    const { result, toolResults } = await session.script(reads(3));
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("AUDIT_UNAVAILABLE");
    // Nothing ran, and nothing was sent to the model.
    expect(toolResults).toEqual([]);
    expect(chatCalls(services)).toEqual([]);
  });

  it("stops the agent, its tool calls and its model requests once a sink that stopped taking events has a full buffer", async () => {
    const { services } = fixture;
    const session = fixture.session();
    await session.login();
    // The sink took the launch's probe and the session's first events; from
    // the batch that carries the first tool decision on, it refuses
    // everything. Events now pile up in the buffer.
    audit.control.failOnEvent = "tool.allowed";
    const steps = reads(AUDIT_BUFFER);
    const { result } = await session.script(steps);
    // The session ended with the loss, not with the agent's answer, and the
    // model request that would have followed was refused before it was sent.
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("AUDIT_UNAVAILABLE");
    expect(result.stderr).toContain("the audit buffer is full");
    // What ran is in the local log (the fixture only reports tool results of a
    // script that finished). The control: the agent did act while the buffer
    // had room. Then it stopped at the next governed tool or model boundary,
    // and the model was not asked for the turns that would have followed.
    const recorded = auditEvents(session.state);
    const events = recorded.map((event) => event.event);
    const allowed = events.filter((event) => event === "tool.allowed").length;
    expect(allowed).toBeGreaterThan(0);
    expect(allowed).toBeLessThan(steps.length);
    // Backpressure can become visible at either the next tool decision or
    // the next model dispatch, depending on which event filled the buffer.
    const denied = recorded.findIndex(
      (event) =>
        ["tool.denied", "model.denied"].includes(String(event.event)) &&
        (event.detail as Record<string, unknown> | undefined)?.error ===
          "AUDIT_UNAVAILABLE",
    );
    expect(denied).toBeGreaterThanOrEqual(0);
    expect(chatCalls(services).length).toBeLessThan(steps.length + 1);
    expect(chatCalls(services).length).toBe(
      events.filter((event) => event === "model.request").length,
    );
    // The actual refusal must prevent both later tool execution and model
    // requests, and must still report the loss when the session closes.
    expect(events.at(-1)).toBe("session.end");
    expect(events.slice(denied + 1)).not.toContain("tool.allowed");
    expect(events.lastIndexOf("model.request")).toBeLessThan(denied);
  });

  it("reports the events a required sink did not take when the session ends", async () => {
    const session = fixture.session();
    await session.login();
    // The sink answers the launch's readiness probe and takes the session's
    // first events, then refuses the batch that closes the session and every
    // one after it: the session has already run, so this proves the loss is
    // reported (a failing exit), not that anything stopped.
    audit.control.failOnEvent = "session.end";
    const run = await session.run(["--smoke-model"]);
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("AUDIT_UNAVAILABLE");
    const local = auditEvents(session.state).map((event) => event.event);
    expect(local).toEqual(
      expect.arrayContaining(["session.start", "session.end"]),
    );
  });
});
