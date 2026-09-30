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
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher, type Result } from "../helpers/distribution.js";
import {
  describeSightings,
  SecretLedger,
  scanTree,
  sightings,
} from "../helpers/security.js";

// Security cases 6 and 12 (spec 30.3), credential leakage and audit secret
// leakage, as a sweep of everything a real managed run writes or shows. One
// installed-style distribution runs the whole flow (sign in, launch, agent
// turns that try to read secrets, a gateway and a broker that echo the
// credential back in their errors, sign out), and afterwards every secret the
// run ever held (the runtime credential, and the access, refresh, and ID
// tokens) is looked for, in plain and in decoded form, in:
//
//   piship.yaml and piship.lock (source and built artifact)
//   the state directory: logs (audit.jsonl, metrics.json), sessions,
//     preferences, identity and credential metadata, cache, data
//   the output of every command, including the failing ones
//   what the HTTP audit sink received, byte for byte
//   what the model was sent (every request body) and what its tools returned
//
// The file store keeps every value base64url-encoded and is where a stored
// secret belongs, so it is excluded from the scan while the user is signed
// in, and must hold nothing after sign-out. Migration reports and rollback
// snapshots are swept in tests/e2e/security-lifecycle.test.ts.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const windows = process.platform === "win32";
const temporary: string[] = [];
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

type Services = Awaited<ReturnType<typeof startLocalServices>>;

interface Collected {
  readonly url: string;
  readonly headers: string;
  readonly body: string;
}

/** A company audit collector that keeps every request byte for byte. */
async function collector(): Promise<{
  url: string;
  requests: Collected[];
  close: () => Promise<void>;
}> {
  const requests: Collected[] = [];
  const server: Server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      requests.push({
        url: request.url ?? "",
        headers: JSON.stringify(request.headers),
        body,
      });
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  return {
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}/audit`,
    requests,
    close: () =>
      new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}

/**
 * A service that answers what it is asked with an error that repeats the
 * request back, the way a careless gateway or broker echoes a rejected
 * Authorization header and body into its message. `passthrough` sends the
 * requests it should serve to the real fixture first.
 */
async function echoing(
  serve: (method: string, path: string) => boolean,
  forward: (path: string, authorization: string) => Promise<Response>,
): Promise<{ url: string; calls: number; close: () => Promise<void> }> {
  let calls = 0;
  const server: Server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", async () => {
      const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
      const authorization = request.headers.authorization ?? "";
      if (serve(request.method ?? "GET", path)) {
        const real = await forward(path, authorization);
        response.writeHead(real.status, { "content-type": "application/json" });
        response.end(await real.text());
        return;
      }
      calls += 1;
      response.writeHead(500, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          error: {
            message: `upstream failure for Authorization: ${authorization} with body ${body}`,
            type: "server_error",
          },
        }),
      );
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}`,
    get calls() {
      return calls;
    },
    close: () =>
      new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}

/** A copy of demo-company built as its owner would, with a required HTTP audit sink. */
function build(services: Services, auditUrl: string) {
  const temp = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-security-sweep-")),
  );
  temporary.push(temp);
  const directory = join(temp, "distribution");
  cpSync(join(root, "examples", "demo-company"), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  let source = readFileSync(manifest, "utf8")
    .replace(
      "provider: system",
      "provider: file\n    acknowledgePlaintext: true",
    )
    .replace("127.0.0.1:8765", "127.0.0.1")
    .replace("defaultMode: plan", "defaultMode: build")
    .replace(
      "  - ACMECODE_LLM_GATEWAY_URL\n",
      "  - ACMECODE_LLM_GATEWAY_URL\n  - ACMECODE_AUDIT_URL\n",
    )
    .replace(
      "    - id: local\n      type: file\n      required: false",
      `    - id: local\n      type: file\n      required: false\n    - id: company\n      type: http\n      url: \${ACMECODE_AUDIT_URL}\n      required: true`,
    )
    .replace(
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: ask',
      '    - id: acme.shell\n      action: shell.execute\n      resource: "**"\n      effect: allow',
    );
  for (const marker of ["type: http", "defaultMode: build", "effect: allow"])
    if (!source.includes(marker)) throw new Error(`patch failed: ${marker}`);
  if (windows)
    source = source.replace(
      "  required: true\n  filesystem:",
      "  required: false\n  filesystem:",
    );
  writeFileSync(manifest, source);
  const home = join(temp, "home");
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...services.env(),
    ACMECODE_AUDIT_URL: auditUrl,
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
  writeFileSync(join(project, "notes.txt"), "project notes\n");
  return {
    temp,
    project,
    state: join(temp, "state", "acmecode"),
    run: (args: string[], extra: NodeJS.ProcessEnv = {}): Promise<Result> =>
      branded(command, args, {
        cwd: project,
        env: { ...env, ...extra },
        approve: (url) => services.approve(url),
      }),
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

/** One distribution, its services and audit collector, and a ledger of every secret it saw. */
async function start() {
  const services: Services = await startLocalServices();
  closers.push(() => services.close());
  const sink = await collector();
  closers.push(() => sink.close());
  const dist = build(services, sink.url);
  const secrets = join(dist.state, "secrets");
  const ledger = new SecretLedger();
  const outputs = new Map<string, string>();
  const observe = () => {
    ledger.observeServices(services);
    if (existsSync(secrets)) ledger.observeFileStore(secrets);
  };
  // Runs one command and remembers what it printed and what it held.
  const step = async (
    label: string,
    args: string[],
    extra: NodeJS.ProcessEnv = {},
  ): Promise<Result> => {
    const done = await dist.run(args, extra);
    outputs.set(label, `${done.stdout}\n${done.stderr}`);
    observe();
    return done;
  };
  /**
   * Every place a secret of the run could be, but the store's own directory
   * (and, when named, `skip`): files, output of every command, the sink, and
   * what the model was sent.
   */
  const sweep = (skip: readonly string[] = []) => {
    const everything = ledger.all();
    return [
      ...describeSightings(
        scanTree(dist.temp, everything, ["node_modules", "secrets", ...skip]),
      ),
      ...[...outputs].flatMap(([label, text]) =>
        describeSightings(sightings(`output of ${label}`, text, everything)),
      ),
      ...sink.requests.flatMap((request, index) =>
        describeSightings(
          sightings(
            `audit sink request ${index}`,
            `${request.url}\n${request.headers}\n${request.body}`,
            everything,
          ),
        ),
      ),
      ...(services.state.requests as { path: string; body: string }[])
        .filter((request) => request.path.endsWith("/chat/completions"))
        .flatMap((request, index) =>
          describeSightings(
            sightings(`model request ${index}`, request.body, everything),
          ),
        ),
    ];
  };
  return { services, sink, dist, secrets, ledger, outputs, step, sweep };
}

describe("credential and audit leakage sweep (local fixtures, real launcher)", () => {
  it("leaves no secret of the run in any file, output, audit event, sink request, model request or tool result", async () => {
    const { services, sink, dist, secrets, ledger, outputs, step, sweep } =
      await start();

    // Sign in, and the commands a user runs around a launch.
    const login = await step("login", ["login"]);
    expect(login.status, login.stderr).toBe(0);
    // The control for every scan below: the run holds identity tokens and a
    // credential, and the scan finds them where they belong.
    expect(ledger.size).toBeGreaterThanOrEqual(4);
    expect(
      scanTree(secrets, ledger.all(), []).map((hit) => hit.form),
    ).toContain("decoded");
    for (const [label, args] of [
      ["smoke", ["--smoke"]],
      ["models", ["models"]],
      ["config-explain", ["config", "explain"]],
      ["doctor", ["doctor"]],
      ["capabilities", ["capabilities"]],
      ["policy-explain", ["policy", "explain", "shell.execute", "ls"]],
    ] as const) {
      const done = await step(label, [...args]);
      expect(done.status, `${label}: ${done.stderr}`).toBe(0);
    }

    // The agent tries to read what it must not, and to see the environment.
    const state = dist.state;
    const stored = readdirSync(secrets).map((name) => join(secrets, name));
    expect(stored.length).toBeGreaterThan(0);
    const steps = [
      { name: "bash", arguments: { command: "env; echo; printenv" } },
      ...stored.slice(0, 2).map((path) => ({
        name: "read",
        arguments: { path },
      })),
      {
        name: "read",
        arguments: { path: join(state, "identity", "session.json") },
      },
      ...(windows
        ? []
        : [
            {
              name: "bash",
              arguments: {
                command: `cat ${JSON.stringify(stored[0])}; echo exit=$?`,
              },
            },
            {
              name: "bash",
              arguments: {
                command: `cat ${JSON.stringify(join(state, "credentials-metadata", "inference.json"))}; echo exit=$?`,
              },
            },
            {
              name: "bash",
              arguments: {
                command: `ls -la ${JSON.stringify(state)}; echo exit=$?`,
              },
            },
          ]),
    ];
    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = steps;
    services.state.toolResults = [];
    const turns = await step("agent-turns", ["--smoke-model"]);
    expect(turns.status, turns.stderr).toBe(0);
    const toolResults = [...services.state.toolResults] as string[];
    expect(toolResults).toHaveLength(steps.length);
    // The environment output reached the model, so the request scan covers
    // what an environment dump carried.
    expect(toolResults[0]).toMatch(/PATH=/);
    outputs.set("tool-results", toolResults.join("\n----\n"));

    // Nothing outside the secret store holds any secret of the run.
    expect(sweep()).toEqual([]);

    // The scans looked at real data: the log and the sink hold the run's
    // events, and the model was sent the agent's turns.
    const events = auditEvents(dist.state).map((event) => event.event);
    expect(events).toEqual(
      expect.arrayContaining([
        "identity.login",
        "credential.acquire",
        "session.start",
        "tool.allowed",
      ]),
    );
    expect(sink.requests.length).toBeGreaterThan(0);
    expect(
      (services.state.requests as { path: string }[]).filter((request) =>
        request.path.endsWith("/chat/completions"),
      ).length,
    ).toBeGreaterThan(steps.length);

    // After sign-out the store is empty too, so nothing anywhere holds any.
    const logout = await step("logout", ["logout"]);
    expect(logout.status, logout.stderr).toBe(0);
    expect(
      describeSightings(scanTree(dist.temp, ledger.all(), ["node_modules"])),
    ).toEqual([]);
  }, 900000);

  it("does not repeat what a broker or a revoke endpoint echoes back of a token or a credential", async () => {
    const { services, dist, ledger, step, sweep } = await start();
    expect((await step("login", ["login"])).status).toBe(0);
    expect((await step("smoke", ["--smoke"])).status).toBe(0);

    // A revoke endpoint that rejects the credential and echoes it (and the
    // Authorization header that carried it) into its answer: sign-out still
    // clears everything locally, says it could not revoke, and prints nothing
    // that repeats the credential.
    const revoking = await echoing(
      () => false,
      () => Promise.reject(new Error("unused")),
    );
    closers.push(() => revoking.close());
    const signedOut = await step("logout-echoed-revoke", ["logout"], {
      ACMECODE_CREDENTIAL_REVOKE_URL: `${revoking.url}/v1/revoke`,
    });
    expect(signedOut.status, signedOut.stderr).toBe(0);
    expect(revoking.calls, "the revoke endpoint was asked").toBeGreaterThan(0);
    expect(signedOut.stderr).toMatch(/revocation/i);

    // A broker that echoes the identity token it is sent as the bearer.
    const broker = await echoing(
      () => false,
      () => Promise.reject(new Error("unused")),
    );
    closers.push(() => broker.close());
    const refused = await step("login-echoed-broker", ["login"], {
      ACMECODE_CREDENTIAL_BROKER_URL: `${broker.url}/v1/credential`,
    });
    expect(
      broker.calls,
      "the broker was asked for a credential",
    ).toBeGreaterThan(0);
    expect(refused.status).toBe(1);
    expect(services.state.requests.length).toBeGreaterThan(0);

    expect(sweep()).toEqual([]);
    expect((await step("logout", ["logout"])).status).toBe(0);
    expect(
      describeSightings(scanTree(dist.temp, ledger.all(), ["node_modules"])),
    ).toEqual([]);
  }, 900000);

  /**
   * A gateway that rejects a request and echoes the Authorization header into
   * its error, as a careless proxy does. What PiShip prints, logs and sends to
   * the audit sink is clean; the Pi session file is not (see the next test).
   */
  async function echoingGateway() {
    const run = await start();
    const { services, dist, step } = run;
    expect((await step("login", ["login"])).status).toBe(0);
    const gateway = await echoing(
      (method, path) => method === "GET" && path.endsWith("/models"),
      (path, authorization) =>
        fetch(`${services.base}/gateway/v1${path.replace(/^\/v1/, "")}`, {
          headers: { authorization },
        }),
    );
    closers.push(() => gateway.close());
    const echoed = await step("gateway-echo-model", ["--smoke-model"], {
      ACMECODE_LLM_GATEWAY_URL: `${gateway.url}/v1`,
    });
    expect(
      gateway.calls,
      "the gateway was asked for a completion",
    ).toBeGreaterThan(0);
    expect(echoed.status).toBe(1);
    expect(echoed.stderr).toContain("GATEWAY_PROTOCOL_ERROR");
    return { ...run, sessions: join(dist.state, "sessions") };
  }

  it("keeps what a gateway echoes of the credential out of the launcher's output, the audit log and the audit sink", async () => {
    const { ledger, sweep, sessions } = await echoingGateway();
    expect(ledger.size).toBeGreaterThanOrEqual(4);
    expect(sweep(["sessions"])).toEqual([]);
    expect(existsSync(sessions)).toBe(true);
  }, 900000);

  // KNOWN GAP (V07-82 finding 1), not yet fixed in the product: Pi stores the
  // provider's error text in the session file it writes under the state
  // directory, and PiShip redacts that text only where it prints it. A
  // gateway that echoes the credential leaves it in `sessions/` in plain text.
  // `it.fails` documents the reproduction and passes while the gap is open;
  // once the error text is redacted before Pi persists it, this test fails,
  // and it becomes an ordinary `it`.
  it.fails("keeps what a gateway echoes of the credential out of the Pi session file", async () => {
    const { dist, ledger } = await echoingGateway();
    expect(
      describeSightings(
        scanTree(join(dist.state, "sessions"), ledger.all(), []),
      ),
    ).toEqual([]);
  }, 900000);
});
