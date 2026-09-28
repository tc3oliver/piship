import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createManagedFetch, DEFAULT_NETWORK_POLICY } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { activateSandbox, SANDBOX_READY_MARKER } from "./activate.js";
import type { SandboxPolicy } from "./profile.js";
import {
  connectEnvelope,
  E2bCompatibleBackend,
  type E2bCompatibleOptions,
  EnvelopeReader,
} from "./remote/e2b.js";
import {
  KubernetesAgentSandboxBackend,
  type KubernetesAgentSandboxOptions,
  runtimeCommand,
} from "./remote/kubernetes.js";

interface Recorded {
  readonly method: string;
  readonly path: string;
  readonly headers: IncomingMessage["headers"];
  readonly body: Buffer;
}

type Handler = (
  request: Recorded,
  response: ServerResponse,
  raw: IncomingMessage,
) => void | Promise<void>;

async function serve(handler: Handler): Promise<{
  server: Server;
  url: string;
  requests: Recorded[];
}> {
  const requests: Recorded[] = [];
  const server = createServer((raw, response) => {
    const chunks: Buffer[] = [];
    raw.on("data", (chunk: Buffer) => chunks.push(chunk));
    raw.on("end", () => {
      const request = {
        method: raw.method ?? "GET",
        path: raw.url ?? "/",
        headers: raw.headers,
        body: Buffer.concat(chunks),
      };
      requests.push(request);
      void Promise.resolve(handler(request, response, raw)).catch(() => {
        response.statusCode = 500;
        response.end();
      });
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, url: `http://127.0.0.1:${port}`, requests };
}

const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY, "sandbox");

const policy = (overrides: Partial<SandboxPolicy> = {}): SandboxPolicy => ({
  required: true,
  filesystem: { read: { deny: ["~/.ssh"] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: {
    allow: ["PATH", "HOME", "LANG", "DOCS_MODE", "ACME_API_TOKEN"],
  },
  ...overrides,
});

const SECRETS = {
  ACME_API_TOKEN: "sk-live-never-in-remote-backends",
  AWS_SECRET_ACCESS_KEY: "aws-never-in-remote-backends",
  GITHUB_TOKEN: "ghp_never_in_remote_backends_0000000000",
};
const ENV = {
  PATH: "/opt/host/bin",
  HOME: "/home/alice",
  LANG: "C.UTF-8",
  DOCS_MODE: "demo",
  UNLISTED_VARIABLE: "unlisted-host-value",
  ...SECRETS,
};

let root: string;
let workspace: string;
let servers: Server[] = [];
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-remote-")));
  workspace = join(root, "ws");
  mkdirSync(join(workspace, "sub"), { recursive: true });
});
afterEach(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise((done) => server.close(done));
  }
  servers = [];
  rmSync(root, { recursive: true, force: true });
});

/** A check-command answer: the marker line and a blocked outbound check. */
function checkAnswer(unlisted: string | undefined): string {
  return `${SANDBOX_READY_MARKER} ${unlisted ?? "unset"}\npiship-network-blocked\n`;
}

// ------------------------------------------------------------------ E2B

interface StartRequest {
  process: {
    cmd: string;
    args: string[];
    envs: Record<string, string>;
    cwd: string;
  };
  stdin: boolean;
}

interface E2bScript {
  health?: number;
  create?: number;
  /** Stdout and exit code for a command; `hang` keeps the stream open. */
  command?: (start: StartRequest) => {
    stdout?: string;
    exitCode?: number;
    hang?: boolean;
    streamError?: string;
  };
}

async function e2bServer(script: E2bScript = {}) {
  const hung = new Set<ServerResponse>();
  const started = await serve((request, response) => {
    const path = request.path.split("?")[0] ?? "";
    if (path === "/health") {
      response.statusCode = script.health ?? 204;
      return void response.end();
    }
    if (request.method === "POST" && path === "/sandboxes") {
      response.statusCode = script.create ?? 201;
      response.setHeader("Content-Type", "application/json");
      return void response.end(
        script.create && script.create >= 400
          ? JSON.stringify({ code: script.create, message: "no capacity" })
          : JSON.stringify({
              sandboxID: "sbx1",
              templateID: "piship-workspace",
              envdVersion: "0.4.0",
              envdAccessToken: "envd-token-1",
              domain: null,
            }),
      );
    }
    if (path === "/sandboxes/sbx1/timeout" || path === "/sandboxes/sbx1") {
      response.statusCode = 204;
      return void response.end();
    }
    if (path === "/process.Process/SendSignal") {
      for (const open of hung) open.end(connectEnvelope({}, 0x02));
      hung.clear();
      response.setHeader("Content-Type", "application/json");
      return void response.end("{}");
    }
    if (path === "/process.Process/Start") {
      const [frame] = new EnvelopeReader().push(request.body);
      const start = frame?.message as StartRequest;
      const script_ = start.process.args[2] ?? "";
      const answer = script_.includes(SANDBOX_READY_MARKER)
        ? { stdout: checkAnswer(start.process.envs.PISHIP_PROBE_UNLISTED) }
        : (script.command?.(start) ?? { stdout: "", exitCode: 0 });
      response.setHeader("Content-Type", "application/connect+json");
      response.write(connectEnvelope({ event: { start: { pid: 42 } } }));
      if (answer.stdout)
        response.write(
          connectEnvelope({
            event: {
              data: { stdout: Buffer.from(answer.stdout).toString("base64") },
            },
          }),
        );
      if (answer.hang) return void hung.add(response);
      if (answer.streamError)
        return void response.end(
          connectEnvelope(
            { error: { code: "internal", message: answer.streamError } },
            0x02,
          ),
        );
      response.write(
        connectEnvelope({
          event: {
            end: {
              ...(answer.exitCode ? { exitCode: answer.exitCode } : {}),
              exited: true,
              status: `exit status ${answer.exitCode ?? 0}`,
            },
          },
        }),
      );
      return void response.end(connectEnvelope({}, 0x02));
    }
    response.statusCode = 404;
    response.end();
  });
  servers.push(started.server);
  return started;
}

function e2b(url: string, options: Partial<E2bCompatibleOptions> = {}) {
  return new E2bCompatibleBackend({
    endpoint: url,
    fetch,
    template: "piship-workspace",
    envdUrl: () => url,
    ...options,
  });
}

const activate = (
  backend: E2bCompatibleBackend | KubernetesAgentSandboxBackend,
  config: SandboxPolicy = policy(),
) =>
  activateSandbox(config, {
    workspace,
    homeDir: join(root, "home"),
    backend,
    env: ENV,
    settleMs: 2000,
  });

const run = async (
  sandbox: Awaited<ReturnType<typeof activateSandbox>>,
  command: string,
  options: { cwd?: string; timeout?: number } = {},
) => {
  let output = "";
  const result = await sandbox.exec(command, options.cwd ?? workspace, {
    onData: (chunk) => {
      output += chunk.toString("utf8");
    },
    ...(options.timeout ? { timeout: options.timeout } : {}),
  });
  return { ...result, output };
};

const starts = (requests: Recorded[]) =>
  requests
    .filter((request) => request.path === "/process.Process/Start")
    .map(
      (request) =>
        new EnvelopeReader().push(request.body)[0]?.message as StartRequest,
    );

describe("e2b-compatible backend against a mock server", () => {
  it("creates, checks, runs, and deletes a sandbox", async () => {
    const mock = await e2bServer({
      command: (start) => ({
        stdout: `cwd=${start.process.cwd}\n`,
        exitCode: start.process.args[2] === "exit 3" ? 3 : 0,
      }),
    });
    const sandbox = await activate(e2b(mock.url));
    expect(sandbox.report).toMatchObject({
      level: "enforced",
      adapter: "e2b-compatible",
      provider: "e2b-compatible",
      verification: "backend-attested",
      localProcesses: false,
    });
    expect(await run(sandbox, "pwd", { cwd: join(workspace, "sub") })).toEqual({
      exitCode: 0,
      output: "cwd=/home/user/sub\n",
    });
    expect((await run(sandbox, "exit 3")).exitCode).toBe(3);
    await sandbox.dispose();
    const created = JSON.parse(
      mock.requests
        .find((request) => request.path === "/sandboxes")
        ?.body.toString() ?? "{}",
    );
    expect(created).toEqual({
      templateID: "piship-workspace",
      timeout: 3600,
      metadata: { "created-by": "piship" },
      allow_internet_access: false,
    });
    const start = starts(mock.requests).at(-1);
    expect(start?.process.cmd).toBe("/bin/bash");
    expect(start?.process.args).toEqual(["-l", "-c", "exit 3"]);
    expect(start?.stdin).toBe(false);
    expect(
      mock.requests.filter(
        (request) => request.path === "/sandboxes/sbx1/timeout",
      ),
    ).toHaveLength(3);
    expect(mock.requests.at(-1)).toMatchObject({
      method: "DELETE",
      path: "/sandboxes/sbx1",
    });
  });

  it("maps the workspace onto a configured workdir and allows the network only when asked", async () => {
    const mock = await e2bServer({
      command: (start) => ({ stdout: `${start.process.cwd}\n` }),
    });
    const sandbox = await activate(
      e2b(mock.url, { workdir: "/workspace/repo" }),
      policy({ network: { mode: "allow" } }),
    );
    expect((await run(sandbox, "pwd")).output).toBe("/workspace/repo\n");
    expect(
      (await run(sandbox, "pwd", { cwd: join(workspace, "sub") })).output,
    ).toBe("/workspace/repo/sub\n");
    await sandbox.dispose();
    const created = JSON.parse(
      mock.requests
        .find((request) => request.path === "/sandboxes")
        ?.body.toString() ?? "{}",
    );
    expect(created.allow_internet_access).toBe(true);
  });

  it("sends only approved, non-host variables and no credentials", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(e2b(mock.url));
    await run(sandbox, "env");
    await sandbox.dispose();
    expect(starts(mock.requests).at(-1)?.process.envs).toEqual({
      LANG: "C.UTF-8",
      DOCS_MODE: "demo",
    });
    const wire = JSON.stringify(
      mock.requests.map((request) => ({
        headers: request.headers,
        body: request.body.toString("latin1"),
      })),
    );
    for (const value of [
      ...Object.values(SECRETS),
      "unlisted-host-value",
      "/home/alice",
      "/opt/host/bin",
    ])
      expect(wire).not.toContain(value);
  });

  it("sends the endpoint credential to the control plane only", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(
      e2b(mock.url, { credential: async () => "runtime-credential-1" }),
    );
    await run(sandbox, "true");
    await sandbox.dispose();
    for (const request of mock.requests) {
      const control =
        request.path.startsWith("/sandboxes") && request.path !== "/health";
      if (control)
        expect(request.headers["x-api-key"]).toBe("runtime-credential-1");
      else
        expect(JSON.stringify(request.headers)).not.toContain(
          "runtime-credential-1",
        );
      if (request.path.startsWith("/process.Process/")) {
        expect(request.headers["x-access-token"]).toBe("envd-token-1");
        expect(request.headers["e2b-sandbox-id"]).toBe("sbx1");
        expect(request.headers["e2b-sandbox-port"]).toBe("49983");
        expect(request.headers["connect-protocol-version"]).toBe("1");
      }
    }
  });

  it("kills the remote process on timeout and reports PiShip's outcome", async () => {
    const mock = await e2bServer({
      command: (start) =>
        start.process.args[2]?.startsWith("sleep")
          ? { stdout: "working\n", hang: true }
          : { exitCode: 0 },
    });
    const sandbox = await activate(e2b(mock.url));
    await expect(run(sandbox, "sleep 600", { timeout: 0.3 })).rejects.toThrow(
      "timeout:0.3",
    );
    // The kill is sent right after PiShip stops waiting; wait for it.
    const find = () =>
      mock.requests.find(
        (request) => request.path === "/process.Process/SendSignal",
      );
    for (let attempt = 0; attempt < 100 && !find(); attempt++)
      await new Promise((done) => setTimeout(done, 20));
    const signal = find();
    expect(JSON.parse(signal?.body.toString() ?? "{}")).toEqual({
      process: { pid: 42 },
      signal: "SIGNAL_SIGKILL",
    });
    expect(signal?.headers["content-type"]).toBe("application/json");
    // The sandbox settled the cancelled stream, so it stays usable.
    expect((await run(sandbox, "true")).exitCode).toBe(0);
    await sandbox.dispose();
  });

  it("surfaces a failed command stream", async () => {
    const mock = await e2bServer({
      command: () => ({ streamError: "process exploded" }),
    });
    const sandbox = await activate(e2b(mock.url));
    await expect(run(sandbox, "boom")).rejects.toThrow(/process exploded/);
    await sandbox.dispose();
  });

  it("fails closed when the service is unhealthy or cannot create a sandbox", async () => {
    const unhealthy = await e2bServer({ health: 503 });
    await expect(activate(e2b(unhealthy.url))).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("HTTP 503"),
    });
    expect(
      unhealthy.requests.some((request) => request.path === "/sandboxes"),
    ).toBe(false);
    const full = await e2bServer({ create: 500 });
    await expect(activate(e2b(full.url))).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("no capacity"),
    });
  });

  it("splits Connect envelopes across chunk boundaries", () => {
    const bytes = Buffer.concat([
      connectEnvelope({ event: { start: { pid: 1 } } }),
      connectEnvelope({}, 0x02),
    ]);
    const reader = new EnvelopeReader();
    const frames = [
      ...reader.push(bytes.subarray(0, 3)),
      ...reader.push(bytes.subarray(3, 20)),
      ...reader.push(bytes.subarray(20)),
    ];
    expect(frames).toEqual([
      { flags: 0, message: { event: { start: { pid: 1 } } } },
      { flags: 2, message: {} },
    ]);
    const oversized = Buffer.alloc(5);
    oversized.writeUInt32BE(64 * 1024 * 1024, 1);
    expect(() => new EnvelopeReader().push(oversized)).toThrow(/oversized/);
  });
});

// ------------------------------------------------ Kubernetes Agent Sandbox

const CLAIMS =
  "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/agents/sandboxclaims";

async function kubernetesServer(
  execute?: (command: string) => {
    stdout?: string;
    exit_code?: number;
    hang?: boolean;
  },
) {
  const polls = new Map<string, number>();
  const started = await serve((request, response) => {
    const path = request.path.split("?")[0] ?? "";
    response.setHeader("Content-Type", "application/json");
    if (request.method === "GET" && path === CLAIMS)
      return void response.end(JSON.stringify({ items: [] }));
    if (request.method === "POST" && path === CLAIMS) {
      response.statusCode = 201;
      return void response.end(request.body);
    }
    if (path.startsWith(`${CLAIMS}/`)) {
      const name = path.slice(CLAIMS.length + 1);
      if (request.method === "DELETE") return void response.end("{}");
      const seen = (polls.get(name) ?? 0) + 1;
      polls.set(name, seen);
      return void response.end(
        JSON.stringify({
          status:
            seen < 2
              ? { conditions: [{ type: "Ready", status: "False" }] }
              : {
                  conditions: [{ type: "Ready", status: "True" }],
                  sandbox: { name: `pool-${name}` },
                },
        }),
      );
    }
    if (request.method === "POST" && path === "/execute") {
      const { command } = JSON.parse(request.body.toString()) as {
        command: string;
      };
      if (command.includes(SANDBOX_READY_MARKER))
        return void response.end(
          JSON.stringify({
            stdout: checkAnswer(
              command.includes("'PISHIP_PROBE_UNLISTED=") ? "1" : undefined,
            ),
            stderr: "",
            exit_code: 0,
          }),
        );
      const answer = execute?.(command) ?? { stdout: "", exit_code: 0 };
      if (answer.hang) return;
      return void response.end(JSON.stringify({ stderr: "", ...answer }));
    }
    response.statusCode = 404;
    response.end("{}");
  });
  servers.push(started.server);
  return started;
}

function kubernetes(
  url: string,
  options: Partial<KubernetesAgentSandboxOptions> = {},
) {
  return new KubernetesAgentSandboxBackend({
    endpoint: url,
    router: url,
    fetch,
    template: "python-pool",
    namespace: "agents",
    pollMs: 10,
    ...options,
  });
}

describe("kubernetes-agent-sandbox backend against a mock cluster", () => {
  it("claims a sandbox, runs through the router, and deletes the claim", async () => {
    const mock = await kubernetesServer(() => ({
      stdout: "hello\n",
      exit_code: 4,
    }));
    const sandbox = await activate(kubernetes(mock.url));
    expect(sandbox.report).toMatchObject({
      level: "enforced",
      provider: "kubernetes-agent-sandbox",
      verification: "backend-attested",
    });
    expect(
      await run(sandbox, "make test", { cwd: join(workspace, "sub") }),
    ).toEqual({ exitCode: 4, output: "hello\n" });
    await sandbox.dispose();
    const claim = JSON.parse(
      mock.requests
        .find((request) => request.method === "POST" && request.path === CLAIMS)
        ?.body.toString() ?? "{}",
    );
    expect(claim).toMatchObject({
      apiVersion: "extensions.agents.x-k8s.io/v1beta1",
      kind: "SandboxClaim",
      spec: { warmPoolRef: { name: "python-pool" } },
    });
    expect(claim.metadata.name).toMatch(/^piship-[0-9a-f]{12}$/);
    const execute = mock.requests.filter(
      (request) => request.path === "/execute",
    );
    expect(execute.at(-1)?.headers).toMatchObject({
      "x-sandbox-id": `pool-${claim.metadata.name}`,
      "x-sandbox-namespace": "agents",
      "x-sandbox-port": "8888",
    });
    expect(JSON.parse(execute.at(-1)?.body.toString() ?? "{}").command).toBe(
      `env 'LANG=C.UTF-8' 'DOCS_MODE=demo' /bin/sh -c 'cd -- '"'"'sub'"'"' && make test'`,
    );
    expect(mock.requests.at(-1)).toMatchObject({
      method: "DELETE",
      path: `${CLAIMS}/${claim.metadata.name}`,
    });
    const wire = JSON.stringify(
      mock.requests.map((request) => ({
        headers: request.headers,
        body: request.body.toString(),
      })),
    );
    for (const value of [...Object.values(SECRETS), "unlisted-host-value"])
      expect(wire).not.toContain(value);
  });

  it("replaces the claim after a timed-out command", async () => {
    const mock = await kubernetesServer((command) =>
      command.includes("sleep") ? { hang: true } : { stdout: "ok\n" },
    );
    const sandbox = await activate(kubernetes(mock.url));
    await expect(run(sandbox, "sleep 600", { timeout: 0.3 })).rejects.toThrow(
      "timeout:0.3",
    );
    expect((await run(sandbox, "echo ok")).output).toBe("ok\n");
    await sandbox.dispose();
    const created = mock.requests.filter(
      (request) => request.method === "POST" && request.path === CLAIMS,
    );
    const deleted = mock.requests.filter(
      (request) => request.method === "DELETE",
    );
    expect(created).toHaveLength(2);
    expect(deleted).toHaveLength(2);
  });

  it("sends a bearer to the API and the router only when a credential is given", async () => {
    const mock = await kubernetesServer();
    const sandbox = await activate(
      kubernetes(mock.url, { credential: async () => "runtime-credential-2" }),
    );
    await run(sandbox, "true");
    await sandbox.dispose();
    for (const request of mock.requests)
      expect(request.headers.authorization).toBe("Bearer runtime-credential-2");
  });

  it("quotes commands and environment for the runtime's shell-like split", () => {
    expect(
      runtimeCommand(
        {
          command: 'echo "it\'s" && ls',
          cwd: "/unused",
          workspacePath: ".",
          env: { A: "x y", "BAD NAME": "z" },
        },
        undefined,
      ),
    ).toBe(`env 'A=x y' /bin/sh -c 'echo "it'"'"'s" && ls'`);
    expect(
      runtimeCommand(
        { command: "ls", cwd: "/unused", workspacePath: "a/b", env: {} },
        "/workspace",
      ),
    ).toBe(`env /bin/sh -c 'cd -- '"'"'/workspace/a/b'"'"' && ls'`);
  });

  it("rejects names that are not Kubernetes resource names", () => {
    expect(() =>
      kubernetes("http://127.0.0.1:1", { namespace: "Agents" }),
    ).toThrow(/Kubernetes resource names/);
  });
});
