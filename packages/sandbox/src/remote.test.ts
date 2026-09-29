import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createManagedFetch, DEFAULT_NETWORK_POLICY } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { activateSandbox, describeContainment } from "./activate.js";
import type { SandboxPolicy, SandboxProfile } from "./profile.js";
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
import { e2bServer, type StartRequest } from "./testing/e2b-server.js";
import {
  CLAIMS,
  type Cluster,
  kubernetesServer,
} from "./testing/kubernetes-server.js";
import { closeMockServers, type Recorded } from "./testing/mock-server.js";

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
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-remote-")));
  workspace = join(root, "ws");
  mkdirSync(join(workspace, "sub"), { recursive: true });
});
afterEach(async () => {
  await closeMockServers();
  rmSync(root, { recursive: true, force: true });
});

// ------------------------------------------------------------------ E2B

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

describe("remote capability reporting", () => {
  const backends = () => [
    e2b("http://127.0.0.1:1"),
    kubernetes("http://127.0.0.1:1"),
  ];

  it("never declares PiShip's filesystem path planes for a remote backend", () => {
    for (const backend of backends()) {
      const capabilities = backend.capabilities();
      expect(capabilities.isolation).toBe("remote");
      expect(capabilities.planes).toEqual([
        "host-filesystem-isolation",
        "network-deny",
        "environment-filter",
      ]);
      expect(capabilities.planes).not.toContain("filesystem-read-deny");
      expect(capabilities.planes).not.toContain("filesystem-write-allowlist");
      expect(capabilities.localProcesses).toBe(false);
      // Neither backend knows the developer's workspace: a template or a
      // warm-pool pod holds a copy of the code at best.
      expect(capabilities.workspace).toEqual({ mode: "snapshot" });
    }
  });

  it("reports only enforced guarantees in the containment report and doctor line", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(e2b(mock.url));
    expect(sandbox.report.planes).toEqual([
      "network-deny",
      "environment-filter",
      "host-filesystem-isolation",
    ]);
    const line = describeContainment(sandbox.report);
    expect(line).toBe(
      "enforced by e2b-compatible (required, attested by the backend): network-deny, environment-filter, host-filesystem-isolation; network deny. Contains shell commands; MCP stdio servers cannot be contained by this backend and do not start, not the agent process or in-process extensions. The sandbox cannot reach this host's files, but it does not enforce sandbox.filesystem path rules; they govern only the local file tools. Workspace: snapshot. Remote commands see a copy, not the files the agent edits; this is not a complete coding-agent workspace.",
    );
    expect(sandbox.report).toMatchObject({
      isolation: "remote",
      workspace: {
        declared: "snapshot",
        effective: "snapshot",
        verification: "not-required",
        gitControlProtection: "not-applicable",
        complete: false,
      },
    });
    // A snapshot is never checked: no sentinel reaches the service.
    expect((await run(sandbox, "true")).exitCode).toBe(0);
    expect(sandbox.workspace()?.verification).toBe("not-required");
    const wire = mock.requests.map((request) => request.body.toString());
    expect(wire.join("\n")).not.toMatch(/piship-ws|\.git\/piship-workspace/);
    expect(line).not.toMatch(/filesystem-read-deny|filesystem-write-allowlist/);
    await sandbox.dispose();
  });
});

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
    const tag = (starts(mock.requests).at(-1) as StartRequest & { tag: string })
      .tag;
    expect(tag).toMatch(/^piship-[0-9a-f]{16}$/);
    expect(JSON.parse(signal?.body.toString() ?? "{}")).toEqual({
      process: { tag },
      signal: "SIGNAL_SIGKILL",
    });
    expect(signal?.headers["content-type"]).toBe("application/json");
    // The sandbox settled the cancelled stream, so it stays usable.
    expect((await run(sandbox, "true")).exitCode).toBe(0);
    await sandbox.dispose();
  });

  it("maps envd's -1 for a signalled process to a signal exit", async () => {
    const mock = await e2bServer({ command: () => ({ exitCode: -1 }) });
    const sandbox = await activate(e2b(mock.url));
    expect((await run(sandbox, "kill -9 $$")).exitCode).toBe(1);
    await sandbox.dispose();
  });

  it("runs commands as the E2B default user", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(e2b(mock.url));
    await run(sandbox, "whoami");
    await sandbox.dispose();
    for (const request of mock.requests.filter(
      (item) => item.path === "/process.Process/Start",
    ))
      expect(request.headers.authorization).toBe(
        `Basic ${Buffer.from("user:").toString("base64")}`,
      );
  });

  it("runs commands as root for a CubeSandbox-style service when configured", async () => {
    const cube = await e2bServer({ user: "root" });
    // Without the setting, the service refuses the E2B default user.
    await expect(activate(e2b(cube.url))).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("HTTP 401"),
    });
    const sandbox = await activate(e2b(cube.url, { user: "root" }));
    expect((await run(sandbox, "whoami")).exitCode).toBe(0);
    await sandbox.dispose();
    const starts = cube.requests.filter(
      (item) => item.path === "/process.Process/Start",
    );
    expect(starts.at(-1)?.headers.authorization).toBe(
      `Basic ${Buffer.from("root:").toString("base64")}`,
    );
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

  it("shares one claim between concurrent commands and keeps it for the others when one is cancelled", async () => {
    let release!: () => void;
    const gate = new Promise<void>((done) => {
      release = done;
    });
    const mock = await kubernetesServer((command) =>
      command.includes("sleep") ? { hang: true } : { stdout: "ok\n" },
    );
    const sandbox = await activate(kubernetes(mock.url));
    const claims = () =>
      mock.requests.filter(
        (request) => request.method === "POST" && request.path === CLAIMS,
      ).length;
    const deletes = () =>
      mock.requests.filter((request) => request.method === "DELETE").length;
    const controller = new AbortController();
    const slow = sandbox.exec("sleep 600", workspace, {
      onData: () => {},
      signal: controller.signal,
    });
    const quick = Promise.all([run(sandbox, "echo a"), run(sandbox, "echo b")]);
    expect((await quick).map((result) => result.output)).toEqual([
      "ok\n",
      "ok\n",
    ]);
    controller.abort();
    await expect(slow).rejects.toThrow("aborted");
    release();
    await gate;
    expect(claims()).toBe(1);
    // The cancelled command's claim is deleted once nothing uses it.
    expect(deletes()).toBe(1);
    const after = await Promise.all([
      run(sandbox, "echo c"),
      run(sandbox, "echo d"),
    ]);
    expect(after.map((result) => result.output)).toEqual(["ok\n", "ok\n"]);
    expect(claims()).toBe(2);
    await sandbox.dispose();
    expect(deletes()).toBe(2);
  });

  const claimNames = (requests: Recorded[]) =>
    requests
      .filter((request) => request.method === "POST" && request.path === CLAIMS)
      .map(
        (request) =>
          (
            JSON.parse(request.body.toString()) as {
              metadata: { name: string };
            }
          ).metadata.name,
      );
  const lifecycleOf = (request: Recorded | undefined) =>
    (
      JSON.parse(request?.body.toString() ?? "{}") as {
        spec?: {
          lifecycle?: { shutdownTime?: string; shutdownPolicy?: string };
        };
      }
    ).spec?.lifecycle;

  it("creates every claim with a bounded, deterministic lifecycle", async () => {
    const start = Date.parse("2026-09-28T18:00:00.250Z");
    const mock = await kubernetesServer();
    const sandbox = await activate(
      kubernetes(mock.url, { lifetimeSeconds: 900, now: () => start }),
    );
    await sandbox.dispose();
    const created = mock.requests.find(
      (request) => request.method === "POST" && request.path === CLAIMS,
    );
    // Rounded up to the second: never shorter than the lifetime.
    expect(lifecycleOf(created)).toEqual({
      shutdownTime: "2026-09-28T18:15:01Z",
      shutdownPolicy: "Delete",
    });
  });

  it("deletes the claim when a command is cancelled", async () => {
    const mock = await kubernetesServer((command) =>
      command.includes("sleep") ? { hang: true } : { stdout: "ok\n" },
    );
    const sandbox = await activate(kubernetes(mock.url));
    const [first] = claimNames(mock.requests);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 100);
    await expect(
      sandbox.exec("sleep 600", workspace, {
        onData: () => {},
        signal: controller.signal,
      }),
    ).rejects.toThrow("aborted");
    expect(
      mock.requests
        .filter((request) => request.method === "DELETE")
        .map((request) => request.path),
    ).toEqual([`${CLAIMS}/${first}`]);
    await sandbox.dispose();
  });

  it("stays fail closed when cleanup fails, and the claim still expires on its own", async () => {
    const cluster: Cluster = { deleteStatus: 500 };
    const mock = await kubernetesServer(
      (command) =>
        command.includes("sleep") ? { hang: true } : { stdout: "ok\n" },
      cluster,
    );
    const now = Date.parse("2026-09-28T18:00:00Z");
    const sandbox = await activate(
      kubernetes(mock.url, { lifetimeSeconds: 600, now: () => now }),
    );
    await expect(run(sandbox, "sleep 600", { timeout: 0.2 })).rejects.toThrow(
      "timeout:0.2",
    );
    const [retired] = claimNames(mock.requests);
    // The DELETE was attempted and failed; nothing about it leaked back.
    expect(
      mock.requests.some(
        (request) =>
          request.method === "DELETE" &&
          request.path === `${CLAIMS}/${retired}`,
      ),
    ).toBe(true);
    // The retired claim carries the safety net and is never renewed again.
    expect(
      lifecycleOf(
        mock.requests.find(
          (request) => request.method === "POST" && request.path === CLAIMS,
        ),
      ),
    ).toEqual({
      shutdownTime: "2026-09-28T18:10:00Z",
      shutdownPolicy: "Delete",
    });
    // The next command runs in a fresh claim, never the retired one.
    expect((await run(sandbox, "echo ok")).output).toBe("ok\n");
    const names = claimNames(mock.requests);
    expect(names).toHaveLength(2);
    const execute = mock.requests.filter(
      (request) => request.path === "/execute",
    );
    expect(execute.at(-1)?.headers["x-sandbox-id"]).toBe(`pool-${names[1]}`);
    await sandbox.dispose();
  });

  it("renews the claim so a long session is not expired early", async () => {
    let now = Date.parse("2026-09-28T18:00:00Z");
    const mock = await kubernetesServer((command) =>
      command.includes("slow") ? { hang: true } : { stdout: "ok\n" },
    );
    const sandbox = await activate(
      kubernetes(mock.url, { lifetimeSeconds: 1, now: () => now }),
    );
    const patches = () =>
      mock.requests.filter((request) => request.method === "PATCH");
    // Fresh claim: nothing to renew yet.
    await run(sandbox, "echo a");
    expect(patches()).toHaveLength(0);
    // Past half the lifetime, the next command renews first.
    now += 600;
    await run(sandbox, "echo b");
    expect(patches()).toHaveLength(1);
    expect(lifecycleOf(patches()[0])).toEqual({
      shutdownTime: "2026-09-28T18:00:02Z",
    });
    expect(patches()[0]?.headers["content-type"]).toBe(
      "application/merge-patch+json",
    );
    // A command that runs longer than the lifetime is kept alive while it runs.
    const controller = new AbortController();
    const slow = sandbox
      .exec("slow job", workspace, {
        onData: () => {},
        signal: controller.signal,
      })
      .catch(() => undefined);
    // With a one-second lifetime the claim is renewed every 250 ms while
    // the command runs; wait for two renewals beyond the one above.
    const deadline = Date.now() + 10_000;
    while (patches().length < 3 && Date.now() < deadline)
      await new Promise((done) => setTimeout(done, 50));
    expect(patches().length).toBeGreaterThanOrEqual(3);
    controller.abort();
    await slow;
    await sandbox.dispose();
  });

  it("stops renewing a claim once its command is cancelled", async () => {
    const mock = await kubernetesServer((command) =>
      command.includes("sleep") ? { hang: true } : { stdout: "ok\n" },
    );
    // A one-second lifetime renews a running command every 250 ms.
    const sandbox = await activate(
      kubernetes(mock.url, { lifetimeSeconds: 1 }),
    );
    const [first] = claimNames(mock.requests);
    const renewals = () =>
      mock.requests.filter(
        (request) =>
          request.method === "PATCH" && request.path === `${CLAIMS}/${first}`,
      ).length;
    const controller = new AbortController();
    const pending = sandbox
      .exec("sleep 600", workspace, {
        onData: () => {},
        signal: controller.signal,
      })
      .catch(() => undefined);
    // Renewal really runs while the command does...
    const deadline = Date.now() + 10_000;
    while (renewals() < 1 && Date.now() < deadline)
      await new Promise((done) => setTimeout(done, 25));
    expect(renewals()).toBeGreaterThanOrEqual(1);
    controller.abort();
    await pending;
    const atRetire = renewals();
    // ...and never again after retirement, over more than two intervals.
    await new Promise((done) => setTimeout(done, 700));
    expect(renewals()).toBe(atRetire);
    await sandbox.dispose();
  });

  it("replaces a locally expired claim without renewing it", async () => {
    let now = Date.parse("2026-09-28T18:00:00Z");
    // The cluster has not removed the claim yet, so a PATCH would succeed.
    const mock = await kubernetesServer();
    const sandbox = await activate(
      kubernetes(mock.url, { lifetimeSeconds: 60, now: () => now }),
    );
    const [first] = claimNames(mock.requests);
    now += 61_000;
    expect((await run(sandbox, "echo ok")).exitCode).toBe(0);
    expect(claimNames(mock.requests)).toHaveLength(2);
    expect(
      mock.requests.filter((request) => request.method === "PATCH"),
    ).toHaveLength(0);
    expect(
      mock.requests.some(
        (request) =>
          request.method === "DELETE" && request.path === `${CLAIMS}/${first}`,
      ),
    ).toBe(true);
    await sandbox.dispose();
  });

  it("reports a new epoch once an expired claim is replaced", async () => {
    let now = Date.parse("2026-09-28T18:00:00Z");
    const mock = await kubernetesServer();
    const instance = await kubernetes(mock.url, {
      lifetimeSeconds: 60,
      now: () => now,
    }).prepare({ profile: {} as SandboxProfile });
    const io = {
      signal: new AbortController().signal,
      onStdout: () => {},
      onStderr: () => {},
    };
    const request = {
      command: "true",
      cwd: workspace,
      workspacePath: ".",
      env: {},
    };
    expect(instance.epoch?.()).toBeUndefined();
    await instance.exec(request, io);
    const first = instance.epoch?.();
    expect(first).toBe(claimNames(mock.requests)[0]);
    await instance.exec(request, io);
    expect(instance.epoch?.()).toBe(first);
    now += 61_000;
    await instance.exec(request, io);
    expect(instance.epoch?.()).toBe(claimNames(mock.requests)[1]);
    expect(instance.epoch?.()).not.toBe(first);
    await instance.dispose();
  });

  it("creates no claim after dispose, even mid-renewal", async () => {
    let now = Date.parse("2026-09-28T18:00:00Z");
    let open!: () => void;
    const cluster: Cluster = {
      expired: new Set(),
      patchGate: new Promise<void>((done) => {
        open = done;
      }),
    };
    const mock = await kubernetesServer(undefined, cluster);
    const sandbox = await activate(
      kubernetes(mock.url, { lifetimeSeconds: 60, now: () => now }),
    );
    const [first] = claimNames(mock.requests);
    // Due for renewal; the cluster answers that the claim is gone only
    // after the session has been disposed.
    now += 40_000;
    cluster.expired?.add(first ?? "");
    const pending = run(sandbox, "echo ok");
    const deadline = Date.now() + 10_000;
    while (
      !mock.requests.some((request) => request.method === "PATCH") &&
      Date.now() < deadline
    )
      await new Promise((done) => setTimeout(done, 10));
    await sandbox.dispose();
    open();
    await expect(pending).rejects.toThrow(/disposed/);
    expect(claimNames(mock.requests)).toEqual([first]);
    expect(
      mock.requests.filter((request) => request.path === "/execute").length,
    ).toBe(1); // the activation check only
  });

  it("replaces a claim the cluster already expired before running", async () => {
    let now = Date.parse("2026-09-28T18:00:00Z");
    const cluster: Cluster = { expired: new Set() };
    const mock = await kubernetesServer(undefined, cluster);
    const sandbox = await activate(
      kubernetes(mock.url, { lifetimeSeconds: 60, now: () => now }),
    );
    const [first] = claimNames(mock.requests);
    cluster.expired?.add(first ?? "");
    now += 120_000;
    expect((await run(sandbox, "echo ok")).exitCode).toBe(0);
    const names = claimNames(mock.requests);
    expect(names).toHaveLength(2);
    expect(
      mock.requests.filter((request) => request.path === "/execute").at(-1)
        ?.headers["x-sandbox-id"],
    ).toBe(`pool-${names[1]}`);
    await sandbox.dispose();
  });

  it("disposes idempotently", async () => {
    const mock = await kubernetesServer();
    const sandbox = await activate(kubernetes(mock.url));
    await Promise.all([sandbox.dispose(), sandbox.dispose()]);
    await sandbox.dispose();
    expect(
      mock.requests.filter((request) => request.method === "DELETE"),
    ).toHaveLength(1);
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
