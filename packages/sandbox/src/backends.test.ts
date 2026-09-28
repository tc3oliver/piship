import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  activateSandbox,
  describeContainment,
  HOST_BOUND_VARIABLES,
  SANDBOX_READY_MARKER,
} from "./activate.js";
import {
  capabilityMismatch,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxExecIO,
  type SandboxExecRequest,
  type SandboxExecResult,
  type SandboxInstance,
} from "./backend.js";
import type { SandboxCommand, WrappedCommand } from "./adapter.js";
import { customBackend } from "./custom.js";
import type { SandboxPolicy, SandboxProfile } from "./profile.js";
import { selectAdapter } from "./select.js";

const policy = (overrides: Partial<SandboxPolicy> = {}): SandboxPolicy => ({
  required: true,
  filesystem: { read: { deny: ["~/.ssh"] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: {
    allow: ["PATH", "HOME", "LANG", "DOCS_MODE", "ACME_API_TOKEN"],
  },
  ...overrides,
});

const REMOTE: SandboxCapabilities = {
  isolation: "remote",
  planes: [
    "filesystem-read-deny",
    "filesystem-write-allowlist",
    "network-deny",
    "environment-filter",
  ],
  network: ["deny", "allow"],
  localProcesses: false,
};

/** Answer PiShip's check command the way a contained shell would. */
function answerCheck(request: SandboxExecRequest, io: SandboxExecIO): void {
  io.onStdout(
    Buffer.from(
      `${SANDBOX_READY_MARKER} ${request.env.PISHIP_PROBE_UNLISTED ?? "unset"}\n`,
    ),
  );
  if (request.command.includes("piship-network"))
    io.onStdout(Buffer.from("piship-network-blocked\n"));
}

interface FakeOptions {
  capabilities?: SandboxCapabilities;
  available?: () => Promise<
    { available: true } | { available: false; reason: string }
  >;
  prepare?: () => Promise<void>;
  exec?: (
    request: SandboxExecRequest,
    io: SandboxExecIO,
  ) => Promise<SandboxExecResult>;
  check?: (request: SandboxExecRequest, io: SandboxExecIO) => void;
}

/** A company backend as a custom adapter module would return it. */
function fakeBackend(options: FakeOptions = {}) {
  const events: string[] = [];
  const requests: SandboxExecRequest[] = [];
  const raw = {
    id: "acme-sandbox",
    available: async () => {
      events.push("available");
      return options.available
        ? options.available()
        : { available: true as const };
    },
    capabilities: () => {
      events.push("capabilities");
      return options.capabilities ?? REMOTE;
    },
    prepare: async (): Promise<SandboxInstance> => {
      events.push("prepare");
      await options.prepare?.();
      return {
        exec: async (request, io) => {
          requests.push(request);
          if (request.command.includes(SANDBOX_READY_MARKER)) {
            events.push("check");
            (options.check ?? answerCheck)(request, io);
            return { exitCode: 0 };
          }
          events.push("exec");
          if (options.exec) return options.exec(request, io);
          io.onStdout(Buffer.from(`ran ${request.command}\n`));
          return { exitCode: 0 };
        },
        dispose: async () => {
          events.push("dispose");
        },
      };
    },
  };
  return { backend: customBackend(raw), events, requests };
}

let root: string;
let workspace: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-backends-")));
  workspace = join(root, "ws");
  mkdirSync(join(workspace, "sub"), { recursive: true });
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const activate = (
  backend: SandboxBackend,
  config: SandboxPolicy = policy(),
  extra: { env?: NodeJS.ProcessEnv; settleMs?: number; enable?: boolean } = {},
) =>
  activateSandbox(config, {
    workspace,
    homeDir: join(root, "home"),
    backend,
    env: extra.env ?? { PATH: "/usr/bin", LANG: "C.UTF-8" },
    ...(extra.settleMs !== undefined ? { settleMs: extra.settleMs } : {}),
    ...(extra.enable ? { enable: true } : {}),
  });

const run = async (
  sandbox: Awaited<ReturnType<typeof activateSandbox>>,
  command: string,
  options: { timeout?: number; signal?: AbortSignal; cwd?: string } = {},
) => {
  let output = "";
  const result = await sandbox.exec(command, options.cwd ?? workspace, {
    onData: (chunk) => {
      output += chunk.toString("utf8");
    },
    ...(options.timeout ? { timeout: options.timeout } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  });
  return { ...result, output };
};

describe("custom adapter lifecycle", () => {
  it("checks, prepares, verifies, runs, and disposes in order", async () => {
    const { backend, events, requests } = fakeBackend();
    const sandbox = await activate(backend);
    expect(sandbox.report).toMatchObject({
      level: "enforced",
      adapter: "acme-sandbox",
      provider: "custom",
      required: true,
      verification: "backend-attested",
      localProcesses: false,
      planes: [
        "filesystem-read-deny",
        "filesystem-write-allowlist",
        "network-deny",
        "environment-filter",
      ],
    });
    expect(describeContainment(sandbox.report)).toContain(
      "attested by the backend",
    );
    const result = await run(sandbox, "make test", {
      cwd: join(workspace, "sub"),
    });
    expect(result).toEqual({ exitCode: 0, output: "ran make test\n" });
    expect(requests.at(-1)).toMatchObject({
      command: "make test",
      workspacePath: "sub",
    });
    await sandbox.dispose();
    await sandbox.dispose();
    expect(events).toEqual([
      "available",
      "capabilities",
      "prepare",
      "check",
      "exec",
      "dispose",
    ]);
    await expect(run(sandbox, "true")).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
  });

  it("keeps the provider fixed to custom and rejects malformed adapters", () => {
    const { backend } = fakeBackend();
    expect(backend.provider).toBe("custom");
    expect(() => customBackend(null)).toThrow(/no backend object/);
    expect(() =>
      customBackend({
        id: "Acme Sandbox",
        available() {},
        capabilities() {},
        prepare() {},
      }),
    ).toThrow(/lowercase identifier/);
    expect(() =>
      customBackend({
        id: "linux-bubblewrap",
        available() {},
        capabilities() {},
        prepare() {},
      }),
    ).toThrow(/reserved/);
    expect(() => customBackend({ id: "acme", available() {} })).toThrow(
      /capabilities\(\) is missing/,
    );
  });

  it("fails closed when prepare returns no usable instance", async () => {
    const backend = customBackend({
      id: "acme",
      available: async () => ({ available: true }),
      capabilities: () => REMOTE,
      prepare: async () => ({ exec: "nope" }),
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("exec() and dispose()"),
    });
  });

  it("refuses to wrap local processes, such as MCP stdio servers, for a remote backend", async () => {
    const { backend } = fakeBackend();
    const sandbox = await activate(backend);
    expect(() =>
      sandbox.wrap(process.execPath, ["server.js"], workspace),
    ).toThrow(/cannot contain local processes/);
    await sandbox.dispose();
  });

  it("refuses a working directory outside the workspace", async () => {
    const { backend } = fakeBackend();
    const sandbox = await activate(backend);
    await expect(run(sandbox, "ls", { cwd: root })).rejects.toThrow(
      /outside the workspace/,
    );
    await sandbox.dispose();
  });
});

describe("a required backend that is unavailable fails closed", () => {
  it("throws SANDBOX_UNAVAILABLE and never prepares", async () => {
    const { backend, events } = fakeBackend({
      available: async () => ({
        available: false,
        reason: "the acme sandbox service is down",
      }),
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("the acme sandbox service is down"),
    });
    expect(events).toEqual(["available"]);
  });

  it("treats a throwing availability check as unavailable", async () => {
    const { backend } = fakeBackend({
      available: async () => {
        throw new Error("connect ECONNREFUSED Bearer abcdefgh12345678");
      },
    });
    const error = await activate(backend).catch((caught: unknown) => caught);
    expect(error).toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
    expect(String((error as Error).message)).not.toContain("abcdefgh12345678");
  });

  it("fails closed when prepare fails", async () => {
    const { backend, events } = fakeBackend({
      prepare: async () => {
        throw new Error("quota exceeded");
      },
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining(
        "could not prepare a sandbox: quota exceeded",
      ),
    });
    expect(events).not.toContain("check");
  });

  it("fails closed and disposes when the outside check fails", async () => {
    const { backend, events } = fakeBackend({
      check: (_request, io) => io.onStdout(Buffer.from("something else\n")),
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("did not report back"),
    });
    expect(events.at(-1)).toBe("dispose");
  });

  it("fails closed when an outbound connection succeeds in deny mode", async () => {
    const { backend } = fakeBackend({
      check: (request, io) =>
        io.onStdout(
          Buffer.from(
            `${SANDBOX_READY_MARKER} unset\n${request.command.includes("piship-network") ? "piship-network-reachable\n" : ""}`,
          ),
        ),
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("outbound network connection succeeded"),
    });
  });

  it("fails closed in deny mode when the outbound check cannot run", async () => {
    const { backend } = fakeBackend({
      check: (request, io) =>
        io.onStdout(
          Buffer.from(
            `${SANDBOX_READY_MARKER} unset\n${request.command.includes("piship-network") ? "piship-network-unchecked\n" : ""}`,
          ),
        ),
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("network denial cannot be confirmed"),
    });
    // With the network allowed there is nothing to confirm.
    const sandbox = await activate(
      backend,
      policy({ network: { mode: "allow" } }),
    );
    expect(sandbox.report.level).toBe("enforced");
    await sandbox.dispose();
  });

  it("fails closed when capabilities() throws or availability is malformed", async () => {
    const throwing = customBackend({
      id: "acme",
      available: async () => ({ available: true }),
      capabilities: () => {
        throw new Error("not configured");
      },
      prepare: async () => ({}),
    });
    await expect(activate(throwing)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("reported no capabilities"),
    });
    const malformed = customBackend({
      id: "acme",
      available: async () => "yes",
      capabilities: () => REMOTE,
      prepare: async () => ({}),
    });
    await expect(activate(malformed)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("reported no availability"),
    });
  });

  it("fails closed when the check sees a variable PiShip never sent", async () => {
    const { backend } = fakeBackend({
      check: (_request, io) =>
        io.onStdout(Buffer.from(`${SANDBOX_READY_MARKER} 1\n`)),
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("unapproved environment variable"),
    });
  });

  it("reports unavailable instead of throwing when the sandbox is optional", async () => {
    const { backend } = fakeBackend({
      available: async () => ({ available: false, reason: "down" }),
    });
    const sandbox = await activate(backend, policy({ required: false }), {
      enable: true,
    });
    expect(sandbox.report).toMatchObject({
      level: "unavailable",
      provider: "custom",
      planes: [],
    });
    await sandbox.dispose();
  });
});

describe("capability mismatch", () => {
  const without = (plane: string): SandboxCapabilities => ({
    ...REMOTE,
    planes: REMOTE.planes.filter((item) => item !== plane),
  });

  it.each([
    ["network-deny", "deny"],
    ["environment-filter", "deny"],
    ["filesystem-read-deny", "allow"],
    ["filesystem-write-allowlist", "allow"],
  ] as const)(
    "fails closed when the backend does not provide %s (network %s)",
    async (plane, mode) => {
      const { backend, events } = fakeBackend({ capabilities: without(plane) });
      await expect(
        activate(backend, policy({ network: { mode } })),
      ).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining(`does not provide ${plane}`),
      });
      expect(events).not.toContain("prepare");
    },
  );

  it("fails closed when a network deny mode is not among the backend's modes", async () => {
    const { backend } = fakeBackend({
      capabilities: { ...REMOTE, network: ["allow"] },
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("network-deny"),
    });
  });

  it("does not require network-deny when the policy allows the network", async () => {
    const { backend } = fakeBackend({ capabilities: without("network-deny") });
    const sandbox = await activate(
      backend,
      policy({ network: { mode: "allow" } }),
    );
    expect(sandbox.report.level).toBe("enforced");
    expect(sandbox.report.planes).not.toContain("network-deny");
    await sandbox.dispose();
  });

  it("treats malformed declarations as missing capabilities", () => {
    expect(capabilityMismatch({} as SandboxCapabilities, "deny")).toBeDefined();
    expect(
      capabilityMismatch(
        { ...REMOTE, isolation: "vm" } as unknown as SandboxCapabilities,
        "allow",
      ),
    ).toMatch(/isolation/);
    expect(capabilityMismatch(REMOTE, "deny")).toBeUndefined();
  });
});

describe("the environment a backend receives", () => {
  const env = {
    PATH: "/opt/host/bin",
    HOME: "/home/alice",
    LANG: "C.UTF-8",
    DOCS_MODE: "demo",
    ACME_API_TOKEN: "sk-live-never-in-backends",
    AWS_SECRET_ACCESS_KEY: "aws-never-in-backends",
    GITHUB_TOKEN: "ghp_never_in_backends_000000000000",
    UNLISTED_VARIABLE: "unlisted",
  };

  it("is the allowlist without credentials or host-bound names", async () => {
    const { backend, requests } = fakeBackend();
    const sandbox = await activate(backend, policy(), { env });
    await run(sandbox, "env");
    const request = requests.at(-1);
    expect(request?.env).toEqual({ LANG: "C.UTF-8", DOCS_MODE: "demo" });
    for (const name of HOST_BOUND_VARIABLES)
      expect(request?.env).not.toHaveProperty(name);
    const sent = JSON.stringify(requests);
    for (const secret of [
      "sk-live-never-in-backends",
      "aws-never-in-backends",
      "ghp_never_in_backends",
      "unlisted",
      "/home/alice",
      "/opt/host/bin",
    ])
      expect(sent).not.toContain(secret);
    await sandbox.dispose();
  });

  it("filters a per-command environment the same way", async () => {
    const { backend, requests } = fakeBackend();
    const sandbox = await activate(backend, policy(), { env });
    await sandbox.exec("env", workspace, {
      onData: () => {},
      env: { ...env, DOCS_MODE: "strict", EXTRA: "x" },
    });
    expect(requests.at(-1)?.env).toEqual({
      LANG: "C.UTF-8",
      DOCS_MODE: "strict",
    });
    await sandbox.dispose();
  });
});

describe("PiShip owns timeout, cancellation, and dispose", () => {
  /** A backend command that only ends when its signal aborts. */
  const untilAborted =
    (onAbort: "settle" | "ignore", late?: () => void) =>
    (request: SandboxExecRequest, io: SandboxExecIO) =>
      new Promise<SandboxExecResult>((resolvePromise) => {
        if (!request.command.startsWith("sleep"))
          return resolvePromise({ exitCode: 0 });
        io.onStdout(Buffer.from("started\n"));
        io.signal.addEventListener("abort", () => {
          setTimeout(() => {
            io.onStdout(Buffer.from("after abort\n"));
            late?.();
            if (onAbort === "settle") resolvePromise({ exitCode: 0 });
          }, 10);
        });
      });

  it("reports a timeout even when the backend claims success afterwards", async () => {
    const { backend } = fakeBackend({ exec: untilAborted("settle") });
    const sandbox = await activate(backend);
    let output = "";
    await expect(
      sandbox.exec("sleep 60", workspace, {
        onData: (chunk) => {
          output += chunk.toString("utf8");
        },
        timeout: 0.2,
      }),
    ).rejects.toThrow("timeout:0.2");
    expect(output).toBe("started\n");
    // The instance settled, so it stays usable.
    expect((await run(sandbox, "true")).exitCode).toBe(0);
    await sandbox.dispose();
  });

  it("cancels through the AbortSignal", async () => {
    const { backend } = fakeBackend({ exec: untilAborted("settle") });
    const sandbox = await activate(backend);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);
    await expect(
      run(sandbox, "sleep 60", { signal: controller.signal }),
    ).rejects.toThrow("aborted");
    const aborted = new AbortController();
    aborted.abort();
    await expect(
      run(sandbox, "true", { signal: aborted.signal }),
    ).rejects.toThrow("aborted");
    await sandbox.dispose();
  });

  it("retires a backend that ignores cancellation and disposes it once", async () => {
    const { backend, events } = fakeBackend({ exec: untilAborted("ignore") });
    const sandbox = await activate(backend, policy(), { settleMs: 50 });
    await expect(run(sandbox, "sleep 60", { timeout: 0.1 })).rejects.toThrow(
      "timeout:0.1",
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
    expect(events.filter((event) => event === "dispose")).toHaveLength(1);
    await expect(run(sandbox, "true")).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining("retired"),
    });
    expect(() => sandbox.wrap("/bin/true", [], workspace)).toThrow(/retired/);
    await sandbox.dispose();
    expect(events.filter((event) => event === "dispose")).toHaveLength(1);
  });

  it("redacts a backend failure", async () => {
    const { backend } = fakeBackend({
      exec: async () => {
        throw new Error("upstream said Authorization: Bearer abcdefgh12345678");
      },
    });
    const sandbox = await activate(backend);
    const error = await run(sandbox, "true").catch((caught: unknown) => caught);
    expect(String((error as Error).message)).not.toContain("abcdefgh12345678");
    await sandbox.dispose();
  });

  it("maps a signal exit to 128 + signal number", async () => {
    const { backend } = fakeBackend({
      exec: async () => ({ exitCode: null, signal: "SIGTERM" }),
    });
    const sandbox = await activate(backend);
    expect((await run(sandbox, "true")).exitCode).toBe(143);
    await sandbox.dispose();
  });
});

const native = selectAdapter();
const nativeReady = (await native.available()).available;
const requireSandbox = process.env.PISHIP_REQUIRE_SANDBOX === "1";

describe("a local custom backend is proven by the live probe", () => {
  const LOCAL: SandboxCapabilities = {
    ...REMOTE,
    isolation: "local",
    localProcesses: true,
  };
  /** A company wrapper around a local mechanism; `contain: false` wraps nothing. */
  const local = (contain: boolean) =>
    customBackend({
      id: "acme-local",
      available: async () => ({ available: true }),
      capabilities: () => LOCAL,
      prepare: async ({ profile }: { profile: SandboxProfile }) => ({
        wrap: (command: SandboxCommand): WrappedCommand =>
          contain
            ? native.wrap(profile, command)
            : { ...command, args: [...command.args] },
        exec: async () => ({ exitCode: 0 }),
        dispose: async () => {},
      }),
    });

  it.skipIf(process.platform === "win32")(
    "rejects a local backend whose wrap contains nothing",
    async () => {
      await expect(activate(local(false))).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining("a write outside the allowed paths"),
      });
    },
  );

  it.skipIf(!nativeReady && !requireSandbox)(
    "reports live-probe verification for a local backend that really contains",
    async () => {
      const sandbox = await activate(local(true));
      expect(sandbox.report).toMatchObject({
        level: "enforced",
        provider: "custom",
        verification: "live-probe",
        localProcesses: true,
      });
      await sandbox.dispose();
    },
  );
});
