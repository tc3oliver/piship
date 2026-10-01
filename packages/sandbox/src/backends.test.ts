import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
} from "node:fs";
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
  claimedGuarantees,
  enforcesPathPolicy,
  networkProbe,
  type SandboxBackend,
  type SandboxCapabilities,
  type SandboxExecIO,
  type SandboxExecRequest,
  type SandboxExecResult,
} from "./backend.js";
import { customBackend } from "./custom.js";
import type { SandboxPolicy, SandboxProfile } from "./profile.js";
import { selectAdapter } from "./select.js";
import {
  answerCheck,
  fakeBackend,
  fakeWrappingBackend,
  PATH_PLANES,
  PROBED_CAPABILITIES as PROBED,
  REMOTE_CAPABILITIES as REMOTE,
  TEST_PROBE,
} from "./testing/fake-backend.js";

const policy = (overrides: Partial<SandboxPolicy> = {}): SandboxPolicy => ({
  required: true,
  filesystem: { read: { deny: ["~/.ssh"] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: {
    allow: ["PATH", "HOME", "LANG", "DOCS_MODE", "ACME_API_TOKEN"],
  },
  ...overrides,
});

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
        "network-deny",
        "environment-filter",
        "host-filesystem-isolation",
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

  it("fails closed when the network probe is reachable in deny mode", async () => {
    // A backend whose deny mode lets everything through.
    const { backend, events } = fakeBackend({
      capabilities: PROBED,
      check: (request, io) => answerCheck(request, io, "allow"),
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining(
        "a connection to the backend's network probe succeeded although the network is denied",
      ),
    });
    // No allow-mode sandbox is created for a violation.
    expect(events.filter((event) => event === "prepare")).toHaveLength(1);
    expect(events.at(-1)).toBe("dispose");
  });

  it("reports network denial attested when the connection check cannot run", async () => {
    const { backend, events } = fakeBackend({
      capabilities: PROBED,
      check: (request, io) =>
        io.onStdout(
          Buffer.from(
            `${SANDBOX_READY_MARKER} unset\n${request.command.includes("/dev/tcp/") ? "piship-network-unchecked\n" : ""}`,
          ),
        ),
    });
    const sandbox = await activate(backend);
    expect(sandbox.report).toMatchObject({
      level: "enforced",
      planes: expect.arrayContaining(["network-deny"]),
      networkDenial: {
        evidence: "attested",
        probe: true,
        reason: expect.stringContaining("could not run inside the sandbox"),
      },
    });
    expect(sandbox.report.warnings).toContainEqual(
      expect.stringContaining(
        "network denial is attested by the backend, not verified",
      ),
    );
    expect(events.filter((event) => event === "prepare")).toHaveLength(1);
    await sandbox.dispose();
    // With the network allowed there is nothing to check.
    const allowed = await activate(
      backend,
      policy({ network: { mode: "allow" } }),
    );
    expect(allowed.report.level).toBe("enforced");
    expect(allowed.report.networkDenial).toBeUndefined();
    await allowed.dispose();
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
    ["host-filesystem-isolation", "allow"],
  ] as const)(
    "fails closed when a remote backend does not provide %s (network %s)",
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

  it.each(PATH_PLANES)(
    "fails closed when a local backend does not provide %s",
    async (plane) => {
      const { backend, events } = fakeBackend({
        capabilities: {
          isolation: "local",
          planes: (
            [...PATH_PLANES, "network-deny", "environment-filter"] as const
          ).filter((item) => item !== plane),
          network: ["deny", "allow"],
          localProcesses: false,
        },
      });
      await expect(activate(backend)).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining(`does not provide ${plane}`),
      });
      expect(events).not.toContain("prepare");
    },
  );

  it("does not accept filesystem path planes in place of host isolation for a remote backend", async () => {
    // A remote backend that claims PiShip's path planes but not host
    // isolation cannot run: the path planes are not what a remote run needs.
    const { backend } = fakeBackend({
      capabilities: {
        ...REMOTE,
        planes: [...PATH_PLANES, "network-deny", "environment-filter"],
      },
    });
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining(
        "does not provide host-filesystem-isolation",
      ),
    });
  });

  it("never lets host isolation stand in for a local backend's path policy", () => {
    expect(
      capabilityMismatch(
        {
          isolation: "local",
          planes: [
            "host-filesystem-isolation",
            "network-deny",
            "environment-filter",
          ],
          network: ["deny"],
          localProcesses: false,
        },
        "deny",
      ),
    ).toBe(
      "it does not provide filesystem-read-deny, filesystem-write-allowlist",
    );
    expect(
      claimedGuarantees(
        {
          ...REMOTE,
          isolation: "local",
          planes: ["host-filesystem-isolation"],
        },
        "deny",
      ),
    ).toEqual([]);
  });

  it("reports path planes for a remote backend only when it declares them", async () => {
    const plain = fakeBackend();
    const sandbox = await activate(plain.backend);
    for (const plane of PATH_PLANES)
      expect(sandbox.report.planes).not.toContain(plane);
    expect(describeContainment(sandbox.report)).toContain(
      "does not enforce sandbox.filesystem path rules",
    );
    await sandbox.dispose();
    // A company backend that maps the path policy into its sandbox may say so.
    const mapped = fakeBackend({
      capabilities: { ...REMOTE, planes: [...REMOTE.planes, ...PATH_PLANES] },
    });
    const withPaths = await activate(mapped.backend);
    expect(withPaths.report.planes).toEqual(
      expect.arrayContaining([...PATH_PLANES, "host-filesystem-isolation"]),
    );
    expect(describeContainment(withPaths.report)).not.toContain("path rules");
    await withPaths.dispose();
  });

  it.each(PATH_PLANES)(
    "reports a remote backend with only %s as partly enforcing the path policy",
    async (plane) => {
      const { backend } = fakeBackend({
        capabilities: { ...REMOTE, planes: [...REMOTE.planes, plane] },
      });
      const sandbox = await activate(backend);
      expect(sandbox.report.planes).toContain(plane);
      expect(enforcesPathPolicy(sandbox.report.planes)).toBe(false);
      expect(describeContainment(sandbox.report)).toContain(
        `sandbox.filesystem path rules are only partly enforced by the backend (${plane} only)`,
      );
      await sandbox.dispose();
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

describe("remote network denial evidence", () => {
  const modes = (options: Parameters<typeof fakeBackend>[0] = {}) => {
    const prepared: string[] = [];
    const profiles: SandboxProfile[] = [];
    const fake = fakeBackend({
      ...options,
      onPrepare: (profile) => {
        prepared.push(profile.network);
        profiles.push(profile);
      },
    });
    return { ...fake, prepared, profiles };
  };

  it("is verified when the same probe is reachable with the network allowed and blocked with it denied", async () => {
    const { backend, events, requests, prepared, profiles } = modes({
      capabilities: PROBED,
    });
    const sandbox = await activate(backend);
    // The allow-mode sandbox gets an empty workspace PiShip made, nothing
    // protected, and no environment; it is gone once activation returns.
    const [session, contrast] = profiles;
    expect(session?.workspace).toBe(workspace);
    expect(contrast?.workspace).not.toBe(workspace);
    expect(contrast?.workspace.startsWith(`${workspace}/`)).toBe(false);
    expect(contrast).toMatchObject({
      network: "allow",
      environmentAllow: [],
      readDeny: [],
      writeProtect: { files: [], directories: [] },
    });
    expect(existsSync(contrast?.workspace ?? "")).toBe(false);
    expect(requests[0]?.env).toMatchObject({ LANG: "C.UTF-8" });
    expect(requests[1]?.env).toEqual({});
    expect(sandbox.report).toMatchObject({
      verification: "backend-attested",
      planes: expect.arrayContaining(["network-deny"]),
      networkDenial: { evidence: "verified", probe: true },
    });
    expect(sandbox.report.networkDenial?.reason).toBeUndefined();
    expect(describeContainment(sandbox.report)).toContain(
      "network deny (verified)",
    );
    // One deny sandbox for the session and one allow sandbox for the
    // contrast, gone before the session runs anything; both checks ask
    // about the same target.
    expect(prepared).toEqual(["deny", "allow"]);
    expect(events).toEqual([
      "available",
      "capabilities",
      "prepare",
      "check",
      "prepare",
      "check",
      "dispose",
    ]);
    const checks = requests.map((request) => request.command);
    expect(checks).toHaveLength(2);
    for (const command of checks)
      expect(command).toContain(
        `/dev/tcp/${TEST_PROBE.host}/${TEST_PROBE.port}'`,
      );
    await sandbox.dispose();
  });

  it("proves nothing when the check asks about a target the allow-mode sandbox cannot reach", async () => {
    // The fake's allow mode reaches a different target than the one declared.
    const { backend } = modes({
      capabilities: PROBED,
      network: { reachable: ["elsewhere.sandbox.test:8443"] },
    });
    const sandbox = await activate(backend);
    expect(sandbox.report.networkDenial).toEqual({
      evidence: "attested",
      probe: true,
      reason:
        "the backend's network probe was not reachable from an allow-mode sandbox either, so a blocked connection proves nothing",
    });
    expect(sandbox.report.planes).toContain("network-deny");
    expect(sandbox.report.warnings).toContain(
      "network denial is attested by the backend, not verified: the backend's network probe was not reachable from an allow-mode sandbox either, so a blocked connection proves nothing",
    );
    expect(describeContainment(sandbox.report)).toContain(
      "network deny (attested by the backend, not verified)",
    );
    await sandbox.dispose();
  });

  it("is attested, not failed, without a network probe, and creates no allow-mode sandbox", async () => {
    const { backend, requests, prepared } = modes();
    const sandbox = await activate(backend);
    expect(sandbox.report).toMatchObject({
      level: "enforced",
      planes: expect.arrayContaining(["network-deny"]),
      networkDenial: {
        evidence: "attested",
        probe: false,
        reason: "the backend declares no network probe to check it with",
      },
    });
    // Attested exactly as declared: not lower than the backend claims.
    expect(sandbox.report.warnings).not.toContainEqual(
      expect.stringContaining("network denial"),
    );
    expect(prepared).toEqual(["deny"]);
    expect(requests[0]?.command).not.toContain("/dev/tcp/");
    await sandbox.dispose();
  });

  it("is attested when the backend can only deny the network, and creates no allow-mode sandbox", async () => {
    const { backend, prepared } = modes({
      capabilities: { ...PROBED, network: ["deny"] },
    });
    const sandbox = await activate(backend);
    expect(sandbox.report.networkDenial).toMatchObject({
      evidence: "attested",
      probe: true,
      reason: expect.stringContaining("cannot allow the network"),
    });
    expect(prepared).toEqual(["deny"]);
    await sandbox.dispose();
  });

  it("is attested when the allow-mode sandbox cannot be created", async () => {
    let calls = 0;
    const { backend, events, profiles } = modes({
      capabilities: PROBED,
      prepare: async () => {
        if (++calls === 2) throw new Error("no capacity");
      },
    });
    const sandbox = await activate(backend);
    expect(sandbox.report.networkDenial).toMatchObject({
      evidence: "attested",
      reason: expect.stringContaining(
        "could not prepare an allow-mode sandbox",
      ),
    });
    expect(sandbox.report.level).toBe("enforced");
    expect(profiles).toHaveLength(2);
    expect(existsSync(profiles[1]?.workspace ?? "")).toBe(false);
    await sandbox.dispose();
    expect(events.filter((event) => event === "dispose")).toHaveLength(1);
  });

  it("is attested when the allow-mode check fails, and disposes the allow-mode sandbox", async () => {
    const { backend, events, profiles } = modes({
      capabilities: PROBED,
      check: (request, io, mode) =>
        mode === "allow"
          ? io.onStdout(Buffer.from("something else\n"))
          : answerCheck(request, io, mode),
    });
    const sandbox = await activate(backend);
    expect(sandbox.report.networkDenial?.evidence).toBe("attested");
    expect(events.filter((event) => event === "dispose")).toHaveLength(1);
    expect(existsSync(profiles[1]?.workspace ?? "")).toBe(false);
    await sandbox.dispose();
  });

  it("fails closed on a malformed network probe before anything is created", async () => {
    for (const networkProbe of [
      { host: "probe.sandbox.test; rm -rf /", port: 8443 },
      { host: "-oProxyCommand=x", port: 8443 },
      { host: "[::1]", port: 8443 },
      { host: "probe.sandbox.test", port: 0 },
      { host: "probe.sandbox.test", port: 1.5 },
      "probe.sandbox.test:8443",
    ]) {
      const { backend, events } = modes({
        capabilities: {
          ...REMOTE,
          networkProbe,
        } as unknown as SandboxCapabilities,
      });
      await expect(activate(backend)).rejects.toMatchObject({
        code: "SANDBOX_UNAVAILABLE",
        message: expect.stringContaining("malformed network probe"),
      });
      expect(events).not.toContain("prepare");
    }
  });

  it("ignores a local backend's network probe: the live probe decides", () => {
    expect(
      networkProbe({
        isolation: "local",
        planes: [],
        network: ["deny"],
        localProcesses: true,
        networkProbe: { host: "bad host", port: 0 },
      }),
    ).toBeUndefined();
    expect(networkProbe(PROBED)).toEqual({ probe: TEST_PROBE });
    expect(networkProbe(REMOTE)).toBeUndefined();
  });

  it("does not check the network when the policy allows it", async () => {
    const { backend, requests, prepared } = modes({ capabilities: PROBED });
    const sandbox = await activate(
      backend,
      policy({ network: { mode: "allow" } }),
    );
    expect(sandbox.report.networkDenial).toBeUndefined();
    expect(prepared).toEqual(["allow"]);
    expect(requests[0]?.command).not.toContain("/dev/tcp/");
    await sandbox.dispose();
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

describe("custom backend deadlines", () => {
  const never = () => new Promise<never>(() => undefined);
  const instance = (
    dispose: (options?: { signal?: AbortSignal }) => Promise<void>,
  ) => ({
    exec: async () => ({ exitCode: 0 }),
    dispose,
  });

  it("fails activation when available() never answers, naming the backend", {
    timeout: 2_000,
  }, async () => {
    let seen: AbortSignal | undefined;
    const backend = customBackend(
      {
        id: "acme",
        available: (options?: { signal?: AbortSignal }) => {
          seen = options?.signal;
          return never();
        },
        capabilities: () => REMOTE,
        prepare: never,
      },
      { availableMs: 20 },
    );
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining(
        "the acme sandbox backend did not answer available() within 1 s",
      ),
    });
    expect(seen?.aborted).toBe(true);
  });

  it("fails activation when prepare() never answers, and disposes an instance that arrives late", {
    timeout: 2_000,
  }, async () => {
    let seen: AbortSignal | undefined;
    let deliver: (value: unknown) => void = () => {};
    let disposed = 0;
    const backend = customBackend(
      {
        id: "acme",
        available: async () => ({ available: true }),
        capabilities: () => REMOTE,
        prepare: (request: { signal?: AbortSignal }) => {
          seen = request.signal;
          return new Promise((resolve) => {
            deliver = resolve;
          });
        },
      },
      { prepareMs: 20 },
    );
    await expect(activate(backend)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
      message: expect.stringContaining(
        "the acme sandbox backend did not answer prepare() within 1 s",
      ),
    });
    expect(seen?.aborted).toBe(true);
    deliver(
      instance(async () => {
        disposed += 1;
      }),
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(disposed).toBe(1);
  });

  it("ends a dispose() that never answers without throwing, and says so", {
    timeout: 2_000,
  }, async () => {
    const notices: string[] = [];
    let seen: AbortSignal | undefined;
    const backend = customBackend(
      {
        id: "acme",
        available: async () => ({ available: true }),
        capabilities: () => REMOTE,
        prepare: async () =>
          instance((options) => {
            seen = options?.signal;
            return never();
          }),
      },
      { disposeMs: 20, notify: (message) => notices.push(message) },
    );
    const prepared = await backend.prepare({ profile: {} as SandboxProfile });
    await expect(prepared.dispose()).resolves.toBeUndefined();
    expect(seen?.aborted).toBe(true);
    expect(notices).toEqual([
      expect.stringContaining(
        "the acme sandbox backend did not answer dispose() within 1 s",
      ),
    ]);
  });

  it("keeps a backend that ignores the signal, and its own dispose() failure", async () => {
    const backend = customBackend({
      id: "acme",
      available: async () => ({ available: true }),
      capabilities: () => REMOTE,
      prepare: async () =>
        instance(async () => {
          throw new Error("service refused");
        }),
    });
    await expect(backend.available()).resolves.toEqual({ available: true });
    const prepared = await backend.prepare({ profile: {} as SandboxProfile });
    await expect(prepared.dispose()).rejects.toThrow("service refused");
  });
});

const native = selectAdapter();
const nativeReady = (await native.available()).available;
const requireSandbox = process.env.PISHIP_REQUIRE_SANDBOX === "1";

describe("a local custom backend is proven by the live probe", () => {
  /** A company wrapper around a local mechanism; `contain: false` wraps nothing. */
  const local = (contain: boolean) => fakeWrappingBackend(native, contain);

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
