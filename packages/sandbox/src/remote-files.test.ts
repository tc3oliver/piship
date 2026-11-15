import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createManagedFetch, DEFAULT_NETWORK_POLICY } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { activateSandbox, describeContainment } from "./activate.js";
import type { SandboxBackend } from "./backend.js";
import type { SandboxPolicy } from "./profile.js";
import { E2bCompatibleBackend, EnvelopeReader } from "./remote/e2b.js";
import { e2bServer, type StartRequest } from "./testing/e2b-server.js";
import { closeMockServers, leaks } from "./testing/mock-server.js";

const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY, "sandbox");
const policy: SandboxPolicy = {
  required: true,
  filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: { allow: ["LANG"] },
  remoteWorkspace: true,
};

let root: string;
let workspace: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-remote-files-")));
  workspace = join(root, "ws");
  mkdirSync(join(workspace, "sub"), { recursive: true });
});
afterEach(async () => {
  await closeMockServers();
  rmSync(root, { recursive: true, force: true });
});

const backend = (url: string, key?: string) =>
  new E2bCompatibleBackend({
    endpoint: url,
    fetch,
    envdUrl: () => url,
    ...(key ? { credential: async () => key } : {}),
  });
const activate = (b: SandboxBackend, config = policy) =>
  activateSandbox(config, {
    workspace,
    homeDir: join(root, "home"),
    backend: b,
    env: {},
    settleMs: 2000,
  });

describe("remote workspace file access", () => {
  it("writes, reads and stats through envd and reports the workspace as remote", async () => {
    const files = new Map<string, Buffer>();
    const mock = await e2bServer({ files });
    const sandbox = await activate(backend(mock.url));
    expect(sandbox.report.workspace).toMatchObject({
      declared: "remote",
      effective: "remote",
      verification: "not-required",
    });
    expect(describeContainment(sandbox.report)).toContain("Workspace: remote");
    const path = join(workspace, "sub", "a.bin");
    const data = Buffer.from([0, 1, 2, 255, 13, 10, 45, 45]);
    await sandbox.files?.write(path, data);
    expect(files.get("/home/user/sub/a.bin")).toEqual(data);
    expect(await sandbox.files?.read(path)).toEqual(data);
    expect(await sandbox.files?.stat(path)).toEqual({ type: "file", size: 8 });
    expect(await sandbox.files?.stat(join(workspace, "sub"))).toMatchObject({
      type: "directory",
    });
    expect(await sandbox.files?.stat(join(workspace, "none"))).toBeUndefined();
    await expect(
      sandbox.files?.read(join(workspace, "none")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await sandbox.dispose();
  });

  it("renews the timeout for file calls at most once a minute, and for every command", async () => {
    const mock = await e2bServer({ files: new Map() });
    const sandbox = await activate(backend(mock.url));
    const renewals = () =>
      mock.requests.filter((r) => r.path === "/sandboxes/sbx1/timeout").length;
    const path = join(workspace, "sub", "a.txt");
    const before = renewals();
    for (let i = 0; i < 3; i++)
      await sandbox.files?.write(path, Buffer.from("x"));
    expect(renewals()).toBe(before);
    await sandbox.exec("true", workspace, { onData: () => {} });
    expect(renewals()).toBe(before + 1);
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 61_000);
      await sandbox.files?.read(path);
      await sandbox.files?.read(path);
      expect(renewals()).toBe(before + 2);
    } finally {
      vi.useRealTimers();
    }
    await sandbox.dispose();
  });

  it("fails a read shorter than its Content-Length and refuses an oversized announcement", async () => {
    const mock = await e2bServer({
      files: new Map([["/home/user/a", Buffer.from("abc")]]),
    });
    const announce: { length?: string; encoding?: string } = {};
    const lying: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      if (
        !String(input).includes("/files?") ||
        init?.method !== "GET" ||
        !response.ok
      )
        return response;
      return new Response(Buffer.from("abc"), {
        headers: {
          "content-length": announce.length ?? "3",
          ...(announce.encoding
            ? { "content-encoding": announce.encoding }
            : {}),
        },
      });
    };
    const sandbox = await activate(
      new E2bCompatibleBackend({
        endpoint: mock.url,
        fetch: lying,
        envdUrl: () => mock.url,
      }),
    );
    const path = join(workspace, "a");
    expect(await sandbox.files?.read(path)).toEqual(Buffer.from("abc"));
    announce.length = "10";
    await expect(sandbox.files?.read(path)).rejects.toThrow(
      /3 of the 10 bytes/,
    );
    announce.encoding = "gzip"; // the length then counts the compressed body
    expect(await sandbox.files?.read(path)).toEqual(Buffer.from("abc"));
    delete announce.encoding;
    announce.length = String(101 * 1024 * 1024);
    await expect(sandbox.files?.read(path)).rejects.toThrow(/too large/);
    await sandbox.dispose();
  });

  it("rejects at once when the caller's signal is already aborted", async () => {
    const mock = await e2bServer({ files: new Map() });
    const sandbox = await activate(backend(mock.url));
    const before = mock.requests.length;
    await expect(
      sandbox.files?.read(join(workspace, "sub", "a"), {
        signal: AbortSignal.abort(),
      }),
    ).rejects.toThrow(/aborted/);
    expect(mock.requests.length).toBe(before);
    await sandbox.dispose();
  });

  it("refuses paths outside the workspace without contacting the sandbox", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(backend(mock.url));
    const before = mock.requests.length;
    for (const path of [join(root, "other"), join(workspace, ".."), workspace])
      await expect(sandbox.files?.read(path)).rejects.toThrow(
        /only the project/,
      );
    expect(mock.requests.length).toBe(before);
    await sandbox.dispose();
  });

  it("sends envd credentials only to envd and keeps secrets out of URLs and errors", async () => {
    const key = "fake-sandbox-key-SENTINEL-0003";
    const mock = await e2bServer({ apiKey: key });
    const sandbox = await activate(backend(mock.url, key));
    await sandbox.files?.write(join(workspace, "x"), Buffer.from("hi"));
    await sandbox.files?.read(join(workspace, "x"));
    const envd = mock.requests.filter(
      (r) => r.path.startsWith("/files") || r.path.includes("Filesystem"),
    );
    expect(envd.length).toBe(2);
    for (const r of envd) {
      expect(r.headers["x-access-token"]).toBe("envd-token-1");
      expect(r.headers["x-api-key"]).toBeUndefined();
      expect(r.headers.authorization).toBe(
        `Basic ${Buffer.from("user:").toString("base64")}`,
      );
      expect(r.path).not.toContain("envd-token-1");
    }
    expect(leaks(mock.requests, key, ["x-api-key"])).toEqual([]);
    expect(leaks(envd, "envd-token-1", ["x-access-token"])).toEqual([]);
    await sandbox.dispose();
  });

  it("fails with a redacted error when envd refuses the user", async () => {
    const script: { user?: string } = {};
    const mock = await e2bServer(script);
    const sandbox = await activate(backend(mock.url));
    // After activation, so only the file request meets the refusal.
    script.user = "root";
    const error = await sandbox.files
      ?.read(join(workspace, "x"))
      .catch((caught: unknown) => caught);
    expect(String((error as Error).message)).toMatch(/HTTP 401/);
    expect(String((error as Error).message)).not.toContain("envd-token-1");
    await sandbox.dispose();
  });

  it("refuses file access after dispose with SANDBOX_UNAVAILABLE", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(backend(mock.url));
    await sandbox.dispose();
    await expect(
      sandbox.files?.read(join(workspace, "x")),
    ).rejects.toMatchObject({ code: "SANDBOX_UNAVAILABLE" });
  });

  it("fails closed for a local backend and for an instance without files", async () => {
    const local: SandboxBackend = {
      id: "local-fake",
      provider: "custom",
      available: async () => ({ available: true }),
      capabilities: () => ({
        isolation: "local",
        planes: ["network-deny", "environment-filter"],
        network: ["deny", "allow"],
        localProcesses: false,
      }),
      prepare: async () => {
        throw new Error("must not prepare");
      },
    };
    await expect(activate(local)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
    const mock = await e2bServer();
    const real = backend(mock.url);
    const bare: SandboxBackend = {
      id: real.id,
      provider: real.provider,
      available: () => real.available(),
      capabilities: () => real.capabilities(),
      prepare: async (request) => {
        const { files: _files, ...instance } = await real.prepare(request);
        return instance;
      },
    };
    await expect(activate(bare)).rejects.toMatchObject({
      code: "SANDBOX_UNAVAILABLE",
    });
  });

  it("creates the workdir from / before the first command when asked", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(
      new E2bCompatibleBackend({
        endpoint: mock.url,
        fetch,
        envdUrl: () => mock.url,
        createWorkdir: true,
      }),
    );
    const starts = mock.requests
      .filter((r) => r.path === "/process.Process/Start")
      .map(
        (r) => new EnvelopeReader().push(r.body)[0]?.message as StartRequest,
      );
    expect(starts[0]?.process).toMatchObject({
      cwd: "/",
      args: ["-l", "-c", "mkdir -p -- '/home/user'"],
    });
    expect(starts.length).toBeGreaterThan(1);
    await sandbox.dispose();
  });

  it("keeps an idle remote workspace alive and stops when disposed", async () => {
    const script: Parameters<typeof e2bServer>[0] = {};
    const mock = await e2bServer(script);
    const renewals = () =>
      mock.requests.filter((r) => r.path === "/sandboxes/sbx1/timeout").length;
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      const sandbox = await activate(
        new E2bCompatibleBackend({
          endpoint: mock.url,
          fetch,
          envdUrl: () => mock.url,
          createWorkdir: true,
          lifetimeSeconds: 400,
        }),
      );
      const before = renewals();
      await vi.advanceTimersByTimeAsync(100_000);
      await vi.waitFor(() => expect(renewals()).toBe(before + 1));
      // A renewal that fails is ignored; the timer goes on.
      script.gone = true;
      await vi.advanceTimersByTimeAsync(100_000);
      await vi.waitFor(() => expect(renewals()).toBe(before + 2));
      await sandbox.dispose();
      await vi.advanceTimersByTimeAsync(500_000);
      expect(renewals()).toBe(before + 2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("marks a sandbox that expired, for the file and command paths alike", async () => {
    const script: Parameters<typeof e2bServer>[0] = {};
    const mock = await e2bServer(script);
    const sandbox = await activate(backend(mock.url));
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      script.gone = true;
      vi.setSystemTime(Date.now() + 61_000);
      await expect(
        sandbox.files?.read(join(workspace, "a")),
      ).rejects.toMatchObject({
        code: "SANDBOX_GONE",
        message: expect.stringMatching(/expired or was lost/),
      });
      await expect(
        sandbox.exec("true", workspace, { onData: () => {} }),
      ).rejects.toMatchObject({ code: "SANDBOX_GONE" });
    } finally {
      vi.useRealTimers();
    }
    await sandbox.dispose();
  });

  it("has no file access without remoteWorkspace", async () => {
    const mock = await e2bServer();
    const sandbox = await activate(backend(mock.url), {
      ...policy,
      remoteWorkspace: false,
    });
    expect(sandbox.files).toBeUndefined();
    expect(sandbox.report.workspace?.declared).toBe("snapshot");
    await sandbox.dispose();
  });
});
