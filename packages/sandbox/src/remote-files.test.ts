import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createManagedFetch, DEFAULT_NETWORK_POLICY } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
