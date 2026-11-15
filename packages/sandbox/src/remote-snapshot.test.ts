import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createManagedFetch, DEFAULT_NETWORK_POLICY } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { activateSandbox } from "./activate.js";
import type { SandboxBackend } from "./backend.js";
import { customBackend } from "./custom.js";
import type { SandboxPolicy } from "./profile.js";
import { E2bCompatibleBackend } from "./remote/e2b.js";
import { e2bServer } from "./testing/e2b-server.js";
import { closeMockServers, leaks } from "./testing/mock-server.js";

const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY, "sandbox");
const policy: SandboxPolicy = {
  required: true,
  filesystem: { read: { deny: [] }, write: { allow: ["workspace"] } },
  network: { mode: "deny" },
  environment: { allow: ["LANG"] },
  remoteWorkspace: true,
};
const KEY = "e2b-key-never-in-a-body";

let root: string;
let workspace: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-snapshot-")));
  workspace = join(root, "ws");
  mkdirSync(workspace, { recursive: true });
});
afterEach(async () => {
  await closeMockServers();
  rmSync(root, { recursive: true, force: true });
});

const backend = (url: string) =>
  new E2bCompatibleBackend({
    endpoint: url,
    fetch,
    envdUrl: () => url,
    credential: async () => KEY,
  });
const activate = (b: SandboxBackend, remoteWorkspace = true) =>
  activateSandbox(
    { ...policy, remoteWorkspace },
    {
      workspace,
      homeDir: join(root, "home"),
      backend: b,
      env: {},
      settleMs: 2000,
    },
  );

describe("e2b snapshots", () => {
  it("saves a snapshot with no name, sends the key only in its header, and creates from the id", async () => {
    const script = { apiKey: KEY };
    const mock = await e2bServer(script);
    const first = await activate(backend(mock.url));
    expect(await first.snapshot?.()).toEqual({ id: "snap-1" });
    const request = mock.requests.find((item) =>
      item.path.endsWith("/snapshots"),
    );
    expect(request?.method).toBe("POST");
    expect(request?.path).toBe("/sandboxes/sbx1/snapshots");
    expect(JSON.parse(request?.body.toString() ?? "")).toEqual({
      memory: false,
    });
    expect(leaks(mock.requests, KEY, ["x-api-key"])).toEqual([]);
    // The timeout is renewed before the snapshot, never during a command.
    const paths = mock.requests.map((item) => item.path);
    expect(paths.indexOf("/sandboxes/sbx1/timeout")).toBeLessThan(
      paths.indexOf("/sandboxes/sbx1/snapshots"),
    );
    await first.dispose();

    const b = backend(mock.url);
    const instance = await b.prepare({
      profile: first.profile,
      template: "snap-1",
    });
    const create = mock.requests.filter(
      (item) => item.method === "POST" && item.path === "/sandboxes",
    );
    expect(JSON.parse(create.at(-1)?.body.toString() ?? "")).toMatchObject({
      templateID: "snap-1",
    });
    await instance.dispose();
  });

  it("stops a snapshot that is still saving when the caller's signal aborts", async () => {
    const mock = await e2bServer({ holdSnapshot: true });
    const sandbox = await activate(backend(mock.url));
    const abort = new AbortController();
    const saving = sandbox.snapshot?.({ signal: abort.signal });
    for (
      let i = 0;
      i < 200 &&
      !mock.requests.some((item) => item.path.endsWith("/snapshots"));
      i++
    )
      await new Promise((done) => setTimeout(done, 10));
    abort.abort();
    await expect(saving).rejects.toThrow(/aborted/);
    await sandbox.dispose();
  });

  it("maps 404, 405 and 501 to an unsupported error and 503 to a plain failure", async () => {
    for (const status of [404, 405, 501]) {
      const mock = await e2bServer({ snapshot: status });
      const sandbox = await activate(backend(mock.url));
      await expect(sandbox.snapshot?.()).rejects.toMatchObject({
        code: "SNAPSHOT_UNSUPPORTED",
      });
      await sandbox.dispose();
    }
    const mock = await e2bServer({ snapshot: 503 });
    const sandbox = await activate(backend(mock.url));
    const error = await sandbox.snapshot?.().catch((caught) => caught);
    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBeUndefined();
    expect(error.message).toContain("503");
    await sandbox.dispose();
  });

  it("surfaces a snapshot that is gone as a typed error and does not retry", async () => {
    const mock = await e2bServer();
    const before = mock.requests.length;
    await expect(
      backend(mock.url).prepare({
        profile: (await activate(backend(mock.url))).profile,
        template: "snap-9",
      }),
    ).rejects.toMatchObject({ code: "SNAPSHOT_GONE" });
    const creates = mock.requests
      .slice(before)
      .filter((item) => item.method === "POST" && item.path === "/sandboxes");
    // One create for the helper activation and exactly one for the snapshot.
    expect(creates).toHaveLength(2);
    // A failure that is not about the snapshot stays a plain error.
    const busy = await e2bServer({
      createFromSnapshot: 503,
      snapshots: ["snap-1"],
    });
    const error = await backend(busy.url)
      .prepare({
        profile: (await activate(backend(busy.url))).profile,
        template: "snap-1",
      })
      .catch((caught) => caught);
    expect(error.message).toContain("503");
    expect(error.code).toBeUndefined();
  });

  it("refuses an id that is not a plain snapshot id before any request", async () => {
    const mock = await e2bServer();
    const profile = (await activate(backend(mock.url))).profile;
    const before = mock.requests.length;
    for (const template of ["../x", "a b", "", "x".repeat(200)])
      await expect(
        backend(mock.url).prepare({ profile, template }),
      ).rejects.toThrow(/not valid/);
    expect(mock.requests.length).toBe(before);
  });

  it("deletes a snapshot by id, escaping it, and treats a missing one as gone", async () => {
    const script = { apiKey: KEY, snapshots: ["snap-1"] };
    const mock = await e2bServer(script);
    await backend(mock.url).deleteSnapshot("snap-1");
    expect(script.snapshots).toEqual([]);
    const request = mock.requests.at(-1);
    expect(request).toMatchObject({
      method: "DELETE",
      path: "/templates/snap-1",
    });
    expect(request?.headers["x-api-key"]).toBe(KEY);
    await expect(
      backend(mock.url).deleteSnapshot("snap-1"),
    ).resolves.toBeUndefined();
    await expect(backend(mock.url).deleteSnapshot("../x")).rejects.toThrow(
      /not valid/,
    );
  });

  it("offers no snapshot outside a remote workspace and none once disposed", async () => {
    const mock = await e2bServer();
    expect((await activate(backend(mock.url), false)).snapshot).toBeUndefined();
    const sandbox = await activate(backend(mock.url));
    await sandbox.dispose();
    await expect(sandbox.snapshot?.()).rejects.toThrow();
  });
});

describe("custom adapter snapshots", () => {
  const adapter = (extra: Record<string, unknown>) =>
    customBackend({
      id: "acme-remote",
      available: async () => ({ available: true }),
      capabilities: () => ({
        isolation: "remote",
        planes: [
          "host-filesystem-isolation",
          "network-deny",
          "environment-filter",
        ],
        network: ["deny", "allow"],
        localProcesses: false,
      }),
      prepare: async () => ({
        exec: async () => ({ exitCode: 0 }),
        dispose: async () => {},
        ...extra,
      }),
    });
  const profile = async () =>
    (await activate(backend((await e2bServer()).url))).profile;

  it("passes a valid snapshot through and checks its id", async () => {
    const good = await adapter({
      snapshot: async () => ({ id: "ok-1" }),
    }).prepare({ profile: await profile() });
    expect(
      await good.snapshot?.({ signal: new AbortController().signal }),
    ).toEqual({
      id: "ok-1",
    });
    const bad = await adapter({
      snapshot: async () => ({ id: "../etc" }),
    }).prepare({ profile: await profile() });
    await expect(
      bad.snapshot?.({ signal: new AbortController().signal }),
    ).rejects.toThrow(/no valid id/);
    await expect(
      adapter({ snapshot: "yes" }).prepare({ profile: await profile() }),
    ).rejects.toThrow(/prepare\(\) must return/);
  });
});
