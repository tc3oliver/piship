// Contract test of the sandbox service against a fake docker CLI: no Docker
// needed. It pins what the service accepts, what it asks Docker to create,
// and what it never lets out; the live test (tests/sandbox.test.ts) runs the
// same service against real containers.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { request as httpRequest } from "node:http";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createSandboxServer } from "../service/server.mjs";
import { authenticate, loadRegistry } from "../service/src/auth.mjs";
import { loadConfig } from "../service/src/config.mjs";
import { createLogger } from "../service/src/log.mjs";
import { IMAGE, startService, until } from "./harness.mjs";

const generateKey = fileURLToPath(
  new URL("../scripts/generate-key.mjs", import.meta.url),
);

const runCalls = (service) =>
  service.calls().filter((call) => call.command === "run");
const execCalls = (service) =>
  service.calls().filter((call) => call.command === "exec");

/** The values that follow each occurrence of `flag`. */
const flagValues = (args, flag) =>
  args.flatMap((value, index) => (args[index - 1] === flag ? [value] : []));

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

/** A request with a Host header of the caller's choosing. */
function rawRequest(port, headers) {
  return new Promise((resolve, reject) => {
    const sent = httpRequest(
      { host: "127.0.0.1", port, path: "/v1/status", headers },
      (response) => {
        let text = "";
        response.on("data", (chunk) => {
          text += chunk;
        });
        response.on("end", () =>
          resolve({ status: response.statusCode, text }),
        );
      },
    );
    sent.on("error", reject).end();
  });
}

describe("configuration", () => {
  const base = () => ({
    SANDBOX_REGISTRY: "/tmp/registry.json",
    SANDBOX_WORKSPACE_ROOTS: "/tmp",
    SANDBOX_IMAGE: IMAGE,
  });

  it("binds loopback only, with no switch for anything wider", () => {
    for (const host of [
      "0.0.0.0",
      "192.168.1.5",
      "::",
      "example.com",
      "localhost",
    ])
      assert.throws(
        () => loadConfig({ ...base(), SANDBOX_LISTEN_HOST: host }),
        /SANDBOX_LISTEN_HOST must be 127\.0\.0\.1 or ::1/,
      );
    assert.equal(loadConfig(base()).listenHost, "127.0.0.1");
    assert.equal(
      loadConfig({ ...base(), SANDBOX_LISTEN_HOST: "::1" }).listenHost,
      "::1",
    );
  });

  it("names a bad variable and never repeats its value", () => {
    for (const [name, value] of [
      ["SANDBOX_IMAGE", "bad image with spaces"],
      ["SANDBOX_SHELL", "sh"],
      ["SANDBOX_ALLOW_NETWORK", "host"],
      ["SANDBOX_ALLOW_NETWORK", "none"],
      ["SANDBOX_MEMORY", "lots"],
      ["SANDBOX_CPUS", "0.00"],
      ["SANDBOX_INSTANCE", "Has Capitals"],
    ]) {
      let message = "";
      try {
        loadConfig({ ...base(), [name]: value });
      } catch (error) {
        message = error.message;
      }
      assert.match(message, new RegExp(name), `${name}=${value}`);
      // Two Docker network names are refused by name, which says the word.
      if (name !== "SANDBOX_ALLOW_NETWORK")
        assert.equal(
          message.includes(value),
          false,
          `${name} echoed its value`,
        );
    }
    for (const name of [
      "SANDBOX_REGISTRY",
      "SANDBOX_WORKSPACE_ROOTS",
      "SANDBOX_IMAGE",
    ]) {
      const env = base();
      delete env[name];
      assert.throws(() => loadConfig(env), new RegExp(name));
    }
    assert.throws(
      () => loadConfig({ ...base(), SANDBOX_WORKSPACE_ROOTS: "/" }),
      /filesystem root/,
    );
    assert.throws(
      () => loadConfig({ ...base(), SANDBOX_WORKSPACE_ROOTS: "relative/dir" }),
      /absolute/,
    );
  });
});

describe("the key registry", () => {
  it("holds only hashes, and rejects a malformed or duplicated one without echoing it", async () => {
    const service = await startService();
    try {
      const write = (content) => {
        const path = join(service.root, "bad-registry.json");
        writeFileSync(path, content);
        return path;
      };
      const schema = "piship-reference-sandbox-registry/v1";
      const entry = { id: "alice", sha256: "0".repeat(64) };
      for (const content of [
        "{ not json",
        JSON.stringify({ schema: "other", keys: [entry] }),
        JSON.stringify({ schema, keys: [] }),
        JSON.stringify({ schema, keys: [entry, entry] }),
        JSON.stringify({
          schema,
          keys: [{ id: "Alice", sha256: "0".repeat(64) }],
        }),
        JSON.stringify({
          schema,
          keys: [{ id: "alice", sha256: "not-a-hash" }],
        }),
      ])
        assert.throws(
          () => loadRegistry(write(content)),
          (error) =>
            /SANDBOX_REGISTRY/.test(error.message) &&
            !error.message.includes("not-a-hash"),
        );
      const registry = readFileSync(service.config.registry, "utf8");
      for (const key of Object.values(service.keys))
        assert.equal(registry.includes(key), false, "the registry holds a key");
      const keys = loadRegistry(service.config.registry);
      assert.equal(authenticate(keys, `Bearer ${service.keys.alice}`), "alice");
      assert.equal(authenticate(keys, `bearer ${service.keys.bob}`), "bob");
      for (const header of [
        undefined,
        "",
        service.keys.alice,
        `Basic ${service.keys.alice}`,
        `Bearer ${service.keys.alice} extra`,
        "Bearer short",
        `Bearer ${service.keys.alice}x`,
      ])
        assert.equal(authenticate(keys, header), undefined, String(header));
    } finally {
      await service.stop();
    }
  });

  it("is written by generate-key without printing the key, and never overwrites one", async () => {
    const service = await startService();
    const directory = join(service.root, "issued");
    const run = (...extra) =>
      spawnSync(process.execPath, [generateKey, "--dir", directory, ...extra], {
        encoding: "utf8",
      });
    try {
      const first = run("--user", "alice");
      assert.equal(first.status, 0, first.stderr);
      const second = run("--user", "bob");
      assert.equal(second.status, 0, second.stderr);
      const key = readFileSync(join(directory, "alice.key"), "utf8").trim();
      assert.match(key, /^sbxk_[A-Za-z0-9_-]{43}$/);
      assert.equal(`${first.stdout}${first.stderr}`.includes(key), false);
      assert.equal(statSync(join(directory, "alice.key")).mode & 0o777, 0o600);
      assert.equal(
        statSync(join(directory, "registry.json")).mode & 0o777,
        0o600,
      );
      assert.equal(statSync(directory).mode & 0o777, 0o700);
      const registry = loadRegistry(join(directory, "registry.json"));
      assert.deepEqual(registry.map((item) => item.id).sort(), [
        "alice",
        "bob",
      ]);
      assert.equal(authenticate(registry, `Bearer ${key}`), "alice");
      assert.equal(run("--user", "alice").status, 1, "overwrote a key");
      assert.equal(
        readFileSync(join(directory, "alice.key"), "utf8").trim(),
        key,
      );
      assert.equal(run("--user", "alice", "--force").status, 0);
      assert.notEqual(
        readFileSync(join(directory, "alice.key"), "utf8").trim(),
        key,
      );
      assert.equal(run("--user", "Bad Name").status, 2);
    } finally {
      await service.stop();
    }
  });
});

describe("the HTTP surface", () => {
  let service;
  before(async () => {
    service = await startService();
  });
  after(() => service.stop());

  it("answers /health to anyone, and nothing else without the credential", async () => {
    const health = await service.call("/health");
    assert.equal(health.status, 200);
    assert.deepEqual(health.json(), { status: "ok" });
    const refusals = [];
    for (const key of [undefined, "wrong-credential-value", "sbxk_short"])
      refusals.push(await service.call("/v1/status", { key }));
    refusals.push(
      await service.call("/v1/status", {
        headers: { authorization: `Basic ${service.keys.alice}` },
      }),
      await service.call(`/v1/status?token=${service.keys.alice}`),
      await service.call("/v1/sandboxes", { method: "POST", body: {} }),
      await service.call("/v1/sandboxes/sbx_000000000000000000000000/exec", {
        method: "POST",
        body: { command: "true" },
      }),
      await service.call("/v1/sandboxes/sbx_000000000000000000000000", {
        method: "DELETE",
      }),
    );
    for (const refusal of refusals) {
      assert.equal(refusal.status, 401);
      // Missing, wrong, and malformed credentials are one answer.
      assert.deepEqual(refusal.json(), {
        error: {
          code: "unauthorized",
          message: "A valid sandbox credential is required",
        },
      });
      assert.equal(refusal.headers["www-authenticate"], "Bearer");
    }
    assert.equal(runCalls(service).length, 0);
    const ok = await service.call("/v1/status", { key: "alice" });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.json(), { runtime: "ok", sandboxes: 0, limit: 8 });
  });

  it("marks every answer uncacheable and sends no cross-origin permission", async () => {
    for (const answer of [
      await service.call("/health"),
      await service.call("/v1/status", { key: "alice" }),
      await service.call("/v1/status"),
      await service.call("/nowhere"),
    ]) {
      assert.equal(answer.headers["cache-control"], "no-store");
      assert.equal(answer.headers["x-content-type-options"], "nosniff");
      assert.equal(
        Object.keys(answer.headers).some((name) =>
          name.startsWith("access-control-"),
        ),
        false,
      );
    }
  });

  it("answers only for the names it listens on, whatever the credential", async () => {
    const other = await rawRequest(service.port, {
      host: "attacker.example",
      authorization: `Bearer ${service.keys.alice}`,
    });
    assert.equal(other.status, 421);
    assert.equal(other.text.includes("attacker.example"), false);
    const named = await service.call("/v1/status", {
      key: "alice",
      headers: { host: `localhost:${service.port}` },
    });
    assert.equal(named.status, 200);
  });

  it("refuses a body that is not JSON, not small, or not an object", async () => {
    const post = (extra) =>
      service.call("/v1/sandboxes", { method: "POST", key: "alice", ...extra });
    assert.equal(
      (
        await post({
          raw: "workspace=/x",
          headers: { "content-type": "text/plain" },
        })
      ).status,
      415,
    );
    assert.equal(
      (
        await post({
          raw: "{nope",
          headers: { "content-type": "application/json" },
        })
      ).status,
      400,
    );
    assert.equal((await post({ body: [1] })).status, 400);
    assert.equal(
      (
        await post({
          raw: `{"workspace":"${"a".repeat(600_000)}"}`,
          headers: { "content-type": "application/json" },
        })
      ).status,
      413,
    );
    assert.equal(runCalls(service).length, 0);
  });
});

describe("creating a sandbox", () => {
  let service;
  before(async () => {
    service = await startService({ SANDBOX_MAX_PER_KEY: "3" });
  });
  after(() => service.stop());

  it("refuses a workspace it may not mount, without repeating what it was given", async () => {
    const marker = "MARKER-INPUT-7c1f";
    const inside = service.workspace("plain");
    const noGit = join(service.workspaces, "no-git");
    mkdirSync(noGit);
    const linked = join(service.workspaces, "linked-git");
    mkdirSync(join(linked, "elsewhere"), { recursive: true });
    symlinkSync(join(linked, "elsewhere"), join(linked, ".git"));
    const outward = join(service.workspaces, "outward");
    symlinkSync(service.root, outward);
    for (const [workspace, status, code] of [
      [`/nowhere/${marker}`, 422, "workspace_not_allowed"],
      [service.root, 422, "workspace_not_allowed"],
      [join(service.root, marker), 422, "workspace_not_allowed"],
      // A path is never taken lexically: a link out of the root is refused.
      [outward, 422, "workspace_not_allowed"],
      [noGit, 409, "workspace_unsupported"],
      [linked, 409, "workspace_unsupported"],
    ]) {
      const answer = await service.create("alice", workspace);
      assert.equal(answer.status, status, workspace);
      assert.equal(answer.json().error.code, code, workspace);
      assert.equal(answer.text.includes(marker), false);
      assert.equal(answer.text.includes(service.root), false);
    }
    for (const body of [
      { workspace: "relative/path", network: "deny" },
      { workspace: inside, network: "open" },
      { workspace: `${inside},readonly`, network: "deny" },
      { workspace: `${inside}"`, network: "deny" },
      {
        workspace: inside,
        network: "deny",
        writeProtect: { files: ["relative"] },
      },
      { workspace: inside, network: "deny", writeProtect: "yes" },
    ]) {
      const answer = await service.call("/v1/sandboxes", {
        method: "POST",
        key: "alice",
        body,
      });
      assert.equal(answer.status, 400, JSON.stringify(body));
    }
    assert.equal(
      runCalls(service).length,
      0,
      "docker was asked to run something",
    );
  });

  it("starts a container with no privilege and only the mounts it lists", async () => {
    const workspace = service.workspace("project");
    const hooks = join(workspace, ".githooks");
    mkdirSync(hooks);
    const shared = join(workspace, "config");
    mkdirSync(shared);
    writeFileSync(join(shared, "local.cfg"), "x");
    const answer = await service.create("alice", workspace, {
      writeProtect: {
        files: [
          join(workspace, ".git"),
          join(workspace, ".git", "config"),
          join(workspace, ".git", "commondir"),
          join(shared, "local.cfg"),
          join(service.root, "outside.cfg"),
        ],
        directories: [
          join(workspace, ".git", "hooks"),
          join(workspace, ".git", "modules"),
          // One that lies under another is covered by it, missing or not.
          join(hooks, "nested"),
          hooks,
        ],
      },
    });
    assert.equal(answer.status, 201, answer.text);
    assert.match(answer.id, /^sbx_[0-9a-f]{24}$/);
    const [run] = runCalls(service);
    const { args } = run;
    assert.equal(args[0], "run");
    // What the container is not: privileged, published, or sharing the host.
    for (const forbidden of [
      "--privileged",
      "--publish",
      "--publish-all",
      "-p",
      "-P",
      "--volume",
      "-v",
      "--device",
      "--cap-add",
      "--pid",
      "--ipc",
      "--userns",
      "--uts",
      "--add-host",
      "--env-file",
    ])
      assert.equal(args.includes(forbidden), false, `${forbidden} is set`);
    assert.deepEqual(flagValues(args, "--cap-drop"), ["ALL"]);
    assert.deepEqual(flagValues(args, "--security-opt"), ["no-new-privileges"]);
    assert.ok(args.includes("--read-only"));
    assert.ok(args.includes("--init"));
    assert.ok(args.includes("--rm"));
    assert.deepEqual(flagValues(args, "--network"), ["none"]);
    assert.deepEqual(flagValues(args, "--restart"), ["no"]);
    assert.deepEqual(flagValues(args, "--pids-limit"), ["512"]);
    assert.deepEqual(flagValues(args, "--memory"), ["1g"]);
    assert.deepEqual(flagValues(args, "--memory-swap"), ["1g"]);
    assert.deepEqual(flagValues(args, "--cpus"), ["2"]);
    assert.deepEqual(flagValues(args, "--tmpfs"), [
      "/tmp:rw,nosuid,nodev,size=256m",
    ]);
    assert.deepEqual(flagValues(args, "--env"), ["HOME=/tmp"]);
    // Commands run as the workspace's owner, never as root.
    const { uid, gid } = statSync(workspace);
    assert.notEqual(uid, 0);
    assert.deepEqual(flagValues(args, "--user"), [`${uid}:${gid}`]);
    // The image, then the command that ends the container by itself.
    assert.equal(args.at(-3), IMAGE);
    assert.equal(args.at(-2), "sleep");
    assert.equal(Number(args.at(-1)), 43_200 + 60);
    // The workspace, the read-only .git, the protected paths that exist in
    // the working tree, and the one writable place under .git; a parent
    // before what lies under it.
    assert.deepEqual(flagValues(args, "--mount"), [
      `type=bind,src=${workspace},dst=/workspace`,
      `type=bind,src=${join(workspace, ".git")},dst=/workspace/.git,readonly`,
      `type=bind,src=${hooks},dst=/workspace/.githooks,readonly`,
      `type=bind,src=${join(shared, "local.cfg")},dst=/workspace/config/local.cfg,readonly`,
      `type=bind,src=${join(workspace, ".git", "piship-workspace")},dst=/workspace/.git/piship-workspace`,
    ]);
    const name = flagValues(args, "--name")[0];
    assert.match(name, /^piship-sbx-contract-[0-9a-f]{12}$/);
    assert.deepEqual(flagValues(args, "--label").sort(), [
      "piship.sandbox.instance=contract",
      `piship.sandbox.session=${answer.id}`,
    ]);
    assert.equal(
      statSync(join(workspace, ".git", "piship-workspace")).mode & 0o777,
      0o700,
    );
    assert.ok(service.containers().includes(name));
  });

  it("gives an allowed network the configured Docker network", async () => {
    const workspace = service.workspace("allow-network");
    const answer = await service.create("alice", workspace, {
      network: "allow",
    });
    assert.equal(answer.status, 201, answer.text);
    assert.deepEqual(flagValues(runCalls(service).at(-1).args, "--network"), [
      "bridge",
    ]);
  });

  it("refuses a git control path it cannot protect, before starting anything", async () => {
    const workspace = service.workspace("missing-hooks");
    const before = runCalls(service).length;
    const answer = await service.create("bob", workspace, {
      writeProtect: { directories: [join(workspace, ".githooks")] },
    });
    assert.equal(answer.status, 409);
    assert.equal(answer.json().error.code, "protected_path_missing");
    assert.equal(runCalls(service).length, before);
  });

  it("holds each key to its own number of sandboxes", async () => {
    const workspace = service.workspace("limit");
    const held = [];
    for (let count = 0; count < 3; count++) {
      const created = await service.create("bob", workspace);
      assert.equal(created.status, 201, created.text);
      held.push(created.id);
    }
    const over = await service.create("bob", workspace);
    assert.equal(over.status, 429);
    assert.equal(over.headers["retry-after"], "5");
    assert.equal(over.json().error.code, "limit_reached");
    assert.deepEqual(
      (await service.call("/v1/status", { key: "bob" })).json(),
      {
        runtime: "ok",
        sandboxes: 3,
        limit: 3,
      },
    );
    for (const id of held)
      assert.equal(
        (
          await service.call(`/v1/sandboxes/${id}`, {
            method: "DELETE",
            key: "bob",
          })
        ).status,
        204,
      );
  });

  it("reports a container that fails to start with a fixed message, and removes what it made", async () => {
    const workspace = service.workspace("run-fails");
    service.fault("RUN_FAIL");
    const failed = await service.create("alice", workspace);
    service.fault("RUN_FAIL", false);
    assert.equal(failed.status, 502);
    assert.equal(failed.json().error.code, "runtime_error");
    assert.equal(failed.text.includes("cannot start"), false);
    // The operator's log says why; the caller's answer does not.
    assert.match(
      service.logs(),
      /"event":"sandbox.create.failed".*"reason":"cannot start"/,
    );
    const removal = service
      .calls()
      .filter((call) => call.command === "rm")
      .at(-1);
    assert.ok(
      removal.args.some((value) => value.startsWith("piship-sbx-contract-")),
    );
  });
});

describe("a runtime that is down", () => {
  it("says so, and starts nothing", async () => {
    const service = await startService();
    try {
      service.fault("DOWN");
      const status = await service.call("/v1/status", { key: "alice" });
      assert.equal(status.json().runtime, "unavailable");
      const down = await service.create("alice", service.workspace("down"));
      assert.equal(down.status, 503);
      assert.equal(down.json().error.code, "runtime_unavailable");
      assert.equal(runCalls(service).length, 0);
    } finally {
      await service.stop();
    }
  });
});

describe("commands", () => {
  let service;
  let workspace;
  let id;
  before(async () => {
    service = await startService();
    workspace = service.workspace("commands");
    id = (await service.create("alice", workspace)).id;
    assert.match(id, /^sbx_/);
  });
  after(() => service.stop());

  it("streams stdout and stderr apart and ends with the exit", async () => {
    const result = await service.exec(
      "alice",
      id,
      "printf 'out-1'; printf 'err-1' >&2; printf 'out-2'; exit 3",
    );
    assert.equal(result.status, 200);
    assert.ok(
      result.headers["content-type"].startsWith("application/x-ndjson"),
    );
    assert.equal(result.out, "out-1out-2");
    assert.equal(result.err, "err-1");
    assert.deepEqual(result.exit, { exit: 3, signal: null });
    const ok = await service.exec("alice", id, "true");
    assert.deepEqual(ok.exit, { exit: 0, signal: null });
    // Bytes that are not text arrive intact.
    const binary = await service.exec("alice", id, "printf '\\377\\376ok'");
    assert.ok(
      binary.text.includes(
        Buffer.from([0xff, 0xfe, 0x6f, 0x6b]).toString("base64"),
      ),
    );
  });

  it("passes the environment through a file only its owner can read, never through the command line", async () => {
    const value =
      "a value with 'quotes' and \"more\" and $dollar and \\slash and ü";
    const run = await service.exec("alice", id, 'printf "%s" "$FOO"', {
      env: { FOO: value, EMPTY: "" },
    });
    assert.equal(run.out, value);
    const call = execCalls(service)
      .filter((entry) => entry.envFile?.variables.FOO === value)
      .at(-1);
    assert.equal(call.envFile.mode, "600");
    assert.match(call.envFile.variables.PISHIP_EXEC_ID, /^[0-9a-f]{32}$/);
    assert.equal(call.envFile.variables.EMPTY, "");
    assert.equal(JSON.stringify(call.args).includes(value), false);
    assert.equal(call.args.includes("FOO"), false);
    // The file is gone once the command has ended.
    assert.equal(
      existsSync(call.args[call.args.indexOf("--env-file") + 1]),
      false,
    );
  });

  it("runs at the workspace path it is given and refuses a path outside", async () => {
    assert.equal(
      (await service.exec("alice", id, "true", { cwd: "src/deep" })).status,
      200,
    );
    assert.equal(execCalls(service).at(-1).workdir, "/workspace/src/deep");
    assert.equal(
      (await service.exec("alice", id, "true", { cwd: "." })).status,
      200,
    );
    assert.equal(execCalls(service).at(-1).workdir, "/workspace");
    for (const cwd of ["../escape", "/etc", "a/../../b", "x\0y"])
      assert.equal(
        (await service.exec("alice", id, "true", { cwd })).status,
        400,
        cwd,
      );
  });

  it("refuses what cannot be a command, or an environment, before running anything", async () => {
    const before = execCalls(service).length;
    for (const body of [
      { command: "" },
      { command: 5 },
      { command: "x".repeat(100_001) },
      { command: "true", env: { "1BAD": "x" } },
      { command: "true", env: { "with space": "x" } },
      { command: "true", env: { PISHIP_EXEC_ID: "x" } },
      { command: "true", env: { FOO: "line\nbreak" } },
      { command: "true", env: { FOO: 5 } },
      { command: "true", env: [] },
      { command: "true", cwd: 5 },
    ]) {
      const answer = await service.call(`/v1/sandboxes/${id}/exec`, {
        method: "POST",
        key: "alice",
        body,
      });
      assert.equal(answer.status, 400, JSON.stringify(body).slice(0, 60));
    }
    assert.equal(execCalls(service).length, before);
  });

  it("stops a command, and what it started, when the caller goes away", async () => {
    const controller = new AbortController();
    const response = await fetch(`${service.base}/v1/sandboxes/${id}/exec`, {
      method: "POST",
      signal: controller.signal,
      headers: {
        authorization: `Bearer ${service.keys.alice}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ command: "echo started; sleep 30; echo late" }),
    });
    const reader = response.body.getReader();
    const first = await reader.read();
    assert.match(Buffer.from(first.value).toString(), /"stream":"stdout"/);
    controller.abort();
    const cancel = await until(
      () => service.calls().find((entry) => entry.command === "cancel"),
      "the cancel",
    );
    assert.match(cancel.id, /^[0-9a-f]{32}$/);
    const pid = service.commandPid(cancel.id);
    assert.ok(pid, "the command was never started");
    await until(() => !alive(pid), "the command to end");
    // The sandbox itself runs the next command.
    assert.equal(
      (await service.exec("alice", id, "printf still-here")).out,
      "still-here",
    );
  });

  it("gives another user's sandbox the answer of one that does not exist", async () => {
    for (const request of [
      () => service.exec("bob", id, "true"),
      () =>
        service.call(`/v1/sandboxes/${id}`, { method: "DELETE", key: "bob" }),
      () => service.exec("alice", "sbx_ffffffffffffffffffffffff", "true"),
      () => service.exec("alice", "sbx_not_an_id", "true"),
    ]) {
      const answer = await request();
      assert.equal(answer.status, 404);
      assert.equal(answer.json().error.code, "not_found");
    }
    assert.equal(
      (await service.call("/v1/status", { key: "bob" })).json().sandboxes,
      0,
    );
    // The owner still has it.
    assert.equal((await service.exec("alice", id, "true")).exit.exit, 0);
  });

  it("removes the container on delete, ending a command that is still running", async () => {
    const other = (await service.create("alice", workspace)).id;
    const running = service.exec("alice", other, "sleep 30");
    const started = await until(
      () => execCalls(service).find((entry) => entry.args.includes("sleep 30")),
      "the command to start",
    );
    const deleted = await service.call(`/v1/sandboxes/${other}`, {
      method: "DELETE",
      key: "alice",
    });
    assert.equal(deleted.status, 204);
    assert.equal(deleted.text, "");
    assert.deepEqual((await running).exit, { exit: null, signal: "SIGKILL" });
    const removed = service
      .calls()
      .filter((entry) => entry.command === "rm")
      .at(-1);
    assert.ok(removed.args.includes("--force"));
    assert.ok(started);
    assert.equal((await service.exec("alice", other, "true")).status, 404);
    assert.equal(
      (
        await service.call(`/v1/sandboxes/${other}`, {
          method: "DELETE",
          key: "alice",
        })
      ).status,
      404,
    );
  });
});

describe("limits of time and size", () => {
  it("removes a sandbox that has been idle, and not one that is running a command", async () => {
    const service = await startService({ SANDBOX_IDLE_SECONDS: "1" });
    try {
      const workspace = service.workspace("idle");
      const idle = (await service.create("alice", workspace)).id;
      const busy = (await service.create("alice", workspace)).id;
      const running = service.exec("alice", busy, "sleep 2.5");
      await until(
        async () =>
          (await service.call("/v1/status", { key: "alice" })).json()
            .sandboxes === 1,
        "the idle sandbox to be removed",
        4000,
      );
      assert.equal((await service.exec("alice", idle, "true")).status, 404);
      assert.equal((await running).exit.exit, 0);
      assert.equal((await service.exec("alice", busy, "true")).status, 200);
    } finally {
      await service.stop();
    }
  });

  it("ends a sandbox at its maximum lifetime, whoever is using it", async () => {
    const service = await startService({ SANDBOX_MAX_LIFETIME_SECONDS: "1" });
    try {
      const { id } = await service.create(
        "alice",
        service.workspace("lifetime"),
      );
      const running = await service.exec("alice", id, "sleep 30");
      assert.deepEqual(running.exit, { exit: null, signal: "SIGKILL" });
      assert.equal((await service.exec("alice", id, "true")).status, 404);
    } finally {
      await service.stop();
    }
  });

  it("stops a command that runs past its limit or prints past its limit", async () => {
    const service = await startService({
      SANDBOX_MAX_EXEC_SECONDS: "1",
      SANDBOX_MAX_OUTPUT_BYTES: "2048",
    });
    try {
      const { id } = await service.create("alice", service.workspace("caps"));
      const slow = await service.exec("alice", id, "sleep 30");
      assert.deepEqual(slow.exit, { exit: null, signal: "SIGKILL" });
      const loud = await service.exec("alice", id, "yes | head -c 200000");
      assert.equal(loud.exit.exit, null);
      assert.equal(loud.exit.truncated, true);
    } finally {
      await service.stop();
    }
  });
});

describe("the life of the service", () => {
  it("removes every sandbox it holds when it stops, ending their commands", async () => {
    const service = await startService();
    const workspace = service.workspace("shutdown");
    const first = (await service.create("alice", workspace)).id;
    await service.create("bob", workspace);
    assert.equal(service.containers().length, 2);
    const running = service.exec("alice", first, "sleep 30");
    await until(
      () => execCalls(service).some((entry) => entry.args.includes("sleep 30")),
      "the command to start",
    );
    const { leftover } = await service.stop();
    assert.deepEqual(leftover, []);
    assert.equal((await running).exit.signal, "SIGKILL");
  });

  it("removes what an earlier run of its instance left, and nothing else", async () => {
    const first = await startService();
    try {
      const { id } = await first.create("alice", first.workspace("restart"));
      assert.match(id, /^sbx_/);
      const abandoned = first.containers()[0];
      first.leftover("someone-elses", "other-instance");
      first.leftover("unlabelled-project", "");
      // A second run of the same instance, with the same fake docker.
      const env = {
        PATH: process.env.PATH ?? "",
        SANDBOX_INSTANCE: "contract",
        SANDBOX_REGISTRY: first.config.registry,
        SANDBOX_WORKSPACE_ROOTS: first.workspaces,
        SANDBOX_IMAGE: IMAGE,
        SANDBOX_DOCKER: first.config.docker,
        DOCKER_FAKE_DIR: join(first.root, "docker"),
      };
      const config = loadConfig(env);
      config.listenPort = 0;
      const lines = [];
      const second = createSandboxServer(config, {
        write: (line) => lines.push(line),
        env,
      });
      await second.start();
      try {
        assert.equal(first.containers().includes(abandoned), false);
        assert.deepEqual(first.containers().sort(), [
          "someone-elses",
          "unlabelled-project",
        ]);
        assert.match(lines.join(""), /"event":"service.started","removed":1/);
      } finally {
        await second.stop();
      }
    } finally {
      await first.stop();
    }
  });
});

describe("what it logs", () => {
  it("holds no credential, command, environment value, or path", async () => {
    const service = await startService();
    try {
      const marker = "MARKER-COMMAND-9d2e";
      const envMarker = "MARKER-ENV-41aa";
      const workspace = service.workspace("logged");
      const { id } = await service.create("alice", workspace);
      await service.exec("alice", id, `echo ${marker}`, {
        env: { LOGGED: envMarker },
      });
      await service.call("/v1/status", { key: "wrong-credential-marker-0001" });
      await service.create("alice", `/nowhere/${marker}`);
      await service.call(`/v1/sandboxes/${id}`, {
        method: "DELETE",
        key: "alice",
      });
      const logs = service.logs();
      assert.match(logs, /"event":"sandbox.create"/);
      assert.match(logs, /"event":"sandbox.exec"/);
      for (const secret of [
        ...Object.values(service.keys),
        marker,
        envMarker,
        "wrong-credential-marker-0001",
        service.root,
        workspace,
      ])
        assert.equal(
          logs.includes(secret),
          false,
          `the log holds ${secret.slice(0, 12)}`,
        );
      for (const line of logs.split("\n").filter(Boolean)) JSON.parse(line);
    } finally {
      await service.stop();
    }
  });

  it("writes only the fields it names, and scrubs a key from them", () => {
    const lines = [];
    const log = createLogger({ write: (line) => lines.push(line) });
    log("request", {
      route: "sbxk_abcdefghijklmnop",
      command: "echo secret",
      env: { A: "b" },
      status: 401,
    });
    const line = JSON.parse(lines[0]);
    assert.equal(line.route, "[REDACTED]");
    assert.equal("command" in line, false);
    assert.equal("env" in line, false);
    assert.equal(line.status, 401);
  });
});
