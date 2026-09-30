// Contract test of the sandbox service against a fake docker CLI: no Docker
// needed. It pins what the service accepts, what it asks Docker to create,
// and what it never lets out; the live test (tests/sandbox.test.ts) runs the
// same service against real containers.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { request as httpRequest } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createSandboxServer } from "../service/server.mjs";
import { authenticate, loadRegistry } from "../service/src/auth.mjs";
import { loadConfig } from "../service/src/config.mjs";
import { environmentInput, execArguments } from "../service/src/docker.mjs";
import { createLogger } from "../service/src/log.mjs";
import { HOST_UID, IMAGE, startService, until, wait } from "./harness.mjs";

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

  it("names the service by its user and its port unless the operator names it", () => {
    // Two services on one Docker daemon must not share an instance name, or
    // each start-up removes the other's sandboxes.
    assert.equal(loadConfig(base()).instance, `reference-${HOST_UID}-18075`);
    assert.equal(loadConfig(base()).uid, HOST_UID);
    assert.equal(
      loadConfig({ ...base(), SANDBOX_LISTEN_PORT: "18099" }).instance,
      `reference-${HOST_UID}-18099`,
    );
    assert.equal(
      loadConfig({ ...base(), SANDBOX_INSTANCE: "team-a" }).instance,
      "team-a",
    );
    assert.ok(
      loadConfig({ ...base(), SANDBOX_LISTEN_PORT: "65535" }).instance.length <=
        41,
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
      const entry = { id: "alice", sha256: "0".repeat(64), uid: 1000 };
      for (const content of [
        "{ not json",
        JSON.stringify({ schema: "other", keys: [entry] }),
        JSON.stringify({ schema, keys: [] }),
        JSON.stringify({ schema, keys: [entry, entry] }),
        JSON.stringify({
          schema,
          keys: [{ id: "Alice", sha256: "0".repeat(64), uid: 1000 }],
        }),
        JSON.stringify({
          schema,
          keys: [{ id: "alice", sha256: "not-a-hash", uid: 1000 }],
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
      assert.equal(
        authenticate(keys, `Bearer ${service.keys.alice}`)?.id,
        "alice",
      );
      assert.equal(authenticate(keys, `bearer ${service.keys.bob}`)?.id, "bob");
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
      const entry = authenticate(registry, `Bearer ${key}`);
      assert.equal(entry?.id, "alice");
      // Bound to the user who ran the script, unless told otherwise.
      assert.equal(entry?.uid, HOST_UID);
      assert.equal(entry?.unbound, false);
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

  it("binds every key to a host user, or says plainly that it is not", async () => {
    const service = await startService();
    try {
      const directory = join(service.root, "bound");
      const run = (...extra) =>
        spawnSync(
          process.execPath,
          [generateKey, "--dir", directory, ...extra],
          { encoding: "utf8" },
        );
      mkdirSync(join(service.root, "shared"));
      for (const args of [
        ["--user", "uid", "--uid", "4242"],
        ["--user", "open", "--unbound"],
        ["--user", "narrow", "--root", join(service.root, "shared")],
      ])
        assert.equal(run(...args).status, 0, args.join(" "));
      const registry = JSON.parse(
        readFileSync(join(directory, "registry.json"), "utf8"),
      );
      const entry = (id) => registry.keys.find((item) => item.id === id);
      assert.equal(entry("uid").uid, 4242);
      assert.equal("unbound" in entry("uid"), false);
      assert.equal(entry("open").unbound, true);
      assert.equal("uid" in entry("open"), false);
      assert.equal(entry("narrow").uid, HOST_UID);
      assert.deepEqual(entry("narrow").roots, [join(service.root, "shared")]);
      const loaded = loadRegistry(join(directory, "registry.json"));
      assert.equal(loaded.find((item) => item.id === "open")?.unbound, true);
      // What the script refuses to write.
      for (const args of [
        ["--user", "both", "--uid", "1", "--unbound"],
        ["--user", "root", "--uid", "0"],
        ["--user", "text", "--uid", "alice"],
        ["--user", "relative", "--root", "shared"],
      ])
        assert.equal(run(...args).status, 2, args.join(" "));
      assert.equal(entry("both"), undefined);
    } finally {
      await service.stop();
    }
  });

  it("refuses an entry that names no host user, unless it says unbound", async () => {
    const service = await startService();
    try {
      const write = (entry) => {
        const path = join(service.root, "binding-registry.json");
        writeFileSync(
          path,
          JSON.stringify({
            schema: "piship-reference-sandbox-registry/v1",
            keys: [{ id: "alice", sha256: "0".repeat(64), ...entry }],
          }),
        );
        return path;
      };
      const refused = (entry, pattern) =>
        assert.throws(() => loadRegistry(write(entry)), pattern);
      refused({}, /entry alice: name the host user .* or say unbound: true/);
      refused({ uid: 1000, unbound: true }, /exclusive/);
      refused({ unbound: false }, /unbound must be true/);
      refused({ unbound: "yes" }, /unbound must be true/);
      refused({ uid: 0 }, /non-root/);
      refused({ uid: -1 }, /non-root/);
      refused({ uid: "1000" }, /non-root/);
      refused({ uid: 1.5 }, /non-root/);
      refused({ uid: 1000, roots: [] }, /absolute paths/);
      refused({ uid: 1000, roots: ["relative"] }, /absolute paths/);
      refused({ uid: 1000, roots: ["/"] }, /does not exist/);
      refused(
        { uid: 1000, roots: [join(service.root, "missing")] },
        /does not exist/,
      );
      const [bound] = loadRegistry(write({ uid: 1000 }));
      assert.equal(bound?.uid, 1000);
      assert.equal(bound?.unbound, false);
      const [unbound] = loadRegistry(write({ unbound: true }));
      assert.equal(unbound?.uid, undefined);
      assert.equal(unbound?.unbound, true);
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
    // It says which service answered, so a caller can tell its own from
    // another on the same port.
    assert.deepEqual(health.json(), { status: "ok", instance: "contract" });
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
      `piship.sandbox.owner=${HOST_UID}`,
      `piship.sandbox.session=${answer.id}`,
    ]);
    assert.equal(
      statSync(join(workspace, ".git", "piship-workspace")).mode & 0o777,
      0o700,
    );
    assert.ok(service.containers().includes(name));
  });

  it("mounts a workspace only for a key bound to the user who owns it", async () => {
    // Commands run as the workspace's owner, so a key that could name any
    // workspace under the roots could mount another user's project as that
    // user. carol's key is bound to another user than the tests', so it is
    // refused the tests' user's workspace with the answer of a directory
    // outside the roots.
    const workspace = service.workspace("bound");
    const before = runCalls(service).length;
    const outside = await service.create("carol", service.root);
    const carol = await service.create("carol", workspace);
    assert.equal(carol.status, 422);
    assert.equal(carol.json().error.code, "workspace_not_allowed");
    assert.equal(carol.text, outside.text);
    assert.equal(carol.text.includes(workspace), false);
    assert.equal(runCalls(service).length, before, "docker was asked to run");
    // No `.git/piship-workspace` was made in a project the key may not use.
    assert.equal(
      existsSync(join(workspace, ".git", "piship-workspace")),
      false,
    );
    // The key's own user's workspace works, under either key of that user.
    for (const user of ["alice", "bob"]) {
      const made = await service.create(user, workspace);
      assert.equal(made.status, 201, `${user}: ${made.text}`);
      await service.call(`/v1/sandboxes/${made.id}`, {
        method: "DELETE",
        key: user,
      });
    }
    // An entry that says unbound may mount any non-root owner's workspace.
    const open = await service.create("erin", workspace);
    assert.equal(open.status, 201, open.text);
    await service.call(`/v1/sandboxes/${open.id}`, {
      method: "DELETE",
      key: "erin",
    });
  });

  it("holds a key with its own roots to them, and inside the service's roots", async () => {
    const inside = service.workspace("dave/project");
    const beside = service.workspace("beside");
    const allowed = await service.create("dave", inside);
    assert.equal(allowed.status, 201, allowed.text);
    await service.call(`/v1/sandboxes/${allowed.id}`, {
      method: "DELETE",
      key: "dave",
    });
    const refused = await service.create("dave", beside);
    assert.equal(refused.status, 422);
    assert.equal(refused.json().error.code, "workspace_not_allowed");
    // Someone else's key is not narrowed by dave's roots.
    const other = await service.create("alice", beside);
    assert.equal(other.status, 201, other.text);
    await service.call(`/v1/sandboxes/${other.id}`, {
      method: "DELETE",
      key: "alice",
    });
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

describe("a workspace that belongs to root", () => {
  // The tests cannot make a directory of root's, so the reading of a
  // workspace's owner is replaced: the answer is what a stat would say.
  async function withOwner(owner, check) {
    const service = await startService({}, { owner });
    try {
      await check(service);
    } finally {
      await service.stop();
    }
  }

  it("is refused to every key, as a directory outside the roots is", async () => {
    for (const owner of [
      { uid: 0, gid: 0 },
      { uid: 0, gid: 100 },
    ])
      await withOwner(
        () => owner,
        async (service) => {
          const workspace = service.workspace("root-owned");
          const outside = await service.create("alice", service.root);
          for (const user of ["alice", "erin"]) {
            const answer = await service.create(user, workspace);
            assert.equal(answer.status, 422, `${user} uid ${owner.uid}`);
            assert.equal(answer.text, outside.text);
          }
          assert.equal(runCalls(service).length, 0);
        },
      );
  });

  it("is refused when its group is root's, whoever owns it", async () => {
    // --user 1000:0 would run commands in the root group.
    await withOwner(
      () => ({ uid: HOST_UID, gid: 0 }),
      async (service) => {
        const workspace = service.workspace("root-group");
        for (const user of ["alice", "erin"]) {
          const answer = await service.create(user, workspace);
          assert.equal(answer.status, 422, user);
          assert.equal(answer.json().error.code, "workspace_not_allowed");
        }
        assert.equal(runCalls(service).length, 0);
        assert.equal(
          existsSync(join(workspace, ".git", "piship-workspace")),
          false,
        );
      },
    );
  });

  it("runs commands as the owner's user and group when neither is root's", async () => {
    await withOwner(
      () => ({ uid: HOST_UID, gid: 4711 }),
      async (service) => {
        const answer = await service.create(
          "alice",
          service.workspace("group-4711"),
        );
        assert.equal(answer.status, 201, answer.text);
        assert.deepEqual(flagValues(runCalls(service)[0].args, "--user"), [
          `${HOST_UID}:4711`,
        ]);
      },
    );
  });

  it("is checked against the key before anything is made in it", async () => {
    // Another user's uid: a bound key is refused before the service makes
    // .git/piship-workspace in a project that is not its user's.
    await withOwner(
      () => ({ uid: HOST_UID + 5, gid: 4711 }),
      async (service) => {
        const workspace = service.workspace("someone-elses");
        assert.equal((await service.create("alice", workspace)).status, 422);
        assert.equal(
          existsSync(join(workspace, ".git", "piship-workspace")),
          false,
        );
        // An unbound key may, since it says it is not bound.
        assert.equal((await service.create("erin", workspace)).status, 201);
      },
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

  it("passes the environment on the CLI's standard input, never on its command line or in a file", async () => {
    const value =
      "a value with 'quotes' and \"more\" and $dollar and \\slash and ü";
    const before = new Set(readdirSync(tmpdir()));
    // Long enough to look at the machine while the command runs.
    const running = service.exec("alice", id, 'sleep 1; printf "%s" "$FOO"', {
      env: { FOO: value, EMPTY: "" },
    });
    const call = await until(
      () =>
        execCalls(service).find(
          (entry) => entry.environment?.variables.FOO === value,
        ),
      "the command to start",
    );
    // While it runs, nothing of the service is in the temporary directory.
    const made = readdirSync(tmpdir()).filter((name) => !before.has(name));
    assert.deepEqual(
      made.filter((name) => /piship-sandbox-service/.test(name)),
      [],
    );
    const run = await running;
    // The command got its environment, exactly.
    assert.equal(run.out, value);
    assert.equal(call.environment.interactive, true);
    assert.match(call.environment.variables.PISHIP_EXEC_ID, /^[0-9a-f]{32}$/);
    assert.equal(call.environment.variables.EMPTY, "");
    // No value is on the command line, and none is named there.
    assert.equal(JSON.stringify(call.args).includes(value), false);
    assert.equal(call.args.includes("FOO"), false);
    // Nor is a file named for Docker to open.
    assert.equal(call.args.includes("--env-file"), false);
  });

  it("runs nothing when the environment is cut short on its way in", () => {
    // What the container runs, fed here by hand: the environment ends with
    // an empty line, and without it the command does not start.
    const args = execArguments(
      { shell: "/bin/sh" },
      { workdir: "/workspace", container: "c", command: 'echo "ran $FOO"' },
    );
    const inContainer = args.slice(args.indexOf("/bin/sh") + 1);
    const input = environmentInput("0".repeat(32), [["FOO", "bar"]]);
    const whole = spawnSync("/bin/sh", inContainer, {
      input,
      encoding: "utf8",
    });
    assert.equal(whole.stdout, "ran bar\n");
    for (const cut of [input.slice(0, -1), input.slice(0, 20), ""]) {
      const done = spawnSync("/bin/sh", inContainer, {
        input: cut,
        encoding: "utf8",
      });
      assert.equal(done.status, 125);
      assert.equal(done.stdout, "");
    }
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

  /** Start `command` and return how to abort it; resolves once it has begun. */
  async function begin(command, sandbox = id) {
    const controller = new AbortController();
    const response = await fetch(
      `${service.base}/v1/sandboxes/${sandbox}/exec`,
      {
        method: "POST",
        signal: controller.signal,
        headers: {
          authorization: `Bearer ${service.keys.alice}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ command: `echo started; ${command}` }),
      },
    );
    const reader = response.body.getReader();
    await reader.read();
    const call = execCalls(service).find((entry) =>
      entry.args.includes(`echo started; ${command}`),
    );
    assert.ok(call, "the command did not start");
    return {
      execId: call.environment.variables.PISHIP_EXEC_ID,
      abort: () => controller.abort(),
    };
  }

  const cancels = (execId, phase) =>
    service
      .calls()
      .filter(
        (entry) =>
          entry.command === "cancel" &&
          entry.id === execId &&
          entry.phase === phase,
      );

  it("sweeps the sandbox when the only command is cancelled, and marks its own processes when another runs", async () => {
    // Alone: everything but the sandbox's init and its main process, whose ID
    // the service found at creation, so a process that dropped the command's
    // ID (env -u) does not survive the cancel.
    const alone = await begin("sleep 31");
    alone.abort();
    const sweep = await until(
      () => cancels(alone.execId, "done")[0],
      "the sweep",
    );
    assert.equal(sweep.mode, "sweep");
    assert.equal(sweep.main, "4242");

    // With another command running, a sweep would kill that one's processes
    // too: only the processes that carry the cancelled command's ID.
    const first = await begin("sleep 32");
    const second = await begin("sleep 33");
    first.abort();
    const marked = await until(
      () => cancels(first.execId, "done")[0],
      "the marked cancel",
    );
    assert.equal(marked.mode, "marked");
    assert.ok(
      alive(service.commandPid(second.execId)),
      "the other command was killed",
    );
    await wait(150);
    second.abort();
    const last = await until(
      () => cancels(second.execId, "done")[0],
      "the second cancel",
    );
    // The first is over by now, so the second is alone.
    assert.equal(last.mode, "sweep");
  });

  it("starts no command in a sandbox while a cancel is sweeping it", async () => {
    service.fault("CANCEL_DELAY", true, "700");
    try {
      const running = await begin("sleep 34");
      running.abort();
      await until(
        () => cancels(running.execId, "start")[0],
        "the sweep to begin",
      );
      // A command that arrives now waits for the sweep, or the sweep would kill it.
      const next = await service.exec("alice", id, "printf after-the-sweep");
      assert.equal(next.out, "after-the-sweep");
      const done = cancels(running.execId, "done")[0];
      assert.ok(done, "the sweep did not finish");
      const call = execCalls(service).find((entry) =>
        entry.args.includes("printf after-the-sweep"),
      );
      assert.ok(call.t >= done.t, "the command started during the sweep");
    } finally {
      service.fault("CANCEL_DELAY", false);
    }
  });

  it("falls back to the command's own processes when it cannot find the sandbox's main process", async () => {
    service.fault("NO_MAIN");
    let unmapped;
    try {
      unmapped = (await service.create("alice", workspace)).id;
    } finally {
      service.fault("NO_MAIN", false);
    }
    const running = await begin("sleep 35", unmapped);
    running.abort();
    const cancel = await until(
      () => cancels(running.execId, "done")[0],
      "the cancel",
    );
    // Alone in its sandbox, and still not a sweep: there is no main process
    // to leave alone.
    assert.equal(cancel.mode, "marked");
    assert.equal(cancel.main, "");
    await service.call(`/v1/sandboxes/${unmapped}`, {
      method: "DELETE",
      key: "alice",
    });
  });

  it("asks for the sandbox's main process once, before any command runs", async () => {
    const before = service.calls().length;
    const made = await service.create("alice", workspace);
    await service.exec("alice", made.id, "true");
    const after = service.calls().slice(before);
    // (The service asks the runtime's version at most every five seconds.)
    const order = after
      .map((entry) => entry.command)
      .filter((command) => command !== "version");
    assert.deepEqual(order.slice(0, 3), ["run", "main", "exec"]);
    assert.equal(order.filter((command) => command === "main").length, 1);
    await service.call(`/v1/sandboxes/${made.id}`, {
      method: "DELETE",
      key: "alice",
    });
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

  /** A second run of the first service's instance, with the same fake docker. */
  function again(first, port = 0) {
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
    config.listenPort = port;
    const lines = [];
    const second = createSandboxServer(config, {
      write: (line) => lines.push(line),
      env,
    });
    return { second, lines };
  }

  it("removes what an earlier run of this service left, and nothing else", async () => {
    const first = await startService();
    try {
      const { id } = await first.create("alice", first.workspace("restart"));
      assert.match(id, /^sbx_/);
      const abandoned = first.containers()[0];
      first.leftover("someone-elses", "other-instance");
      first.leftover("unlabelled-project", "");
      // Same instance name, another user's service (or none): not this one's.
      first.leftover("other-users-service", "contract", HOST_UID + 1);
      first.leftover("unowned-same-name", "contract", null);
      const { second, lines } = again(first);
      await second.start();
      try {
        assert.equal(first.containers().includes(abandoned), false);
        assert.deepEqual(first.containers().sort(), [
          "other-users-service",
          "someone-elses",
          "unlabelled-project",
          "unowned-same-name",
        ]);
        assert.match(lines.join(""), /"event":"service.started","removed":1/);
        // Both labels are what it asked for.
        const listing = first
          .calls()
          .filter((call) => call.command === "ps")
          .at(-1);
        assert.deepEqual(flagValues(listing.args, "--filter"), [
          "label=piship.sandbox.instance=contract",
          `label=piship.sandbox.owner=${HOST_UID}`,
        ]);
      } finally {
        await second.stop();
      }
    } finally {
      await first.stop();
    }
  });

  it("removes nothing when it cannot have its port, because another service holds it", async () => {
    const first = await startService();
    try {
      const { id } = await first.create("alice", first.workspace("held"));
      assert.match(id, /^sbx_/);
      const before = first.calls().length;
      const { second } = again(first, first.port);
      await assert.rejects(second.start(), /EADDRINUSE/);
      // It did not look for containers to remove, let alone remove the
      // running service's sandbox.
      assert.deepEqual(
        first
          .calls()
          .slice(before)
          .filter((call) => call.command === "ps" || call.command === "rm"),
        [],
      );
      assert.equal(first.containers().length, 1);
      assert.equal(
        (await first.call("/v1/status", { key: "alice" })).json().sandboxes,
        1,
      );
      await second.stop();
    } finally {
      await first.stop();
    }
  });

  /** A real service process on a free port, with the flag of a supervised one or not. */
  async function spawnService(fixture, instance, { supervised }) {
    const probe = createNetServer();
    await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const { port } = probe.address();
    await new Promise((resolve) => probe.close(resolve));
    const child = spawn(
      process.execPath,
      [fileURLToPath(new URL("../service/server.mjs", import.meta.url))],
      {
        env: {
          PATH: process.env.PATH ?? "",
          SANDBOX_LISTEN_PORT: String(port),
          SANDBOX_INSTANCE: instance,
          SANDBOX_REGISTRY: fixture.config.registry,
          SANDBOX_WORKSPACE_ROOTS: fixture.workspaces,
          SANDBOX_IMAGE: IMAGE,
          SANDBOX_DOCKER: fixture.config.docker,
          DOCKER_FAKE_DIR: join(fixture.root, "docker"),
          ...(supervised ? { SANDBOX_EXIT_ON_STDIN_END: "1" } : {}),
        },
        stdio: ["pipe", "ignore", "ignore"],
      },
    );
    const exited = new Promise((resolve) => child.once("exit", resolve));
    const base = `http://127.0.0.1:${port}`;
    await until(async () => {
      try {
        const health = await fetch(`${base}/health`);
        return (await health.json()).instance === instance;
      } catch {
        return false;
      }
    }, "the service to answer as itself");
    return { child, exited, base };
  }

  it("exits, removing its sandboxes, when the supervisor that owns it is gone", async () => {
    const fixture = await startService();
    let held;
    try {
      held = await spawnService(fixture, "stdin-owned", { supervised: true });
      const made = await fetch(`${held.base}/v1/sandboxes`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${fixture.keys.alice}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          workspace: fixture.workspace("owned"),
          network: "deny",
        }),
      });
      assert.equal(made.status, 201);
      const ours = () =>
        fixture.containers().filter((name) => name.includes("-stdin-owned-"));
      assert.equal(ours().length, 1);
      // The supervisor is gone: its end of the pipe closes.
      held.child.stdin.end();
      // A service that does not notice would otherwise hang the test.
      let timer;
      const outcome = await Promise.race([
        held.exited,
        new Promise((resolve) => {
          timer = setTimeout(() => resolve("still running"), 20_000);
        }),
      ]);
      clearTimeout(timer);
      assert.equal(outcome, 0);
      assert.deepEqual(ours(), []);
    } finally {
      held?.child.kill("SIGKILL");
      await fixture.stop();
    }
  });

  it("keeps running when its standard input closes, unless it was started by a supervisor", async () => {
    const fixture = await startService();
    let loose;
    try {
      loose = await spawnService(fixture, "stdin-loose", { supervised: false });
      loose.child.stdin.end();
      await wait(800);
      assert.equal(loose.child.exitCode, null);
      const health = await fetch(`${loose.base}/health`);
      assert.equal((await health.json()).instance, "stdin-loose");
    } finally {
      loose?.child.kill("SIGTERM");
      await loose?.exited;
      await fixture.stop();
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
