// The service under test with a fake docker CLI, five users' keys, and a
// directory of workspaces it may mount. Everything lives in one temporary
// directory that `stop()` removes.
import { randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createSandboxServer, loadConfig } from "../service/server.mjs";
import { REGISTRY_SCHEMA, sha256Hex } from "../service/src/auth.mjs";

const FAKE_DOCKER = fileURLToPath(new URL("./fake-docker", import.meta.url));
export const IMAGE = "example.invalid/sandbox-image:1";

export const newKey = () => `sbxk_${randomBytes(32).toString("base64url")}`;

/** A git repository's control files under `path`, as PiShip finds a project. */
export function makeRepository(path) {
  for (const directory of [".git/hooks", ".git/info"])
    mkdirSync(join(path, directory), { recursive: true });
  writeFileSync(join(path, ".git", "config"), "[core]\n\tbare = false\n");
  writeFileSync(join(path, ".git", "HEAD"), "ref: refs/heads/main\n");
  return path;
}

/** The host user of the tests: the owner of every workspace they make. */
export const HOST_UID = process.getuid?.() ?? 1000;

/**
 * @param {Record<string, string>} [extraEnv] service settings for the test
 * @param {{owner?: (path: string) => {uid: number, gid: number}}} [options]
 *   `owner` replaces how a workspace's owner is read
 *
 * Five keys: alice and bob are bound to the host user of the tests, carol to
 * another user, dave to the host user and to one directory (`dave`), and erin
 * is unbound.
 */
export async function startService(extraEnv = {}, options = {}) {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "piship-sandbox-contract-")),
  );
  const docker = join(root, "docker");
  const workspaces = join(root, "workspaces");
  const keysDirectory = join(root, "keys");
  for (const path of [docker, workspaces, keysDirectory])
    mkdirSync(path, { mode: 0o700 });
  mkdirSync(join(workspaces, "dave"));
  const bindings = {
    alice: { uid: HOST_UID },
    bob: { uid: HOST_UID },
    carol: { uid: HOST_UID + 1 },
    dave: { uid: HOST_UID, roots: [join(workspaces, "dave")] },
    erin: { unbound: true },
  };
  const keys = Object.fromEntries(
    Object.keys(bindings).map((id) => [id, newKey()]),
  );
  const registry = join(keysDirectory, "registry.json");
  writeFileSync(
    registry,
    JSON.stringify({
      schema: REGISTRY_SCHEMA,
      keys: Object.entries(keys).map(([id, key]) => ({
        id,
        sha256: sha256Hex(key),
        ...bindings[id],
      })),
    }),
    { mode: 0o600 },
  );
  const env = {
    PATH: process.env.PATH ?? "",
    // A free port the system chooses, as the live test asks for.
    SANDBOX_LISTEN_PORT: "0",
    SANDBOX_INSTANCE: "contract",
    SANDBOX_REGISTRY: registry,
    SANDBOX_WORKSPACE_ROOTS: workspaces,
    SANDBOX_IMAGE: IMAGE,
    SANDBOX_DOCKER: FAKE_DOCKER,
    SANDBOX_SWEEP_MS: "50",
    DOCKER_FAKE_DIR: docker,
    DOCKER_FAKE_CWD: workspaces,
    ...extraEnv,
  };
  const config = loadConfig(env);
  const lines = [];
  const service = createSandboxServer(config, {
    write: (line) => lines.push(line),
    env,
    ...(options.owner ? { owner: options.owner } : {}),
  });
  const port = await service.start();
  const base = `http://127.0.0.1:${port}`;

  return {
    root,
    workspaces,
    keys,
    config,
    port,
    base,
    /** Every line the service logged. */
    logs: () => lines.join(""),
    /** Every invocation of the fake docker, parsed. */
    calls: () =>
      existsSync(join(docker, "calls.jsonl"))
        ? readFileSync(join(docker, "calls.jsonl"), "utf8")
            .split("\n")
            .filter(Boolean)
            .map((line) => JSON.parse(line))
        : [],
    /** Containers the fake docker holds, by name. */
    containers: () =>
      readdirSync(join(docker, "containers")).map((file) =>
        file.replace(/\.json$/, ""),
      ),
    /**
     * Turn a fault of the fake docker on or off: `DOWN`, `RUN_FAIL`, `NO_MAIN`,
     * `NO_STAT`, `CANCEL_DELAY` (its `content` is the milliseconds), or `SWAP`
     * (its `content` is `{"path", "to"}` as JSON).
     */
    fault(name, on = true, content = "") {
      const file = join(docker, name);
      if (on) writeFileSync(file, content);
      else rmSync(file, { force: true });
    },
    /**
     * A leftover container of `instance` started by the service user `owner`
     * (the host user of the tests by default; none, with `null`).
     */
    leftover(name, instance, owner = HOST_UID) {
      writeFileSync(
        join(docker, "containers", `${name}.json`),
        JSON.stringify({
          name,
          labels: [
            `piship.sandbox.instance=${instance}`,
            ...(owner === null ? [] : [`piship.sandbox.owner=${owner}`]),
          ],
          args: [],
        }),
      );
    },
    workspace: (name) => makeRepository(join(workspaces, name)),
    /**
     * One request. `key` names a user (`alice`), a raw credential (a string
     * that is not a user), or nothing.
     */
    async call(path, { method = "GET", key, body, headers = {}, raw } = {}) {
      const credential = key === undefined ? undefined : (keys[key] ?? key);
      const response = await fetch(`${base}${path}`, {
        method,
        headers: {
          ...(credential ? { authorization: `Bearer ${credential}` } : {}),
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
          ...headers,
        },
        ...(raw !== undefined
          ? { body: raw }
          : body !== undefined
            ? { body: JSON.stringify(body) }
            : {}),
      });
      const text = await response.text();
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers),
        text,
        json: () => JSON.parse(text),
      };
    },
    async create(user, workspace, extra = {}) {
      const answer = await this.call("/v1/sandboxes", {
        method: "POST",
        key: user,
        body: { workspace, network: "deny", ...extra },
      });
      return { ...answer, id: answer.status === 201 ? answer.json().id : "" };
    },
    /** Run a command and collect its output and exit. */
    async exec(user, id, command, extra = {}) {
      const answer = await this.call(`/v1/sandboxes/${id}/exec`, {
        method: "POST",
        key: user,
        body: { command, ...extra },
      });
      if (answer.status !== 200) return { ...answer, out: "", err: "" };
      let out = "";
      let err = "";
      let exit;
      for (const line of answer.text.split("\n").filter(Boolean)) {
        const record = JSON.parse(line);
        if (record.stream === "stdout")
          out += Buffer.from(record.data, "base64").toString();
        else if (record.stream === "stderr")
          err += Buffer.from(record.data, "base64").toString();
        else exit = record;
      }
      return { ...answer, out, err, exit };
    },
    /** The process a command started by the fake docker runs as, by its ID. */
    commandPid(id) {
      const file = join(docker, "execs", `${id}.json`);
      return existsSync(file)
        ? JSON.parse(readFileSync(file, "utf8")).pid
        : undefined;
    },
    /** Stop the service; returns the containers it left behind. */
    async stop() {
      await service.stop();
      const leftover = readdirSync(join(docker, "containers")).map((file) =>
        file.replace(/\.json$/, ""),
      );
      // A fake `docker` started by a cancel may still be appending to its log
      // when the service has stopped: retry while the directory refills.
      rmSync(root, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 100,
      });
      return { leftover };
    },
  };
}

export const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Poll until `check` returns a truthy value, or fail after `ms`. */
export async function until(check, what, ms = 5000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await wait(25);
  }
}
