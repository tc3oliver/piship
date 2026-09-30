import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { readManifestDocument } from "@piship/schema";
import { PROJECT_PREFIX } from "../../../../tests/enterprise-reference/stack.js";
import { cliPath } from "./distribution.js";
import { keepLogs } from "./logs.js";

// The reference sandbox service (examples/enterprise-reference/sandbox) as a
// child process of a test file, and the AcmeCode reference distribution built
// with it. Everything a test starts carries its own name, `piship-reftest-
// <pid>-sandbox-<random>`, like the compose projects of the other reference
// tests: the service's instance name, so every container it makes has the
// label `piship.sandbox.instance=<name>`; the temporary directory that holds
// its keys, its workspaces, and its logs; and the service's own log file.
// `stop()` (also on exit, Ctrl-C, or termination) stops the service, which
// removes its containers, then removes anything still carrying the label and
// the directory. The suite's global setup does the same for a run that was
// killed outright. Nothing is ever pruned, and no container the test did not
// start is touched.

export const sandboxDirectory = fileURLToPath(
  new URL("../../sandbox/", import.meta.url),
);
const composeFile = fileURLToPath(
  new URL("../../compose.yaml", import.meta.url),
);

/**
 * The distribution's ID and launcher command, as its manifest names them: the
 * one place these tests learn them, so a rename of either is a change to the
 * manifest and its lock, and to nothing here.
 */
export const distribution = (() => {
  const { app } = readManifestDocument(
    join(sandboxDirectory, "piship.yaml"),
  ) as { app: { id: string; command: string } };
  return { id: app.id, command: app.command };
})();

/** Beside the stack's own ports (18xxx, 28xxx, 38xxx, 58xxx). */
const DEFAULT_PORT = 48075;

export type SandboxUser = "alice" | "bob";

/**
 * The image the tests run their sandboxes in: Ubuntu 24.04, pinned by its
 * multi-arch index digest. It has what PiShip's checks and a coding agent
 * need (`sh` and `bash`, GNU coreutils, `timeout`, `/proc`), and its `test -w`
 * answers from the kernel, which matters: PiShip attests that a read-only
 * `.git` cannot be renamed with `[ -w .git ]`, and BusyBox's `test` (Alpine)
 * reads the mode bits and calls a read-only mount writable.
 */
export const SANDBOX_IMAGE =
  "ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3";

/**
 * The image the stack's own Node services run, pinned by digest in
 * compose.yaml, which a run that has pulled the stack already has. The
 * network target listens in it.
 */
export function nodeImage(): string {
  const found = /^\s+image: (node:\S+)\s*$/m.exec(
    readFileSync(composeFile, "utf8"),
  );
  if (!found?.[1]) throw new Error("compose.yaml names no node image");
  return found[1];
}

/** Pull the image unless it is here, so no sandbox waits for a registry. */
function ensureImage(image: string): void {
  if (
    spawnSync("docker", ["image", "inspect", image], { encoding: "utf8" })
      .status === 0
  )
    return;
  const pulled = spawnSync("docker", ["pull", "--quiet", image], {
    encoding: "utf8",
    timeout: 300_000,
  });
  if (pulled.status !== 0)
    throw new Error(`docker pull ${image} failed: ${pulled.stderr.trim()}`);
}

export interface Answer {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly text: string;
  json(): unknown;
}

export interface SandboxService {
  readonly instance: string;
  readonly url: string;
  readonly port: number;
  readonly image: string;
  /** The only directory tree the service may mount. */
  readonly root: string;
  /** A user's API key. A secret: never print or assert on it. */
  key(user: SandboxUser): string;
  /** A request to the service; `user` or `key` names the credential, if any. */
  request(
    path: string,
    init?: {
      readonly method?: string;
      readonly user?: SandboxUser;
      readonly key?: string;
      readonly body?: unknown;
      readonly headers?: Readonly<Record<string, string>>;
    },
  ): Promise<Answer>;
  /** How many sandboxes the user holds now. */
  sandboxes(user?: SandboxUser): Promise<number>;
  /** IDs of the containers carrying this service's label, running or not. */
  containers(): string[];
  /** Stop the service; resolves with the containers it left behind. */
  stop(): Promise<{ readonly leftover: readonly string[] }>;
}

const label = (instance: string) => `piship.sandbox.instance=${instance}`;

export function containersOf(instance: string): string[] {
  const listed = spawnSync(
    "docker",
    ["ps", "--all", "--quiet", "--filter", `label=${label(instance)}`],
    { encoding: "utf8" },
  );
  if (listed.status !== 0)
    throw new Error(`docker ps failed: ${listed.stderr.trim()}`);
  return listed.stdout.split("\n").filter(Boolean);
}

/**
 * Issue the two users' keys with the administrator's script, start the
 * service on a loopback port, and return once it answers.
 */
export async function startSandboxService(): Promise<SandboxService> {
  const instance = `${PROJECT_PREFIX}${process.pid}-sandbox-${Math.random().toString(16).slice(2, 8)}`;
  const temp = realpathSync(mkdtempSync(join(tmpdir(), `${instance}-`)));
  const root = join(temp, "workspaces");
  const keys = join(temp, "keys");
  mkdirSync(root, { mode: 0o700 });
  const port = Number(process.env.SANDBOX_PORT ?? DEFAULT_PORT);
  const image = SANDBOX_IMAGE;
  ensureImage(image);
  const secrets = new Map<SandboxUser, string>();
  for (const user of ["alice", "bob"] as const) {
    const issued = spawnSync(
      process.execPath,
      [
        join(sandboxDirectory, "scripts", "generate-key.mjs"),
        "--user",
        user,
        "--dir",
        keys,
      ],
      { encoding: "utf8" },
    );
    if (issued.status !== 0) {
      rmSync(temp, { recursive: true, force: true });
      throw new Error(`generate-key failed: ${issued.stderr}`);
    }
    secrets.set(user, readFileSync(join(keys, `${user}.key`), "utf8").trim());
  }
  // What the scrubber removes from the logs that are kept.
  const envFile = join(temp, ".env");
  writeFileSync(
    envFile,
    [...secrets]
      .map(([user, key]) => `SANDBOX_KEY_${user.toUpperCase()}=${key}\n`)
      .join(""),
    { mode: 0o600 },
  );
  chmodSync(envFile, 0o600);

  // The service reads only what is set here; a developer's SANDBOX_*
  // variables never reach it.
  const environment: NodeJS.ProcessEnv = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !name.startsWith("SANDBOX_"),
    ),
  );
  Object.assign(environment, {
    SANDBOX_LISTEN_PORT: String(port),
    SANDBOX_INSTANCE: instance,
    SANDBOX_REGISTRY: join(keys, "registry.json"),
    SANDBOX_WORKSPACE_ROOTS: root,
    SANDBOX_IMAGE: image,
    SANDBOX_SHELL: "/bin/bash",
  });
  const child: ChildProcess = spawn(
    process.execPath,
    [join(sandboxDirectory, "service", "server.mjs")],
    { env: environment, stdio: ["ignore", "ignore", "pipe"] },
  );
  let logs = "";
  child.stderr?.on("data", (chunk) => {
    if (logs.length < 4_000_000) logs += chunk;
  });
  let exited: number | null | undefined;
  child.once("exit", (code) => {
    exited = code;
  });

  let stopped: Promise<{ leftover: string[] }> | undefined;
  const finish = () => {
    if (logs) keepLogs(instance, envFile, logs);
    const leftover = containersOf(instance);
    // The service removes its own sandboxes when it stops; whatever is still
    // labelled with this instance (an error path, a test's own container) is
    // removed here, by ID, never by a filter that could match another's.
    if (leftover.length > 0)
      spawnSync("docker", ["rm", "--force", ...leftover], { encoding: "utf8" });
    rmSync(temp, { recursive: true, force: true });
    return { leftover };
  };
  const stop = () => {
    stopped ??= (async () => {
      process.off("exit", onExit);
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      if (exited === undefined) {
        const ended = new Promise<void>((resolve) =>
          child.once("exit", () => resolve()),
        );
        child.kill("SIGTERM");
        const timer = setTimeout(() => child.kill("SIGKILL"), 60_000);
        await ended;
        clearTimeout(timer);
      }
      return finish();
    })();
    return stopped;
  };
  const onExit = () => {
    if (stopped) return;
    child.kill("SIGKILL");
    const leftover = containersOf(instance);
    if (leftover.length > 0)
      spawnSync("docker", ["rm", "--force", ...leftover], { encoding: "utf8" });
    rmSync(temp, { recursive: true, force: true });
  };
  const onSignal = (signal: NodeJS.Signals) => {
    onExit();
    process.exit(signal === "SIGINT" ? 130 : 143);
  };
  process.once("exit", onExit);
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (exited !== undefined) {
      await stop();
      throw new Error(
        `the sandbox service exited (${exited}) at start:\n${logs.slice(-2000)}`,
      );
    }
    try {
      if ((await fetch(`${url}/health`)).ok) break;
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) {
      await stop();
      throw new Error(
        `the sandbox service did not answer:\n${logs.slice(-2000)}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  const key = (user: SandboxUser) => {
    const value = secrets.get(user);
    if (!value) throw new Error(`no key for ${user}`);
    return value;
  };
  const request: SandboxService["request"] = async (path, init = {}) => {
    const credential = init.key ?? (init.user ? key(init.user) : undefined);
    const response = await fetch(`${url}${path}`, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      headers: {
        // A fresh connection each time: this file blocks its event loop while
        // it runs docker, so a pooled connection the service closed after its
        // idle timeout would still look open when the next request reuses it.
        connection: "close",
        ...(credential ? { authorization: `Bearer ${credential}` } : {}),
        ...(init.body === undefined
          ? {}
          : { "content-type": "application/json" }),
        ...init.headers,
      },
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    });
    const text = await response.text();
    return {
      status: response.status,
      headers: Object.fromEntries(response.headers),
      text,
      json: () => JSON.parse(text) as unknown,
    };
  };
  return {
    instance,
    url,
    port,
    image,
    root,
    key,
    request,
    async sandboxes(user = "alice") {
      const answer = await request("/v1/status", { user });
      return (answer.json() as { sandboxes: number }).sandboxes;
    },
    containers: () => containersOf(instance),
    stop,
  };
}

export interface NetworkTarget {
  readonly host: string;
  readonly port: number;
  /** Remove the container; the service's leftovers are counted after this. */
  remove(): void;
}

/**
 * A TCP listener in a container of its own on Docker's default bridge, which
 * a sandbox with the network allowed can reach and one without cannot. It
 * carries the service's label, so it is removed with the rest.
 */
export function startNetworkTarget(service: SandboxService): NetworkTarget {
  const started = spawnSync(
    "docker",
    [
      "run",
      "--detach",
      "--rm",
      "--label",
      label(service.instance),
      "--network",
      "bridge",
      nodeImage(),
      "node",
      "-e",
      "require('net').createServer((socket) => socket.destroy()).listen(9000, '0.0.0.0')",
    ],
    { encoding: "utf8" },
  );
  if (started.status !== 0)
    throw new Error(
      `the network target did not start: ${started.stderr.trim()}`,
    );
  const id = started.stdout.trim();
  // Listening, not just started.
  const listening = () =>
    spawnSync(
      "docker",
      [
        "exec",
        id,
        "node",
        "-e",
        "require('net').connect(9000, '127.0.0.1').on('connect', () => process.exit(0)).on('error', () => process.exit(1))",
      ],
      { encoding: "utf8" },
    ).status === 0;
  for (let attempt = 0; attempt < 40 && !listening(); attempt++)
    spawnSync("sleep", ["0.25"]);
  if (!listening()) {
    spawnSync("docker", ["rm", "--force", id], { encoding: "utf8" });
    throw new Error("the network target is not listening");
  }
  const address = spawnSync(
    "docker",
    [
      "inspect",
      "--format",
      "{{.NetworkSettings.Networks.bridge.IPAddress}}",
      id,
    ],
    { encoding: "utf8" },
  ).stdout.trim();
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(address))
    throw new Error("the network target has no address on the default bridge");
  return {
    host: address,
    port: 9000,
    remove: () => {
      spawnSync("docker", ["rm", "--force", id], { encoding: "utf8" });
    },
  };
}

export interface BuiltDistribution {
  /** The built payload: what an installed AcmeCode runs from. */
  readonly artifact: string;
  readonly remove: () => void;
}

/**
 * Build the sandbox variant of the reference distribution from a copy of its
 * committed files, as they are: `piship build` refuses a lock that no longer
 * matches the manifest and the adapter, so this builds exactly what is
 * committed.
 */
export function buildSandboxDistribution(name: string): BuiltDistribution {
  const temp = mkdtempSync(
    join(tmpdir(), `${PROJECT_PREFIX}${process.pid}-${name}-`),
  );
  const directory = join(temp, "distribution");
  mkdirSync(directory);
  for (const entry of [
    "piship.yaml",
    "piship.lock",
    "acme-container-sandbox.mjs",
    "resources",
  ])
    cpSync(join(sandboxDirectory, entry), join(directory, entry), {
      recursive: true,
    });
  const env: NodeJS.ProcessEnv = { ...process.env };
  // Reference and E2E builds use packages/core/dist/build-input.
  for (const variable of ["PISHIP_BUILD_INPUT", "PISHIP_SANDBOX_ADAPTER"])
    delete env[variable];
  const built = spawnSync(
    process.execPath,
    [cliPath, "build", join(directory, "piship.yaml")],
    { cwd: temp, env, encoding: "utf8" },
  );
  if (built.status !== 0) {
    rmSync(temp, { recursive: true, force: true });
    throw new Error(
      `piship build failed (exit ${built.status}):\n${built.stderr}`,
    );
  }
  return {
    artifact: join(temp, "dist", distribution.id),
    remove: () => rmSync(temp, { recursive: true, force: true }),
  };
}
