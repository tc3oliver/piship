import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EPHEMERAL_PORTS,
  type PortName,
  publishedPorts,
  type StackPorts,
  startWithPublishedPorts,
} from "../../examples/enterprise-reference/tests/support/ports.js";
import { registerTeardown } from "../../examples/enterprise-reference/tests/support/teardown.js";

// The live enterprise reference stack (examples/enterprise-reference) for
// `npm run test:reference`. Each test file starts its own copy under its own
// Compose project, on host ports Docker chooses (the example's
// tests/support/ports.ts), with its own `.env` in a temporary directory (never
// the git-ignored one beside compose.yaml), and stops it in afterAll. Two runs
// on one host never meet.
//
// Everything this module returns that is a secret (tokens, keys, the master
// key) stays in memory. Response bodies are scrubbed of key and token shapes
// before a test asserts on them, so a failed assertion cannot print one.

const reference = fileURLToPath(
  new URL("../../examples/enterprise-reference/", import.meta.url),
);

/** Every Compose project and temporary directory of these tests starts with this, then the owning PID. */
export const PROJECT_PREFIX = "piship-reftest-";

export interface HttpResult {
  status: number;
  /** Parsed JSON, or the text when the body is not JSON. */
  body: unknown;
  /** The body as text with every key and token shape replaced. */
  scrubbed: string;
  headers: Record<string, string>;
}

export interface Credential {
  /** The LiteLLM virtual key. A secret: never print or assert on it. */
  key: string;
  /** SHA-256 of the key: what LiteLLM stores and writes to spend logs. */
  hash: string;
  credentialId: string;
  models: string[];
}

export interface SpendLog {
  api_key: string;
  user: string;
  spend: number;
  total_tokens: number;
  model_group: string;
  status: string;
  startTime: string;
}

/** LiteLLM's key hash: SHA-256 hex of the `sk-` key. */
export const keyHash = (key: string) =>
  createHash("sha256").update(key).digest("hex");

/** Replace anything shaped like a LiteLLM key or a JWT. */
export function scrub(text: string): string {
  return text
    .replace(/sk-[A-Za-z0-9_-]{4,}/g, "sk-<redacted>")
    .replace(
      /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
      "<redacted-jwt>",
    );
}

function run(args: string[], env: NodeJS.ProcessEnv) {
  return spawnSync("docker", args, {
    cwd: reference,
    encoding: "utf8",
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
}

function readEnvFile(path: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (match?.[1] !== undefined) values[match[1]] = match[2] ?? "";
  }
  return values;
}

/** One HTTP request; the bearer, if any, goes only into the header. */
export async function request(
  url: string,
  init: { method?: string; bearer?: string; body?: unknown } = {},
): Promise<HttpResult> {
  const response = await fetch(url, {
    method: init.method ?? (init.body === undefined ? "GET" : "POST"),
    headers: {
      ...(init.bearer ? { authorization: `Bearer ${init.bearer}` } : {}),
      ...(init.body === undefined
        ? {}
        : { "content-type": "application/json" }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // Not JSON: keep the text.
  }
  return {
    status: response.status,
    body,
    scrubbed: scrub(text),
    headers: Object.fromEntries(response.headers),
  };
}

export interface PollResult<T> {
  value: T;
  elapsedMs: number;
}

/**
 * Poll until `check` returns a value that is not undefined. LiteLLM writes
 * spend in batches a few seconds after a request, so every spend assertion
 * waits for the records to land instead of sleeping.
 */
export async function poll<T>(
  what: string,
  check: () => Promise<T | undefined>,
  { timeoutMs = 45_000, intervalMs = 500 } = {},
): Promise<PollResult<T>> {
  const started = performance.now();
  for (;;) {
    const value = await check();
    const elapsedMs = Math.round(performance.now() - started);
    if (value !== undefined) return { value, elapsedMs };
    if (elapsedMs > timeoutMs)
      throw new Error(`timed out after ${elapsedMs} ms waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

export type TestPorts = StackPorts;

export interface ReferenceStack {
  project: string;
  /**
   * The host ports Docker chose on 127.0.0.1, read again by
   * `service("start")`: a container started again gets a new port.
   */
  readonly ports: TestPorts;
  readonly gateway: string;
  readonly broker: string;
  /** The mock upstream, for its `/__mock` control endpoints. */
  readonly mock: string;
  /** Seconds `docker compose up --wait` took. */
  startupSeconds: number;
  /** A Keycloak access token for alice or bob, by the Authorization Code + PKCE flow. */
  accessToken(user: "alice" | "bob"): string;
  /**
   * The whole token response of that flow: access token, ID token, and the
   * refresh token. Live credentials for the reference realm; keep them in
   * memory and never print them.
   */
  tokenResponse(user: "alice" | "bob"): {
    access_token: string;
    id_token: string;
    refresh_token?: string;
  };
  /** A fixture user's password, for the Keycloak sign-in form only. */
  password(user: "alice" | "bob"): string;
  /** Sign the user in and acquire a credential from the real broker. */
  acquire(user: "alice" | "bob"): Promise<Credential>;
  /** Revoke a credential through the broker, as PiShip does. */
  revoke(credential: Credential): Promise<HttpResult>;
  /** A LiteLLM admin call with the master key. */
  admin(path: string, body?: unknown): Promise<HttpResult>;
  /** A chat completion sent straight to LiteLLM with a virtual key. */
  chat(
    key: string,
    options?: { model?: string; words?: number; delayMs?: number },
  ): Promise<HttpResult>;
  /** GET /v1/models with a virtual key. */
  models(key: string): Promise<HttpResult>;
  /** The completion requests that reached the mock upstream (its last 100), oldest first. */
  upstreamRequests(): Promise<{ model: string; status: number }[]>;
  /** The LiteLLM user a key belongs to (by its hash, so the key stays out of URLs). */
  keyInfo(hash: string): Promise<Record<string, unknown>>;
  /** LiteLLM's own spend records of a user: its `/spend/users` row and its spend logs. */
  userSpend(userId: string): Promise<{
    spend: number;
    maxBudget: number | null;
    row: Record<string, unknown>;
    logs: SpendLog[];
  }>;
  /**
   * Stop one service of this stack, or start it again and wait for its
   * healthcheck. A start reads the ports again, and the URLs follow. Keycloak
   * and LiteLLM are never started again: the broker holds their ports.
   */
  service(action: "stop" | "start", name: string): void;
  stop(): void;
}

/**
 * Start the reference stack under a Compose project of its own and wait for
 * every healthcheck (`up --wait`, no sleeps). `brokerEnv` adds broker
 * settings (budget, limits) through an override file beside the `.env`.
 */
export function startReferenceStack({
  name,
  brokerEnv = {},
}: {
  name: string;
  brokerEnv?: Record<string, string>;
}): ReferenceStack {
  // The owning process's PID is part of both names, so global-setup.ts can
  // remove what a killed run left behind without touching a live one.
  const project = `${PROJECT_PREFIX}${process.pid}-${name}-${randomBytes(3).toString("hex")}`;
  const directory = mkdtempSync(
    join(tmpdir(), `${PROJECT_PREFIX}${process.pid}-`),
  );
  const envFile = join(directory, ".env");
  const generated = spawnSync(
    process.execPath,
    [join(reference, "scripts/generate-env.mjs"), "--out", envFile],
    { env: { ...process.env, ...EPHEMERAL_PORTS }, encoding: "utf8" },
  );
  if (generated.status !== 0) {
    rmSync(directory, { recursive: true, force: true });
    throw new Error(`generate-env.mjs failed: ${generated.stderr.trim()}`);
  }
  const files = ["-f", join(reference, "compose.yaml")];
  if (Object.keys(brokerEnv).length > 0) {
    const override = join(directory, "override.yaml");
    writeFileSync(
      override,
      [
        "services:",
        "  broker:",
        "    environment:",
        ...Object.entries(brokerEnv).map(
          ([variable, value]) => `      ${variable}: ${JSON.stringify(value)}`,
        ),
        "",
      ].join("\n"),
    );
    files.push("-f", override);
  }
  const compose = ["compose", "-p", project, "--env-file", envFile, ...files];
  // Compose prefers the shell over the env file, so a variable of the same
  // name in the developer's shell must not replace a generated value or a
  // port Docker chose.
  const dockerEnv: NodeJS.ProcessEnv = { ...process.env };
  for (const variable of [
    ...Object.keys(readEnvFile(envFile)),
    "KEYCLOAK_PUBLISHED_PORT",
    "LITELLM_PUBLISHED_PORT",
  ])
    delete dockerEnv[variable];
  const composeRun = (args: readonly string[]) =>
    run([...compose, ...args], dockerEnv);

  // The worker's exit, Ctrl-C, or termination between start and afterAll still
  // stops the stack, and a stop that failed can be called again (see
  // teardown.ts). A worker killed outright cannot: global-setup.ts removes
  // that stack on the next run.
  const stop = registerTeardown({
    project,
    envFile,
    directory,
    compose: composeRun,
    // No `-v`: the stack has no named volume and keeps its data on tmpfs.
    downArguments: ["down", "--remove-orphans"],
  });

  const started = performance.now();
  const up = startWithPublishedPorts(composeRun, envFile, [
    "up",
    "-d",
    "--wait",
    "--wait-timeout",
    "300",
  ]);
  const startupSeconds = Math.round((performance.now() - started) / 100) / 10;
  let ports: TestPorts | undefined;
  let failure = up.status === 0 ? undefined : (up.stderr ?? "").trim();
  if (failure === undefined)
    try {
      ports = publishedPorts(composeRun);
    } catch (error) {
      failure = error instanceof Error ? error.message : String(error);
    }
  if (failure !== undefined || !ports) {
    // Service states only: container logs can hold configuration values.
    const ps = composeRun([
      "ps",
      "-a",
      "--format",
      "{{.Service}} {{.State}} {{.Health}}",
    ]);
    try {
      stop();
    } catch {
      // Report the start failure, not the cleanup one.
    }
    throw new Error(
      `docker compose up failed for ${project}:\n${scrub(failure ?? "")}\n${ps.stdout}`,
    );
  }
  let current: TestPorts = ports;
  const url = (name: PortName) => `http://127.0.0.1:${current[name]}`;

  const env = readEnvFile(envFile);
  const masterKey = env.LITELLM_MASTER_KEY;

  const getToken = (user: "alice" | "bob", args: string[] = []) => {
    // The helper prints the token on stdout; it is captured, never shown.
    const result = spawnSync(
      process.execPath,
      [join(reference, "scripts/get-token.mjs"), user, ...args],
      {
        env: {
          ...process.env,
          ...env,
          KEYCLOAK_PORT: String(current.KEYCLOAK_PORT),
        },
        encoding: "utf8",
      },
    );
    if (result.status !== 0)
      throw new Error(
        `get-token.mjs ${user} failed: ${scrub(result.stderr.trim())}`,
      );
    return result.stdout.trim();
  };
  const accessToken = (user: "alice" | "bob") => getToken(user);
  const tokenResponse = (user: "alice" | "bob") =>
    JSON.parse(getToken(user, ["--response"]));

  const admin = (path: string, body?: unknown) =>
    request(`${url("LITELLM_PORT")}${path}`, {
      ...(masterKey === undefined ? {} : { bearer: masterKey }),
      body,
    });

  return {
    project,
    get ports() {
      return { ...current };
    },
    get gateway() {
      return url("LITELLM_PORT");
    },
    get broker() {
      return url("BROKER_PORT");
    },
    get mock() {
      return url("MOCK_UPSTREAM_PORT");
    },
    startupSeconds,
    accessToken,
    tokenResponse,
    password(user) {
      const value = env[`REFERENCE_${user.toUpperCase()}_PASSWORD`];
      if (!value) throw new Error(`no password generated for ${user}`);
      return value;
    },
    async acquire(user) {
      const response = await request(`${url("BROKER_PORT")}/v1/credential`, {
        bearer: accessToken(user),
        body: { distribution: "acmecode-reference", purpose: "inference" },
      });
      if (response.status !== 200)
        throw new Error(
          `broker acquire for ${user} answered ${response.status} ${response.scrubbed}`,
        );
      const body = response.body as {
        credential: string;
        credential_id: string;
        models: string[];
      };
      return {
        key: body.credential,
        hash: keyHash(body.credential),
        credentialId: body.credential_id,
        models: body.models,
      };
    },
    revoke(credential) {
      return request(`${url("BROKER_PORT")}/v1/revoke`, {
        bearer: credential.key,
        body: {
          credential_id: credential.credentialId,
          distribution: "acmecode-reference",
        },
      });
    },
    admin,
    chat(key, { model = "acme/coder", words = 10, delayMs } = {}) {
      // The mock counts prompt tokens as whitespace-separated words, and
      // holds a request that carries `[mock:delay=MS]`.
      const content = Array(words).fill("word");
      if (delayMs !== undefined) content.push(`[mock:delay=${delayMs}]`);
      return request(`${url("LITELLM_PORT")}/v1/chat/completions`, {
        bearer: key,
        body: {
          model,
          messages: [{ role: "user", content: content.join(" ") }],
        },
      });
    },
    models(key) {
      return request(`${url("LITELLM_PORT")}/v1/models`, { bearer: key });
    },
    async upstreamRequests() {
      const response = await request(
        `${url("MOCK_UPSTREAM_PORT")}/__mock/requests`,
      );
      return (
        response.body as { requests: { model: string; status: number }[] }
      ).requests;
    },
    async keyInfo(hash) {
      const response = await admin(`/key/info?key=${hash}`);
      if (response.status !== 200)
        throw new Error(`/key/info answered ${response.status}`);
      return (response.body as { info: Record<string, unknown> }).info;
    },
    async userSpend(userId) {
      const id = encodeURIComponent(userId);
      const users = await admin(`/spend/users?user_id=${id}`);
      const logs = await admin(`/spend/logs?user_id=${id}`);
      if (users.status !== 200 || logs.status !== 200)
        throw new Error(
          `spend APIs answered ${users.status} and ${logs.status}`,
        );
      const row = (users.body as Record<string, unknown>[])[0] ?? {};
      return {
        spend: Number(row.spend ?? 0),
        maxBudget: typeof row.max_budget === "number" ? row.max_budget : null,
        row,
        logs: logs.body as SpendLog[],
      };
    },
    service(action, name) {
      if (action === "start" && (name === "keycloak" || name === "litellm"))
        throw new Error(
          `${name} cannot be started again: the broker holds its host port`,
        );
      const done =
        action === "stop"
          ? composeRun(["stop", name])
          : composeRun(["up", "-d", "--wait", "--wait-timeout", "120", name]);
      if (done.status !== 0)
        throw new Error(
          `docker compose ${action} ${name} failed for ${project}: ${scrub(done.stderr.trim())}`,
        );
      if (action === "start") current = publishedPorts(composeRun);
    },
    stop,
  };
}

/** The OpenAI-style `error.type` of a LiteLLM answer, if any. */
export function errorType(result: HttpResult | undefined): string | undefined {
  const error = (result?.body as { error?: { type?: unknown } } | undefined)
    ?.error;
  return typeof error?.type === "string" ? error.type : undefined;
}

/** Sum with rounding noise removed: LiteLLM adds float costs. */
export const sum = (values: number[]) =>
  Math.round(values.reduce((total, value) => total + value, 0) * 1e9) / 1e9;
