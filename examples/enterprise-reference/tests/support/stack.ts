import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PROJECT_PREFIX } from "../../../../tests/enterprise-reference/stack.js";
import { registerTeardown } from "./teardown.js";

// The enterprise reference stack (Keycloak, PostgreSQL, LiteLLM, the broker and
// the mock upstream) started with Docker Compose for one test file. The stack
// has its own compose project and loopback ports, and its secrets live in a
// generated env file in a temporary directory: nothing is written into the
// repository, and `stop()` leaves no container, network, or file behind.
//
// The project and the directory are named `piship-reftest-<pid>-...` like
// those of tests/enterprise-reference/stack.ts: a run never touches another
// run's stack, the process's exit and Ctrl-C stop its own, and the suite's
// global setup removes what a killed run left.

export const referenceDirectory = fileURLToPath(
  new URL("../../", import.meta.url),
);
const composeFile = join(referenceDirectory, "compose.yaml");

// Beside the stack's own defaults (18xxx), so a developer's running copy and
// this one do not collide. Each port can be set in the environment.
const DEFAULT_PORTS = {
  KEYCLOAK_PORT: 38080,
  LITELLM_PORT: 34000,
  MOCK_UPSTREAM_PORT: 38090,
  POSTGRES_PORT: 35432,
  BROKER_PORT: 38070,
} as const;

export type ReferenceUser = "alice" | "bob";

export interface Stack {
  readonly project: string;
  readonly ports: Readonly<Record<keyof typeof DEFAULT_PORTS, number>>;
  readonly issuer: string;
  readonly brokerUrl: string;
  readonly revokeUrl: string;
  readonly gatewayUrl: string;
  /** The runtime variables the AcmeCode reference distribution reads. */
  readonly variables: Readonly<Record<string, string>>;
  /** A fixture user's password. Use it for the sign-in form only. */
  password(user: ReferenceUser): string;
  /** LiteLLM's admin key. Only admin calls that inspect or delete keys. */
  masterKey(): string;
  /**
   * Stop the stack and remove its env file. Throws when a step failed, after
   * the others ran; call it again to retry what is left. Once it has
   * succeeded, calling it again does nothing.
   */
  stop(): void;
}

function parseEnv(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (match?.[1] !== undefined) values[match[1]] = match[2] ?? "";
  }
  return values;
}

function docker(
  project: string,
  envFile: string,
  environment: Record<string, string>,
  args: readonly string[],
  files: readonly string[] = [composeFile],
) {
  // Compose prefers the shell over the env file, so a variable of the same
  // name in the developer's shell must not replace a generated value.
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(environment)) delete env[name];
  return spawnSync(
    "docker",
    [
      "compose",
      "-p",
      project,
      "--env-file",
      envFile,
      ...files.flatMap((file) => ["-f", file]),
      ...args,
    ],
    { env, encoding: "utf8" },
  );
}

export interface StackOptions {
  /**
   * Compose files applied on top of compose.yaml, relative to the reference
   * directory, such as compose.live-provider.yaml.
   */
  readonly overrides?: readonly string[];
}

/**
 * Generate the env file, start the stack, and return once every service is
 * healthy (`docker compose up --wait`, no sleeps).
 */
export async function startStack(options: StackOptions = {}): Promise<Stack> {
  const files = [
    composeFile,
    ...(options.overrides ?? []).map((file) => join(referenceDirectory, file)),
  ];
  const project = `${PROJECT_PREFIX}${process.pid}-distribution-${randomBytes(3).toString("hex")}`;
  const ports = Object.fromEntries(
    Object.entries(DEFAULT_PORTS).map(([name, fallback]) => [
      name,
      Number(process.env[name] ?? fallback),
    ]),
  ) as Stack["ports"];
  const directory = mkdtempSync(
    join(tmpdir(), `${PROJECT_PREFIX}${process.pid}-`),
  );
  const envFile = join(directory, ".env");
  const generated = spawnSync(
    process.execPath,
    [join(referenceDirectory, "scripts", "generate-env.mjs"), "--out", envFile],
    {
      env: {
        ...process.env,
        ...Object.fromEntries(
          Object.entries(ports).map(([name, port]) => [name, String(port)]),
        ),
      },
      encoding: "utf8",
    },
  );
  if (generated.status !== 0) {
    rmSync(directory, { recursive: true, force: true });
    throw new Error(`generate-env failed: ${generated.stderr}`);
  }
  chmodSync(envFile, 0o600);
  if (statSync(envFile).mode & 0o077)
    throw new Error("the generated env file is not owner-only");
  const environment = parseEnv(readFileSync(envFile, "utf8"));

  const compose = (args: readonly string[]) =>
    docker(project, envFile, environment, args, files);
  // The worker's exit, Ctrl-C, or termination between start and afterAll still
  // stops the stack, and a stop that failed can be called again (see
  // teardown.ts).
  const stop = registerTeardown({
    project,
    envFile,
    directory,
    compose,
    // No `-v`: the stack keeps no volume, and a volume is never pruned here.
    downArguments: ["down", "--timeout", "10"],
  });
  const up = compose(["up", "--wait", "--wait-timeout", "300"]);
  if (up.status !== 0) {
    const status = compose(["ps", "--all"]);
    try {
      stop();
    } catch {
      // Report the start failure, not the cleanup one.
    }
    throw new Error(
      `docker compose up failed (exit ${up.status}):\n${up.stderr.slice(-2000)}\n${status.stdout}`,
    );
  }

  const base = `http://127.0.0.1:${ports.KEYCLOAK_PORT}`;
  const broker = `http://127.0.0.1:${ports.BROKER_PORT}`;
  const issuer = `${base}/realms/piship-reference`;
  const brokerUrl = `${broker}/v1/credential`;
  const revokeUrl = `${broker}/v1/revoke`;
  const gatewayUrl = `http://127.0.0.1:${ports.LITELLM_PORT}/v1`;
  return {
    project,
    ports,
    issuer,
    brokerUrl,
    revokeUrl,
    gatewayUrl,
    variables: {
      ACMECODE_OIDC_ISSUER: issuer,
      ACMECODE_CREDENTIAL_BROKER_URL: brokerUrl,
      ACMECODE_CREDENTIAL_REVOKE_URL: revokeUrl,
      ACMECODE_LLM_GATEWAY_URL: gatewayUrl,
    },
    password(user) {
      const value = environment[`REFERENCE_${user.toUpperCase()}_PASSWORD`];
      if (!value) throw new Error(`no password generated for ${user}`);
      return value;
    },
    masterKey() {
      const value = environment.LITELLM_MASTER_KEY;
      if (!value) throw new Error("no LiteLLM master key generated");
      return value;
    },
    stop,
  };
}
