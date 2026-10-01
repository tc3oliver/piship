import { appendFileSync } from "node:fs";
import type { ComposeResult } from "./teardown.js";

// The host ports of a test stack. Shared by both stack helpers
// (tests/enterprise-reference/stack.ts and ./stack.ts).
//
// The generated env file asks for port 0 everywhere, so Docker binds a free
// port on 127.0.0.1 as each container starts, and `docker compose port` reads
// it back. Two runs on one host never ask for the same port, and no port is
// picked, released, and bound again later, which another process could win.
//
// Keycloak takes its issuer's port from the request (compose.yaml), so it
// needs to know nothing in advance. The broker does: it checks the issuer and
// returns LiteLLM's URL. So the stack starts in two steps, Keycloak and
// LiteLLM (and what they depend on) first, then the rest, with the two ports
// Docker chose written to the env file in between. Their configuration does
// not read those variables, so the second step leaves them running as they
// are.
//
// A container that is stopped and started again gets a new port: re-read the
// ports after starting a service again.

/** Each port variable of compose.yaml: the service and its container port. */
export const SERVICE_PORTS = {
  KEYCLOAK_PORT: ["keycloak", 8080],
  LITELLM_PORT: ["litellm", 4000],
  MOCK_UPSTREAM_PORT: ["mock-upstream", 8080],
  POSTGRES_PORT: ["postgres", 5432],
  BROKER_PORT: ["broker", 8080],
} as const;

export type PortName = keyof typeof SERVICE_PORTS;
export type StackPorts = Record<PortName, number>;

/** The port variables for generate-env.mjs: 0 each, for Docker to choose. */
export const EPHEMERAL_PORTS = Object.fromEntries(
  Object.keys(SERVICE_PORTS).map((name) => [name, "0"]),
) as Record<PortName, string>;

const detail = (result: ComposeResult) =>
  (result.stderr ?? "").trim() ||
  result.error?.message ||
  `exit status ${result.status}`;

/** The host port Docker published for one port variable. */
export function publishedPort(
  compose: (args: readonly string[]) => ComposeResult,
  name: PortName,
): number {
  const [service, port] = SERVICE_PORTS[name];
  const result = compose(["port", service, String(port)]);
  // Loopback only, as compose.yaml publishes every port.
  const match = /^127\.0\.0\.1:(\d+)$/.exec((result.stdout ?? "").trim());
  if (result.status !== 0 || !match?.[1])
    throw new Error(
      `docker compose port ${service} ${port} found no loopback port: ${detail(result)} ${result.stdout ?? ""}`.trim(),
    );
  return Number(match[1]);
}

/** Every host port of a running stack. */
export function publishedPorts(
  compose: (args: readonly string[]) => ComposeResult,
): StackPorts {
  return Object.fromEntries(
    Object.keys(SERVICE_PORTS).map((name) => [
      name,
      publishedPort(compose, name as PortName),
    ]),
  ) as StackPorts;
}

/**
 * Start the stack whose env file asks for port 0 everywhere, in the two steps
 * above. `up` is the `up` command with its options. Returns the result of the
 * step that failed, or of the last one.
 */
export function startWithPublishedPorts(
  compose: (args: readonly string[]) => ComposeResult,
  envFile: string,
  up: readonly string[],
): ComposeResult {
  const first = compose([...up, "keycloak", "litellm"]);
  if (first.status !== 0) return first;
  try {
    appendFileSync(
      envFile,
      `KEYCLOAK_PUBLISHED_PORT=${publishedPort(compose, "KEYCLOAK_PORT")}\nLITELLM_PUBLISHED_PORT=${publishedPort(compose, "LITELLM_PORT")}\n`,
    );
  } catch (error) {
    return {
      status: 1,
      stderr: error instanceof Error ? error.message : String(error),
    };
  }
  return compose(up);
}
