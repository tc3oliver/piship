// A mock Kubernetes Agent Sandbox cluster: the claims API and the router on
// one loopback server. Test-only: this directory is excluded from the package
// build and never reaches `dist`.
import { SANDBOX_READY_MARKER } from "../activate.js";
import { checkAnswer, type MockServer, serve } from "./mock-server.js";

export const CLAIMS =
  "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/agents/sandboxclaims";

/** Cluster behavior a test can change while the mock runs. */
export interface Cluster {
  /** Status for DELETE; 500 simulates an API outage during cleanup. */
  deleteStatus?: number;
  /** Claims the cluster already removed (their shutdownTime passed). */
  expired?: Set<string>;
  /** Claims never report Ready. */
  neverReady?: boolean;
  /** Holds PATCH responses until it resolves. */
  patchGate?: Promise<void>;
  /**
   * The bearer token the API and the router require; a request without it
   * gets 401 with a body that echoes what it was sent.
   */
  token?: string;
}

export async function kubernetesServer(
  execute?: (command: string) => {
    stdout?: string;
    exit_code?: number;
    hang?: boolean;
  },
  cluster: Cluster = {},
): Promise<MockServer> {
  const polls = new Map<string, number>();
  return serve((request, response) => {
    const path = request.path.split("?")[0] ?? "";
    response.setHeader("Content-Type", "application/json");
    if (
      cluster.token !== undefined &&
      request.headers.authorization !== `Bearer ${cluster.token}`
    ) {
      response.statusCode = 401;
      return void response.end(
        JSON.stringify({
          message: `Unauthorized: ${request.headers.authorization ?? "no token"}`,
        }),
      );
    }
    if (request.method === "GET" && path === CLAIMS)
      return void response.end(JSON.stringify({ items: [] }));
    if (request.method === "POST" && path === CLAIMS) {
      response.statusCode = 201;
      return void response.end(request.body);
    }
    if (path.startsWith(`${CLAIMS}/`)) {
      const name = path.slice(CLAIMS.length + 1);
      if (request.method === "DELETE") {
        response.statusCode = cluster.deleteStatus ?? 200;
        return void response.end(
          response.statusCode >= 400 ? '{"message":"etcd unavailable"}' : "{}",
        );
      }
      if (request.method === "PATCH")
        return void (cluster.patchGate ?? Promise.resolve()).then(() => {
          response.statusCode = cluster.expired?.has(name) ? 404 : 200;
          response.end("{}");
        });
      if (request.method === "GET" && cluster.expired?.has(name)) {
        response.statusCode = 404;
        return void response.end("{}");
      }
      const seen = (polls.get(name) ?? 0) + 1;
      polls.set(name, seen);
      return void response.end(
        JSON.stringify({
          status:
            seen < 2 || cluster.neverReady
              ? { conditions: [{ type: "Ready", status: "False" }] }
              : {
                  conditions: [{ type: "Ready", status: "True" }],
                  sandbox: { name: `pool-${name}` },
                },
        }),
      );
    }
    if (request.method === "POST" && path === "/execute") {
      const sandbox = request.headers["x-sandbox-id"];
      if (
        typeof sandbox === "string" &&
        cluster.expired?.has(sandbox.slice(5))
      ) {
        response.statusCode = 404;
        return void response.end("{}");
      }
      const { command } = JSON.parse(request.body.toString()) as {
        command: string;
      };
      if (command.includes(SANDBOX_READY_MARKER))
        return void response.end(
          JSON.stringify({
            stdout: checkAnswer(
              command.includes("'PISHIP_PROBE_UNLISTED=") ? "1" : undefined,
            ),
            stderr: "",
            exit_code: 0,
          }),
        );
      const answer = execute?.(command) ?? { stdout: "", exit_code: 0 };
      if (answer.hang) return;
      return void response.end(JSON.stringify({ stderr: "", ...answer }));
    }
    response.statusCode = 404;
    response.end("{}");
  });
}
