// A mock E2B-compatible service: the control plane and envd on one loopback
// server. Test-only: this directory is excluded from the package build and
// never reaches `dist`.
import type { ServerResponse } from "node:http";
import { SANDBOX_READY_MARKER } from "../activate.js";
import { connectEnvelope, EnvelopeReader } from "../remote/e2b.js";
import { checkAnswer, type MockServer, serve } from "./mock-server.js";

export interface StartRequest {
  process: {
    cmd: string;
    args: string[];
    envs: Record<string, string>;
    cwd: string;
  };
  stdin: boolean;
}

export interface E2bScript {
  health?: number;
  /** The envd user the sandbox accepts; others are refused. Default `user`. */
  user?: string;
  create?: number;
  /**
   * The API key the control plane requires; a request without it gets 401
   * with a body that echoes what it was sent, as some services do.
   */
  apiKey?: string;
  /** Control paths answered 401 once before the key is accepted. */
  rejectOnce?: readonly string[];
  /** Stdout and exit code for a command; `hang` keeps the stream open. */
  command?: (start: StartRequest) => {
    stdout?: string;
    exitCode?: number;
    hang?: boolean;
    streamError?: string;
  };
}

export async function e2bServer(script: E2bScript = {}): Promise<MockServer> {
  const hung = new Set<ServerResponse>();
  const rejectOnce = new Set(script.rejectOnce ?? []);
  return serve((request, response) => {
    const path = request.path.split("?")[0] ?? "";
    if (path === "/health") {
      response.statusCode = script.health ?? 204;
      return void response.end();
    }
    if (path.startsWith("/sandboxes") && script.apiKey !== undefined) {
      const presented = String(request.headers["x-api-key"] ?? "");
      if (presented !== script.apiKey || rejectOnce.delete(path)) {
        response.statusCode = 401;
        response.setHeader("Content-Type", "application/json");
        return void response.end(
          JSON.stringify({ code: 401, message: `invalid key ${presented}` }),
        );
      }
    }
    if (request.method === "POST" && path === "/sandboxes") {
      response.statusCode = script.create ?? 201;
      response.setHeader("Content-Type", "application/json");
      return void response.end(
        script.create && script.create >= 400
          ? JSON.stringify({ code: script.create, message: "no capacity" })
          : JSON.stringify({
              sandboxID: "sbx1",
              templateID: "piship-workspace",
              envdVersion: "0.4.0",
              envdAccessToken: "envd-token-1",
              domain: null,
            }),
      );
    }
    if (path === "/sandboxes/sbx1/timeout" || path === "/sandboxes/sbx1") {
      response.statusCode = 204;
      return void response.end();
    }
    if (path === "/process.Process/SendSignal") {
      for (const open of hung) open.end(connectEnvelope({}, 0x02));
      hung.clear();
      response.setHeader("Content-Type", "application/json");
      return void response.end("{}");
    }
    if (path === "/process.Process/Start") {
      // envd authenticates the process user with HTTP Basic `<user>:`.
      const expected = `Basic ${Buffer.from(`${script.user ?? "user"}:`).toString("base64")}`;
      if (request.headers.authorization !== expected) {
        response.statusCode = 401;
        response.setHeader("Content-Type", "application/json");
        return void response.end(
          '{"code":"unauthenticated","message":"invalid user"}',
        );
      }
      const [frame] = new EnvelopeReader().push(request.body);
      const start = frame?.message as StartRequest;
      const script_ = start.process.args[2] ?? "";
      const answer = script_.includes(SANDBOX_READY_MARKER)
        ? { stdout: checkAnswer(start.process.envs.PISHIP_PROBE_UNLISTED) }
        : (script.command?.(start) ?? { stdout: "", exitCode: 0 });
      response.setHeader("Content-Type", "application/connect+json");
      response.write(connectEnvelope({ event: { start: { pid: 42 } } }));
      if (answer.stdout)
        response.write(
          connectEnvelope({
            event: {
              data: { stdout: Buffer.from(answer.stdout).toString("base64") },
            },
          }),
        );
      if (answer.hang) return void hung.add(response);
      if (answer.streamError)
        return void response.end(
          connectEnvelope(
            { error: { code: "internal", message: answer.streamError } },
            0x02,
          ),
        );
      response.write(
        connectEnvelope({
          event: {
            end: {
              ...(answer.exitCode ? { exitCode: answer.exitCode } : {}),
              exited: true,
              status: `exit status ${answer.exitCode ?? 0}`,
            },
          },
        }),
      );
      return void response.end(connectEnvelope({}, 0x02));
    }
    response.statusCode = 404;
    response.end();
  });
}
