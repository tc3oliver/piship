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
  /** Status of `POST /sandboxes/{id}/snapshots`; default 201 with a new id. */
  snapshot?: number;
  /** Status when a sandbox is created from a snapshot id; default: found, or 404. */
  createFromSnapshot?: number;
  /** The snapshots that exist (ids `snap-1`, `snap-2`, ...), and those deleted. */
  snapshots?: string[];
  deletedSnapshots?: string[];
  /** Set to true once the sandbox has expired: its timeout endpoint answers 404. */
  gone?: boolean;
  /**
   * The API key the control plane requires; a request without it gets 401
   * with a body that echoes what it was sent, as some services do.
   */
  apiKey?: string;
  /** The sandbox's files by absolute path; served and updated over envd. */
  files?: Map<string, Buffer>;
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

/** The content of the one `file` part of a multipart body. */
function multipartFile(
  body: Buffer,
  contentType: string | undefined,
): Buffer | undefined {
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/.exec(contentType ?? "");
  const mark = Buffer.from(`--${boundary?.[1] ?? boundary?.[2] ?? "\0"}`);
  const start = body.indexOf(mark);
  const headerEnd = body.indexOf("\r\n\r\n", start);
  const end = body.indexOf(
    Buffer.concat([Buffer.from("\r\n"), mark]),
    headerEnd,
  );
  if (start < 0 || headerEnd < 0 || end < 0) return undefined;
  return body.subarray(headerEnd + 4, end);
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
    if (
      (path.startsWith("/sandboxes") || path.startsWith("/templates")) &&
      script.apiKey !== undefined
    ) {
      const presented = String(request.headers["x-api-key"] ?? "");
      if (presented !== script.apiKey || rejectOnce.delete(path)) {
        response.statusCode = 401;
        response.setHeader("Content-Type", "application/json");
        return void response.end(
          JSON.stringify({ code: 401, message: `invalid key ${presented}` }),
        );
      }
    }
    script.snapshots ??= [];
    script.deletedSnapshots ??= [];
    if (request.method === "DELETE" && path.startsWith("/templates/")) {
      const id = decodeURIComponent(path.slice("/templates/".length));
      const at = script.snapshots.indexOf(id);
      if (at >= 0) script.snapshots.splice(at, 1);
      script.deletedSnapshots.push(id);
      response.statusCode = at >= 0 ? 204 : 404;
      return void response.end();
    }
    if (request.method === "POST" && path === "/sandboxes/sbx1/snapshots") {
      response.setHeader("Content-Type", "application/json");
      response.statusCode = script.snapshot ?? 201;
      if (response.statusCode >= 400)
        return void response.end(
          JSON.stringify({
            code: response.statusCode,
            message: "no snapshots",
          }),
        );
      const id = `snap-${script.snapshots.length + script.deletedSnapshots.length + 1}`;
      script.snapshots.push(id);
      return void response.end(JSON.stringify({ snapshotID: id, names: [] }));
    }
    if (request.method === "POST" && path === "/sandboxes") {
      const template = (
        JSON.parse(request.body.toString() || "{}") as {
          templateID?: string;
        }
      ).templateID;
      const fromSnapshot = template?.startsWith("snap-") === true;
      const missing =
        fromSnapshot && !script.snapshots.includes(template as string);
      response.statusCode =
        fromSnapshot && (missing || script.createFromSnapshot)
          ? missing
            ? 404
            : (script.createFromSnapshot as number)
          : (script.create ?? 201);
      response.setHeader("Content-Type", "application/json");
      return void response.end(
        response.statusCode >= 400
          ? JSON.stringify({
              code: response.statusCode,
              message: "no capacity",
            })
          : JSON.stringify({
              sandboxID: "sbx1",
              templateID: "piship-workspace",
              envdVersion: "0.4.0",
              envdAccessToken: "envd-token-1",
              domain: null,
            }),
      );
    }
    if (path === "/sandboxes/sbx1/timeout" && script.gone) {
      response.statusCode = 404;
      response.setHeader("Content-Type", "application/json");
      return void response.end('{"code":404,"message":"sandbox not found"}');
    }
    if (path === "/sandboxes/sbx1/timeout" || path === "/sandboxes/sbx1") {
      response.statusCode = 204;
      return void response.end();
    }
    if (path === "/files" || path === "/filesystem.Filesystem/Stat") {
      // envd: access token, Basic `<user>:`, and (for /files) the username.
      const user = script.user ?? "user";
      const expected = `Basic ${Buffer.from(`${user}:`).toString("base64")}`;
      const query = new URLSearchParams(request.path.split("?")[1] ?? "");
      if (
        request.headers["x-access-token"] !== "envd-token-1" ||
        request.headers.authorization !== expected ||
        (path === "/files" && query.get("username") !== user)
      ) {
        response.statusCode = 401;
        return void response.end('{"code":"unauthenticated"}');
      }
      script.files ??= new Map();
      const store = script.files;
      let target = query.get("path");
      if (path !== "/files")
        target =
          (JSON.parse(request.body.toString()) as { path?: string }).path ??
          null;
      if (!target?.startsWith("/home/user/") || target.includes("..")) {
        response.statusCode = 400;
        return void response.end('{"code":"invalid_argument"}');
      }
      if (path === "/files" && request.method === "POST") {
        const content = multipartFile(
          request.body,
          request.headers["content-type"],
        );
        if (!content) {
          response.statusCode = 400;
          return void response.end();
        }
        store.set(target, content);
        response.setHeader("Content-Type", "application/json");
        return void response.end(
          JSON.stringify([{ path: target, type: "file" }]),
        );
      }
      const found = store.get(target);
      const directory = [...store.keys()].some((key) =>
        key.startsWith(`${target}/`),
      );
      if (path === "/files") {
        if (!found) {
          response.statusCode = 404;
          return void response.end('{"code":404,"message":"file not found"}');
        }
        return void response.end(found);
      }
      if (!found && !directory) {
        response.statusCode = 404;
        response.setHeader("Content-Type", "application/json");
        return void response.end(
          '{"code":"not_found","message":"no such file"}',
        );
      }
      response.setHeader("Content-Type", "application/json");
      return void response.end(
        JSON.stringify({
          entry: found
            ? {
                name: "f",
                type: "FILE_TYPE_FILE",
                path: target,
                size: String(found.length),
              }
            : {
                name: "d",
                type: "FILE_TYPE_DIRECTORY",
                path: target,
                size: "4096",
              },
        }),
      );
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
        ? {
            stdout: checkAnswer(start.process.envs.PISHIP_PROBE_UNLISTED),
          }
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
