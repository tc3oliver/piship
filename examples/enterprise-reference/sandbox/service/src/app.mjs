// The HTTP surface. Every request is checked in the same order: the Host
// header (so a page in a browser cannot reach a loopback service through a
// name it controls), the route, the credential, and only then the body.
// Answers are JSON with `cache-control: no-store`; an error names a fixed code
// and message and never repeats what the caller sent.
import { authenticate } from "./auth.mjs";
import { parseCreate, parseExec, SandboxError } from "./sandboxes.mjs";

const MAX_BODY_BYTES = 512 * 1024;

const ROUTES = [
  { method: "GET", pattern: /^\/health$/, name: "health", public: true },
  { method: "GET", pattern: /^\/v1\/status$/, name: "status" },
  { method: "POST", pattern: /^\/v1\/sandboxes$/, name: "create" },
  {
    method: "DELETE",
    pattern: /^\/v1\/sandboxes\/([A-Za-z0-9_]{1,40})$/,
    name: "delete",
  },
  {
    method: "POST",
    pattern: /^\/v1\/sandboxes\/([A-Za-z0-9_]{1,40})\/exec$/,
    name: "exec",
  },
];

function send(res, status, body, headers = {}) {
  if (res.headersSent || res.destroyed) return;
  const text = body === undefined ? "" : JSON.stringify(body);
  res.writeHead(status, {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...(body === undefined
      ? {}
      : {
          "content-type": "application/json; charset=utf-8",
          "content-length": Buffer.byteLength(text),
        }),
    ...headers,
  });
  res.end(text);
}

function fail(res, error) {
  send(
    res,
    error.status,
    { error: { code: error.code, message: error.message } },
    error.headers,
  );
}

async function readJson(req) {
  const type = req.headers["content-type"] ?? "";
  if (!/^application\/json\s*(?:;|$)/i.test(type))
    throw new SandboxError(
      415,
      "unsupported_media_type",
      "The body must be application/json",
    );
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES)
      throw new SandboxError(413, "too_large", "The request is too large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new SandboxError(400, "bad_request", "The body is not valid JSON");
  }
}

/** Stream one command's output as newline-delimited JSON, ending with its exit. */
async function stream(res, exec, config, sandboxes) {
  let bytes = 0;
  let paused = false;
  const write = (record) => {
    if (res.destroyed || res.writableEnded) return;
    if (!res.write(`${JSON.stringify(record)}\n`) && !paused) {
      paused = true;
      exec.child.stdout.pause();
      exec.child.stderr.pause();
      res.once("drain", () => {
        paused = false;
        exec.child.stdout.resume();
        exec.child.stderr.resume();
      });
    }
  };
  for (const name of ["stdout", "stderr"]) {
    exec.child[name].on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > config.maxOutputBytes) {
        void sandboxes.cancelExec(exec, "output-limit");
        return;
      }
      write({ stream: name, data: chunk.toString("base64") });
    });
  }
  const result = await exec.done;
  write({
    exit: result.exit,
    signal: result.signal,
    ...(result.reason === "output-limit" ? { truncated: true } : {}),
  });
  res.end();
  return result;
}

/**
 * @param {object} deps
 * @param {ReturnType<import("./config.mjs").loadConfig>} deps.config
 * @param {ReturnType<import("./auth.mjs").loadRegistry>} deps.keys
 * @param {import("./sandboxes.mjs").Sandboxes} deps.sandboxes
 * @param {ReturnType<import("./log.mjs").createLogger>} deps.log
 */
export function createApp({ config, keys, sandboxes, log }) {
  return async function handle(req, res) {
    const started = Date.now();
    let route = "unmatched";
    let owner;
    res.once("close", () => {
      if (route === "exec" && res.statusCode === 200) return;
      log("request", {
        route,
        status: res.statusCode,
        ...(owner ? { owner } : {}),
        duration_ms: Date.now() - started,
      });
    });
    try {
      const host = String(req.headers.host ?? "").toLowerCase();
      if (!config.allowedHosts.has(host))
        throw new SandboxError(
          421,
          "misdirected_request",
          "This service does not answer for that host name",
        );
      const path = (req.url ?? "").split("?")[0] ?? "";
      let matched;
      let match;
      for (const candidate of ROUTES) {
        const found = candidate.pattern.exec(path);
        if (found && candidate.method === req.method) {
          matched = candidate;
          match = found;
          break;
        }
      }
      if (!matched)
        throw new SandboxError(404, "not_found", "There is no such route");
      route = matched.name;
      // The instance name says which service answered: a caller that started
      // one (a test, a supervisor) can tell its own from another on the port.
      if (matched.public)
        return send(res, 200, { status: "ok", instance: config.instance });
      const user = authenticate(keys, req.headers.authorization);
      if (user === undefined)
        throw new SandboxError(
          401,
          "unauthorized",
          "A valid sandbox credential is required",
          { "www-authenticate": "Bearer" },
        );
      owner = user.id;
      const id = match?.[1] ?? "";
      switch (matched.name) {
        case "status":
          return send(res, 200, await sandboxes.status(owner));
        case "create": {
          const created = await sandboxes.create(
            user,
            parseCreate(await readJson(req)),
          );
          return send(res, 201, created);
        }
        case "delete":
          await sandboxes.remove(owner, id);
          return send(res, 204);
        case "exec": {
          const request = parseExec(await readJson(req));
          const exec = await sandboxes.startExec(owner, id, request);
          // The caller going away, by cancellation, timeout, or a crash,
          // is what stops the command: this is the only cancel signal. One
          // that went while the command waited to start is cancelled now.
          res.once("close", () => {
            if (!res.writableFinished)
              void sandboxes.cancelExec(exec, "disconnected");
          });
          if (res.destroyed) void sandboxes.cancelExec(exec, "disconnected");
          try {
            await exec.spawned;
          } catch {
            await exec.done;
            throw new SandboxError(
              503,
              "runtime_unavailable",
              "The container runtime is not available",
            );
          }
          if (res.destroyed) {
            // The caller is gone and its cancel is under way: read what the
            // dying command wrote, so the pipes close and the command ends.
            exec.child.stdout.resume();
            exec.child.stderr.resume();
            return;
          }
          res.writeHead(200, {
            "content-type": "application/x-ndjson; charset=utf-8",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
          });
          res.flushHeaders();
          const result = await stream(res, exec, config, sandboxes);
          log("request", {
            route,
            status: 200,
            owner,
            session: id,
            ...(typeof result.exit === "number" ? { exit: result.exit } : {}),
            ...(result.reason ? { reason: result.reason } : {}),
            duration_ms: Date.now() - started,
          });
          return;
        }
      }
    } catch (error) {
      if (error instanceof SandboxError) return fail(res, error);
      log("request.error", { route, reason: "internal" });
      send(res, 500, {
        error: { code: "internal_error", message: "The service failed" },
      });
    }
  };
}
