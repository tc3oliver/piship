// AcmeCode's custom sandbox adapter (`sandbox.provider: custom`): commands
// run in a container of the organization's sandbox service, with the
// developer's project bind-mounted, so the workspace is `shared`: the file
// tools and the shell touch the same files. The service owns isolation;
// PiShip keeps policy, approvals, audit, the approved environment, and the
// timeout and cancellation of every command. An adapter is one file that
// imports nothing but @piship/adapter-sdk and Node built-ins.
//
// The service is `sandbox.endpoint`, and it takes the API key a person stores
// with `<command> sandbox login` (`sandbox.credential: stored`). PiShip
// binds that key to the user and to the endpoint's origin; this adapter
// honors the origin rule too: it sends the key only to an origin it was
// issued for, never to a URL a response names, and never follows a redirect.
import {
  defineSandboxAdapter,
  isPiShipError,
  PiShipError,
  withTimeout,
} from "@piship/adapter-sdk";

const STATUS_TIMEOUT_MS = 10_000;
// Creating a sandbox may pull the image the first time.
const CREATE_TIMEOUT_MS = 180_000;
const DISPOSE_TIMEOUT_MS = 20_000;
const MAX_JSON_BYTES = 65_536;
const MAX_LINE_BYTES = 1_048_576;

function unavailable(message, options = {}) {
  return new PiShipError("SANDBOX_UNAVAILABLE", message, {
    component: "sandbox",
    ...options,
  });
}

function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

/** What a caller of `available()` may be told: never more than a fixed reason. */
function reasonOf(error) {
  if (isPiShipError(error)) {
    if (error.code === "SANDBOX_UNAVAILABLE") return error.message;
    return `the sandbox service is not reachable (${error.code})`;
  }
  return "the sandbox service is unreachable";
}

export default defineSandboxAdapter((context) => {
  const endpoint = context.endpoint;
  // The origins the credential may go to. PiShip passes the ones a stored
  // credential was issued for; without them, only the endpoint's own.
  const origins =
    context.credentialOrigins ?? (endpoint ? [originOf(endpoint)] : []);

  /**
   * One request to the service. The credential is read for this request only
   * and set as the bearer, after checking the URL is on an origin it may go
   * to. A 401 or 403 is reported to PiShip, which marks a stored credential
   * rejected (it never resolves true for one, so nothing is repeated), and
   * fails the call without ever repeating the response's text.
   */
  async function call(method, path, options = {}) {
    if (!endpoint) throw unavailable("sandbox.endpoint is not set");
    const url = new URL(
      path,
      endpoint.endsWith("/") ? endpoint : `${endpoint}/`,
    );
    const headers = {
      accept: "application/json, application/x-ndjson",
      ...(options.body === undefined
        ? {}
        : { "content-type": "application/json" }),
    };
    const secret = await context.credential?.();
    if (secret !== undefined) {
      if (!origins.includes(url.origin))
        throw unavailable(
          "the sandbox credential is not sent to an origin it was not issued for",
        );
      headers.authorization = `Bearer ${secret}`;
    }
    const signal =
      options.timeoutMs === undefined
        ? options.signal
        : withTimeout(options.timeoutMs, options.signal);
    let response;
    try {
      response = await context.fetch(url, {
        method,
        headers,
        redirect: "manual",
        ...(options.body === undefined
          ? {}
          : { body: JSON.stringify(options.body) }),
        ...(signal ? { signal } : {}),
      });
    } catch (error) {
      // PiShip's cancellation passes through as it came, and a network or TLS
      // policy refusal keeps its code. Never build a message from any other
      // transport error: it can quote the Authorization header.
      if (options.signal?.aborted) throw options.signal.reason ?? error;
      if (isPiShipError(error)) throw error;
      throw unavailable("the sandbox service is unreachable", {
        retryable: true,
      });
    }
    if (response.ok) return response;
    await refuse(response);
  }

  /** An answer's text, at most `MAX_JSON_BYTES` of it; the rest is dropped. */
  async function boundedText(response) {
    if (!response.body) return "";
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let text = "";
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
        if (text.length > MAX_JSON_BYTES) {
          await reader.cancel().catch(() => undefined);
          return text.slice(0, MAX_JSON_BYTES + 1);
        }
      }
    } catch {
      throw unavailable("the sandbox service's answer could not be read");
    }
    return text;
  }

  async function refuse(response) {
    if (response.status === 401 || response.status === 403) {
      // Its body may echo the credential: it is never read.
      await response.body?.cancel().catch(() => undefined);
      await context.credentialRejected?.().catch(() => false);
      throw unavailable("the sandbox service refused the sandbox credential", {
        userAction: "Store a new sandbox credential with sandbox login",
      });
    }
    // The service's error code is one lowercase word; take nothing else.
    let code;
    try {
      const found = JSON.parse(await boundedText(response))?.error?.code;
      if (typeof found === "string" && /^[a-z_]{1,40}$/.test(found))
        code = found;
    } catch {
      // not the service's error body
    }
    throw unavailable(
      `the sandbox service refused the request (HTTP ${response.status}${code ? `, ${code}` : ""})`,
      { retryable: response.status === 429 || response.status >= 500 },
    );
  }

  async function json(response) {
    const text = await boundedText(response);
    if (text.length > MAX_JSON_BYTES)
      throw unavailable("the sandbox service's answer is too large");
    try {
      return JSON.parse(text);
    } catch {
      throw unavailable("the sandbox service's answer is not JSON");
    }
  }

  /** Forward a command's output as it arrives; resolve with its exit. */
  async function forward(response, io) {
    if (!response.body)
      throw unavailable("the sandbox service sent no output stream");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let exit;
    const handle = (line) => {
      let record;
      try {
        record = JSON.parse(line);
      } catch {
        throw unavailable("the sandbox service sent an unreadable answer");
      }
      if (record?.stream === "stdout" || record?.stream === "stderr") {
        const chunk = Buffer.from(String(record.data ?? ""), "base64");
        if (record.stream === "stdout") io.onStdout(chunk);
        else io.onStderr(chunk);
      } else if ("exit" in Object(record)) {
        exit = {
          exitCode: Number.isInteger(record.exit) ? record.exit : null,
          signal: typeof record.signal === "string" ? record.signal : null,
        };
      }
    };
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        for (
          let end = buffer.indexOf("\n");
          end >= 0;
          end = buffer.indexOf("\n")
        ) {
          handle(buffer.slice(0, end));
          buffer = buffer.slice(end + 1);
        }
        if (buffer.length > MAX_LINE_BYTES)
          throw unavailable("the sandbox service sent an oversized answer");
      }
    } catch (error) {
      if (io.signal.aborted) throw io.signal.reason ?? error;
      if (isPiShipError(error)) throw error;
      throw unavailable("the connection to the sandbox service was lost", {
        retryable: true,
      });
    }
    if (exit === undefined)
      throw unavailable(
        "the sandbox service ended the connection before the command finished",
      );
    return exit;
  }

  return {
    id: "acme-container",
    async available() {
      if (!endpoint)
        return { available: false, reason: "sandbox.endpoint is not set" };
      try {
        const status = await json(
          await call("GET", "v1/status", { timeoutMs: STATUS_TIMEOUT_MS }),
        );
        return status?.runtime === "ok"
          ? { available: true }
          : {
              available: false,
              reason: "the sandbox service cannot reach its container runtime",
            };
      } catch (error) {
        return { available: false, reason: reasonOf(error) };
      }
    },
    // Claim only what the service enforces. Each command runs in a container
    // that sees this host's files only through the workspace mount and has
    // its `.git` read-only, so it claims workspace-confinement and
    // git-control-protection, and never host-filesystem-isolation (the
    // workspace is reachable) or the filesystem-* planes (PiShip's path
    // rules are not applied inside the container). `network: deny` is a
    // container with no network at all.
    capabilities() {
      return {
        isolation: "remote",
        planes: [
          "workspace-confinement",
          "git-control-protection",
          "network-deny",
          "environment-filter",
        ],
        network: ["deny", "allow"],
        localProcesses: false,
        workspace: { mode: "shared" },
      };
    },
    async prepare(request) {
      // Never repeated on failure: a second create could leave two sandboxes.
      const { profile } = request;
      const created = await json(
        await call("POST", "v1/sandboxes", {
          body: {
            workspace: profile.workspace,
            network: profile.network,
            writeProtect: {
              files: profile.writeProtect.files,
              directories: profile.writeProtect.directories,
            },
          },
          timeoutMs: CREATE_TIMEOUT_MS,
          ...(request.signal ? { signal: request.signal } : {}),
        }),
      );
      if (
        typeof created?.id !== "string" ||
        !/^sbx_[0-9a-f]{24}$/.test(created.id)
      )
        throw unavailable("the sandbox service answered without a sandbox");
      const path = `v1/sandboxes/${created.id}`;
      let disposed = false;
      return {
        async exec(command, io) {
          if (disposed) throw unavailable("the sandbox was disposed");
          if (command.workspacePath === undefined)
            throw unavailable("the command runs outside the workspace");
          // io.signal is PiShip's timeout and cancellation: the service stops
          // the command when this connection ends.
          const response = await call("POST", `${path}/exec`, {
            body: {
              command: command.command,
              cwd: command.workspacePath,
              env: command.env,
            },
            signal: io.signal,
          });
          return forward(response, io);
        },
        async dispose() {
          // Called once and must not throw.
          if (disposed) return;
          disposed = true;
          await call("DELETE", path, { timeoutMs: DISPOSE_TIMEOUT_MS }).catch(
            () => undefined,
          );
        },
      };
    },
  };
});
