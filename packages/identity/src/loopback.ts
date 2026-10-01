import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { PiShipError } from "@piship/contracts";

export interface LoopbackReceiver {
  /** Exact redirect URI including the bound port. */
  readonly redirectUri: string;
  /** Resolves with the full callback URL (code/state/error parameters). */
  readonly callback: Promise<URL>;
  close(): Promise<void>;
}

/** How long a login waits for the browser to return to the redirect. */
export const DEFAULT_LOGIN_TIMEOUT_MS = 300_000;

const PAGE = (message: string) =>
  `<!doctype html><meta charset="utf-8"><title>Sign-in</title><p>${message}</p>`;

/**
 * The registered redirect cannot be bound. That is a local resource the login
 * needs, not a missing identity: name the port and how to free it.
 */
function listenError(base: URL, error: Error): PiShipError {
  const code = (error as NodeJS.ErrnoException).code;
  const port = base.port;
  if (code === "EADDRINUSE") {
    const find =
      process.platform === "win32"
        ? `netstat -ano | findstr :${port}`
        : `lsof -nP -iTCP:${port} -sTCP:LISTEN`;
    return new PiShipError(
      "CONFIG_UNAVAILABLE",
      `Cannot listen on the registered redirect ${base.host}: port ${port} is already in use`,
      {
        component: "identity",
        userAction: `Another login may still be running: finish or cancel it (Ctrl-C), then try again. Otherwise find the process holding port ${port} (\`${find}\`) and stop it, or ask your administrator to register another loopback redirect port`,
      },
    );
  }
  return new PiShipError(
    "CONFIG_UNAVAILABLE",
    `Cannot listen on the registered redirect ${base.host}: ${code ?? error.message}`,
    {
      component: "identity",
      userAction:
        "Check that the loopback address and port of the registered redirect can be used on this machine",
    },
  );
}

/** An OAuth error code is printed only when it looks like one (RFC 6749 A.7). */
const ERROR_CODE = /^[a-z_]{1,64}$/;

/**
 * Listen on the registered loopback redirect (RFC 8252 section 7.3). Only the
 * registered path is answered and the listener closes on completion, timeout,
 * or cancellation. With `state`, only a callback carrying that state completes
 * the sign-in: any other request (another path, a favicon, a stale tab of an
 * earlier login, a forged or stateless callback) is answered and refused, and
 * the sign-in keeps waiting, so a stray request cannot end it. The first
 * matching callback wins. What was refused is named in the timeout.
 */
export async function startLoopbackReceiver(
  registered: string,
  options: { signal?: AbortSignal; timeoutMs?: number; state?: string } = {},
): Promise<LoopbackReceiver> {
  const base = new URL(registered);
  const host = base.hostname.replace(/^\[|\]$/g, "");
  let settle: { resolve(url: URL): void; reject(error: unknown): void };
  const callback = new Promise<URL>((resolve, reject) => {
    settle = { resolve, reject };
  });
  callback.catch(() => {});
  let done = false;
  let refused = 0;
  let providerError: string | undefined;
  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", redirectUri);
    if (request.method !== "GET" || url.pathname !== base.pathname || done) {
      response
        .writeHead(404, { "content-type": "text/plain" })
        .end("Not found");
      return;
    }
    const html = {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    };
    if (
      options.state !== undefined &&
      url.searchParams.get("state") !== options.state
    ) {
      refused++;
      const error = url.searchParams.get("error") ?? "";
      if (ERROR_CODE.test(error)) providerError = error;
      response
        .writeHead(400, html)
        .end(
          PAGE(
            "This response does not belong to the sign-in in progress and was ignored. Complete sign-in from the link the terminal printed, or press Ctrl-C there to cancel.",
          ),
        );
      return;
    }
    done = true;
    const failed = url.searchParams.has("error");
    response
      .writeHead(failed ? 400 : 200, html)
      .end(
        PAGE(
          failed
            ? "Sign-in was not completed. You can close this window."
            : "Sign-in received. You can close this window and return to the terminal.",
        ),
      );
    settle.resolve(url);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", (error) => reject(listenError(base, error)));
    server.listen(Number(base.port || 0), host, () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  const bound = new URL(base.toString());
  bound.port = String(port);
  const redirectUri = bound.toString();
  const close = () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections?.();
      server.close(() => resolve());
    });
  // What the listener refused is named when the sign-in ends without a
  // matching callback: a provider error there is the likely reason.
  const ended = (how: string, retry: string) => {
    if (!refused)
      return new PiShipError("IDENTITY_REQUIRED", `Sign-in ${how}`, {
        ...(retry ? { userAction: retry } : {}),
        component: "identity",
      });
    const reported = providerError
      ? ` (the identity provider reported ${providerError})`
      : "";
    return new PiShipError(
      "IDENTITY_REQUIRED",
      `Sign-in ${how}; refused ${refused} callback${refused > 1 ? "s" : ""} without this sign-in's state${reported}`,
      {
        userAction: providerError
          ? "Check the configured client ID and its registered redirect URI with your administrator, then run login again"
          : "Run login again and complete sign-in from the link it prints; a browser tab of an earlier login cannot complete it",
        component: "identity",
      },
    );
  };
  const timeout = setTimeout(
    () =>
      settle.reject(
        ended(
          "timed out",
          "Run login again and complete sign-in in the browser",
        ),
      ),
    options.timeoutMs ?? DEFAULT_LOGIN_TIMEOUT_MS,
  );
  timeout.unref();
  const abort = () => settle.reject(ended("was cancelled", ""));
  if (options.signal?.aborted) abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  callback
    .finally(() => {
      done = true;
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abort);
    })
    .catch(() => {});
  return { redirectUri, callback, close };
}
