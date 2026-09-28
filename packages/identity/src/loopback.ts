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

const PAGE = (message: string) =>
  `<!doctype html><meta charset="utf-8"><title>Sign-in</title><p>${message}</p>`;

/**
 * Listen on the registered loopback redirect (RFC 8252 section 7.3). Only the
 * registered path is answered, the first callback wins, and the listener
 * closes on completion, timeout, or cancellation.
 */
export async function startLoopbackReceiver(
  registered: string,
  options: { signal?: AbortSignal; timeoutMs?: number } = {},
): Promise<LoopbackReceiver> {
  const base = new URL(registered);
  const host = base.hostname.replace(/^\[|\]$/g, "");
  let settle: { resolve(url: URL): void; reject(error: unknown): void };
  const callback = new Promise<URL>((resolve, reject) => {
    settle = { resolve, reject };
  });
  callback.catch(() => {});
  let done = false;
  const server: Server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", redirectUri);
    if (request.method !== "GET" || url.pathname !== base.pathname || done) {
      response
        .writeHead(404, { "content-type": "text/plain" })
        .end("Not found");
      return;
    }
    done = true;
    const failed = url.searchParams.has("error");
    response
      .writeHead(failed ? 400 : 200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      })
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
    server.once("error", (error) =>
      reject(
        new PiShipError(
          "IDENTITY_REQUIRED",
          `Cannot listen on the registered redirect ${base.host}: ${(error as NodeJS.ErrnoException).code ?? error.message}`,
          { component: "identity" },
        ),
      ),
    );
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
  const timeout = setTimeout(
    () =>
      settle.reject(
        new PiShipError("IDENTITY_REQUIRED", "Sign-in timed out", {
          userAction: "Run login again and complete sign-in in the browser",
          component: "identity",
        }),
      ),
    options.timeoutMs ?? 300_000,
  );
  timeout.unref();
  const abort = () =>
    settle.reject(
      new PiShipError("IDENTITY_REQUIRED", "Sign-in was cancelled", {
        component: "identity",
      }),
    );
  if (options.signal?.aborted) abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  callback
    .finally(() => {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abort);
    })
    .catch(() => {});
  return { redirectUri, callback, close };
}
