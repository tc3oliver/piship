// Shared plumbing for remote sandbox backends: bounded JSON over a managed
// fetch, and the rules for what a remote backend is sent.
import { type ManagedFetch, redact, SecretValue } from "@piship/contracts";

export interface RemoteBackendOptions {
  /** The backend's control endpoint (resolved; no runtime references). */
  readonly endpoint: string;
  /** PiShip's managed fetch: proxy, CA, and private-only policy applied. */
  readonly fetch: ManagedFetch;
  /**
   * The credential for the control endpoint, when the distribution declares
   * one. PiShip decides whether it may be sent before passing it here.
   */
  readonly credential?: () => Promise<string | undefined>;
  /**
   * Called when an origin the credential was sent to answers 401: the
   * credential was not accepted. A 403 (authenticated, but not allowed, such
   * as Kubernetes RBAC) is returned to the caller and rejects nothing.
   * Resolves true when a renewed credential is ready: the backend then
   * repeats that one request once, unless the request may have created
   * something (a sandbox, a claim, or a command).
   */
  readonly credentialRejected?: () => Promise<boolean>;
  /** Directory in the remote environment that maps to the workspace. */
  readonly workdir?: string;
}

// Only an authentication failure rejects the credential. A 403 means the
// credential was accepted and a policy denied the request; replacing the
// credential cannot fix that, and marking it rejected would discard it.
const rejectedStatus = (status: number) => status === 401;

/**
 * One request that carries the backend's credential, when it has one, in the
 * header `header` builds. A 401 to a request that carried it is
 * reported through `credentialRejected`; a repeatable request is sent once
 * more with the renewed credential, a second rejection is reported again
 * and returned. The credential is read per request, never kept here.
 */
export async function credentialedFetch(
  options: Pick<
    RemoteBackendOptions,
    "fetch" | "credential" | "credentialRejected"
  >,
  url: string | URL,
  init: RequestInit,
  header: (credential: string) => readonly [string, string],
  repeatable: boolean,
  /** Zero for a command data-plane request whose lifetime is caller governed. */
  timeoutMs = 30_000,
): Promise<Response> {
  const send = async () => {
    const headers = new Headers(init.headers);
    const credential = await options.credential?.();
    if (credential) {
      // Registered for redaction, whatever its source: a failure body that
      // echoes it (some services answer 401 with the key they were sent)
      // is scrubbed from every later error.
      new SecretValue(credential);
      headers.set(...header(credential));
    }
    const deadline = timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined;
    const signal =
      deadline && init.signal
        ? AbortSignal.any([init.signal, deadline])
        : (deadline ?? init.signal);
    const response = await options.fetch(url, {
      ...init,
      headers,
      signal: signal ?? null,
    });
    return { response, sent: !!credential };
  };
  const first = await send();
  const rejected = options.credentialRejected;
  if (!first.sent || !rejectedStatus(first.response.status) || !rejected)
    return first.response;
  const renewed = await rejected().catch(() => false);
  if (!renewed || !repeatable) return first.response;
  await first.response.body?.cancel().catch(() => undefined);
  const second = await send();
  if (second.sent && rejectedStatus(second.response.status))
    await rejected().catch(() => false);
  return second.response;
}

const MAX_RESPONSE_BYTES = 1024 * 1024;

export function trimSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") end--;
  return value.slice(0, end);
}

/** A redacted, bounded one-line description of a failed response. */
export async function describeFailure(response: Response): Promise<string> {
  let text = "";
  try {
    text = (await response.text()).slice(0, 300);
  } catch {
    // body unavailable
  }
  const detail = redact(text.replace(/\s+/g, " ").trim());
  return `HTTP ${response.status}${detail ? `: ${detail}` : ""}`;
}

/** Read a JSON object body, stopping as soon as it exceeds `maxBytes`. */
export async function readJson(
  response: Response,
  maxBytes = MAX_RESPONSE_BYTES,
): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  if (response.body)
    for await (const chunk of response.body as AsyncIterable<Uint8Array>) {
      size += chunk.byteLength;
      if (size > maxBytes) {
        await response.body.cancel().catch(() => undefined);
        throw new Error("the response is too large");
      }
      chunks.push(Buffer.from(chunk));
    }
  const value = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("the response is not a JSON object");
  return value as Record<string, unknown>;
}

/** Map a workspace-relative path onto the remote working directory. */
export function remoteDirectory(
  workdir: string,
  workspacePath: string | undefined,
): string {
  const base = workdir === "/" ? "" : trimSlashes(workdir);
  if (!workspacePath || workspacePath === ".") return workdir;
  if (
    workspacePath.startsWith("/") ||
    workspacePath.split("/").some((segment) => segment === "..")
  )
    throw new Error("the working directory is outside the workspace");
  return `${base}/${workspacePath}`;
}

/** Quote a value for a POSIX shell. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function errorText(error: unknown): string {
  return redact(String((error as Error)?.message ?? error)).slice(0, 300);
}
