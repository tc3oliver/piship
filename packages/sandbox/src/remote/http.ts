// Shared plumbing for remote sandbox backends: bounded JSON over a managed
// fetch, and the rules for what a remote backend is sent.
import { type ManagedFetch, redact } from "@piship/contracts";

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
  /** Directory in the remote environment that maps to the workspace. */
  readonly workdir?: string;
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

/** Read a JSON object body of at most 1 MiB. */
export async function readJson(
  response: Response,
): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES)
    throw new Error("the response is too large");
  const value = JSON.parse(text) as unknown;
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
