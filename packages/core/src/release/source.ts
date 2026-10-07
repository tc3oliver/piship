// Update sources: validating a directory or URL source and reading channel
// files and release archives from it with size and time limits.
import { createHash } from "node:crypto";
import { cpSync, existsSync, readFileSync, statSync } from "node:fs";
import { basename, isAbsolute, join, resolve } from "node:path";
import { PiShipError, parseRetryAfter, redact } from "@piship/contracts";
import {
  PRIVATE_UPDATE_HOSTS,
  plainHttpUpdateAllowed,
  type UpdateTransport,
} from "@piship/schema";
import { sha256File } from "../archive.js";
import type { ChannelRelease } from "./channel.js";

/** Channel metadata and signatures are small; anything larger is refused. */
const MAX_METADATA_BYTES = 1024 * 1024;
const METADATA_TIMEOUT_MS = 30_000;
const ARCHIVE_TIMEOUT_MS = 30 * 60_000;
/** An archive stream that delivers nothing for this long is treated as dropped. */
const ARCHIVE_IDLE_TIMEOUT_MS = 60_000;

function tooLarge(name: string, limit: number): PiShipError {
  return new PiShipError(
    "INTEGRITY_FAILED",
    `${name} from the update source exceeds ${limit} bytes`,
    {
      userAction:
        "Do not install it; report the update source to the distribution owner",
    },
  );
}

/**
 * Stream a response body into `destination`, stopping past `limit` bytes.
 * Returns the SHA-256 of what was written, computed while it streamed.
 *
 * A body that stops early (a connection dropped by sleep or a network
 * change, a stalled stream, a server that closes before the signed size) is
 * a retryable interruption, not an integrity failure: only a body of the
 * full length is judged by its digest.
 */
async function saveBody(
  response: Response,
  destination: string,
  name: string,
  limit: number,
  idleMs: number,
): Promise<string> {
  const { Readable, Transform } = await import("node:stream");
  const { pipeline } = await import("node:stream/promises");
  const { createWriteStream } = await import("node:fs");
  const digest = createHash("sha256");
  let received = 0;
  const idle = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const rearm = () => {
    clearTimeout(timer);
    timer = setTimeout(() => idle.abort(), idleMs);
  };
  const interrupted = (reason: string): PiShipError =>
    new PiShipError(
      "UPDATE_FAILED",
      `Downloading ${name} was interrupted ${reason}`,
      {
        retryable: true,
        userAction:
          "Run update again; if it keeps stopping at the same size, report the update source",
      },
    );
  rearm();
  try {
    await pipeline(
      Readable.fromWeb(response.body as never),
      new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          rearm();
          received += chunk.length;
          digest.update(chunk);
          callback(received > limit ? tooLarge(name, limit) : null, chunk);
        },
      }),
      createWriteStream(destination, { flags: "wx" }),
      { signal: idle.signal },
    );
  } catch (error) {
    if (error instanceof PiShipError) throw error;
    const failure = error as NodeJS.ErrnoException;
    if (idle.signal.aborted)
      throw interrupted(
        `after ${received} bytes: the update source sent nothing for ${idleMs / 1000} s`,
      );
    if (["TimeoutError", "AbortError"].includes(failure.name))
      throw new PiShipError(
        "UPDATE_FAILED",
        `Update source stopped sending ${name} before the deadline`,
        { retryable: true },
      );
    // A local failure writing the file (a full disk) is not the network's.
    if (failure.syscall !== undefined && failure.code !== undefined)
      throw error;
    throw interrupted(
      `after ${received} bytes (${failure.cause instanceof Error ? failure.cause.message : failure.message})`,
    );
  } finally {
    clearTimeout(timer);
  }
  if (received < limit)
    throw interrupted(`after ${received} of ${limit} bytes`);
  return digest.digest("hex");
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 5;

/**
 * GET `url` from the update source. A redirect is followed only within the
 * source's origin (same scheme, host, and port), at most five times: another
 * origin is never contacted, because only the declared source host is let
 * through a private-only network and the channel's trust is pinned to it.
 * An https source is never redirected to plain HTTP.
 */
async function fetchSource(
  url: URL,
  name: string,
  fetcher: typeof fetch,
  timeout: number,
  transport: UpdateTransport | undefined,
): Promise<Response>;
async function fetchSource(
  url: URL,
  name: string,
  fetcher: typeof fetch,
  timeout: number,
  transport: UpdateTransport | undefined,
  notFound: "absent",
): Promise<Response | undefined>;
async function fetchSource(
  url: URL,
  name: string,
  fetcher: typeof fetch,
  timeout: number,
  transport: UpdateTransport | undefined,
  notFound?: "absent",
): Promise<Response | undefined> {
  checkSourceUrl(url, transport);
  const signal = AbortSignal.timeout(timeout);
  let target = url;
  for (let hop = 0; ; hop += 1) {
    let response: Response;
    try {
      response = await fetcher(target, { redirect: "manual", signal });
    } catch (error) {
      if ((error as Error).name === "TimeoutError")
        throw new PiShipError(
          "UPDATE_FAILED",
          `Update source did not answer for ${name} within ${timeout / 1000} s`,
          { retryable: true },
        );
      throw error;
    }
    if (REDIRECTS.has(response.status)) {
      await response.body?.cancel().catch(() => {});
      const location = response.headers.get("location");
      let next: URL | undefined;
      try {
        next = location ? new URL(location, target) : undefined;
      } catch {
        next = undefined;
      }
      if (!next)
        throw new PiShipError(
          "UPDATE_FAILED",
          `Update source answered HTTP ${response.status} for ${name} without a valid Location`,
        );
      if (url.protocol === "https:" && next.protocol === "http:")
        throw new PiShipError(
          "UPDATE_FAILED",
          `Update source redirected ${name} from https to http://${next.host}; PiShip never follows an https update source to plain HTTP`,
        );
      if (next.origin !== url.origin)
        throw new PiShipError(
          "UPDATE_FAILED",
          `Update source redirected ${name} to another origin (${next.origin}); PiShip follows redirects only within ${url.origin}`,
          {
            userAction:
              "Serve the channel files and archives from the update source's own origin, or set updates.source (or --from) to the URL they are served from",
          },
        );
      if (hop + 1 > MAX_REDIRECTS)
        throw new PiShipError(
          "UPDATE_FAILED",
          `Update source redirected ${name} more than ${MAX_REDIRECTS} times`,
        );
      checkSourceUrl(next, transport);
      target = next;
      continue;
    }
    if (notFound && response.status === 404) {
      await response.body?.cancel().catch(() => {});
      return undefined;
    }
    if (!response.ok || !response.body) {
      await response.body?.cancel().catch(() => {});
      const retryAfterMs =
        response.status === 429 || response.status === 503
          ? parseRetryAfter(response.headers.get("retry-after"))
          : undefined;
      throw new PiShipError(
        "UPDATE_FAILED",
        `Update source returned HTTP ${response.status} for ${name}${response.status === 429 ? " (rate limited)" : ""}`,
        {
          retryable: response.status >= 500 || response.status === 429,
          ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
          ...(response.status === 429
            ? { userAction: "Wait, then run update again" }
            : {}),
        },
      );
    }
    return response;
  }
}

/**
 * Reads a small file from a directory or an https (or loopback http, or
 * private http unless `transport` is https) source. `answer.date` receives the
 * source's HTTP `Date`, when it sent one.
 */
export async function readSourceFile(
  source: string,
  name: string,
  fetcher: typeof fetch = fetch,
  answer?: { date?: number },
  transport?: UpdateTransport,
): Promise<Buffer> {
  if (isUrlSource(source)) {
    const url = new URL(name, source.endsWith("/") ? source : `${source}/`);
    const response = await fetchSource(
      url,
      name,
      fetcher,
      METADATA_TIMEOUT_MS,
      transport,
    );
    const date = Date.parse(response.headers.get("date") ?? "");
    if (answer && !Number.isNaN(date)) answer.date = date;
    return readBody(response, name, MAX_METADATA_BYTES);
  }
  const path = join(resolve(source), name);
  if (!existsSync(path))
    throw new PiShipError("UPDATE_FAILED", `Update source has no ${name}`);
  if (statSync(path).size > MAX_METADATA_BYTES)
    throw tooLarge(name, MAX_METADATA_BYTES);
  return readFileSync(path);
}

async function readBody(
  response: Response,
  name: string,
  limit: number,
): Promise<Buffer> {
  const declared = Number(response.headers.get("content-length"));
  if (declared > limit) {
    await response.body?.cancel().catch(() => {});
    throw tooLarge(name, limit);
  }
  const chunks: Buffer[] = [];
  let received = 0;
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
    received += chunk.length;
    if (received > limit) throw tooLarge(name, limit);
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/**
 * Like `readSourceFile` with a size limit of its own, but a file the source
 * authoritatively reports as absent (HTTP 404, or no such file in a
 * directory source) is `undefined`. Every other failure (network, TLS,
 * proxy, another HTTP status, an unreadable file) still throws.
 */
export async function readOptionalSourceFile(
  source: string,
  name: string,
  limit: number,
  fetcher: typeof fetch = fetch,
  transport?: UpdateTransport,
): Promise<Buffer | undefined> {
  if (isUrlSource(source)) {
    const url = new URL(name, source.endsWith("/") ? source : `${source}/`);
    const response = await fetchSource(
      url,
      name,
      fetcher,
      METADATA_TIMEOUT_MS,
      transport,
      "absent",
    );
    return response && readBody(response, name, limit);
  }
  const path = join(resolve(source), name);
  let size: number;
  try {
    size = statSync(path).size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (size > limit) throw tooLarge(name, limit);
  return readFileSync(path);
}

/**
 * A source written as `scheme:` (other than a Windows drive letter) is a URL;
 * anything else is a local directory path. A drive-relative Windows path such
 * as `C:foo` (no separator after the colon) matches the scheme pattern, so it
 * is treated as a URL and refused rather than resolved against the current
 * directory of drive C; write `C:\foo` or `C:/foo` instead.
 */
export function isUrlSource(source: string): boolean {
  return (
    /^[a-z][a-z0-9+.-]*:/i.test(source) && !/^[a-z]:([\\/]|$)/i.test(source)
  );
}

/**
 * Validate an update source after `${NAME}` resolution or from `--from`, with
 * the same URL rules as the manifest: https, or http to a loopback host (or,
 * unless `transport` is https, to a private or internal host), with no
 * credentials, query string, or fragment. Any other value is a local
 * directory; one resolved from `updates.source` must be absolute, while a
 * `--from` directory may be relative to the working directory. Returns the
 * URL unchanged or the absolute directory path.
 */
export function checkUpdateSource(
  source: string,
  origin: "updates.source" | "--from",
  transport?: UpdateTransport,
): string {
  if (isUrlSource(source)) {
    let url: URL;
    try {
      url = new URL(source);
    } catch {
      throw new PiShipError(
        "CONFIG_INVALID",
        `${origin} is not a valid URL: ${redact(source)}`,
      );
    }
    checkSourceUrl(url, transport);
    if (url.search || url.hash)
      throw new PiShipError(
        "CONFIG_INVALID",
        `${origin} may not contain a query string or fragment`,
      );
    return source;
  }
  if (origin === "updates.source" && !isAbsolute(source))
    throw new PiShipError(
      "CONFIG_INVALID",
      `updates.source resolved to ${redact(source)}, which is neither an https URL, an http URL on 127.0.0.1, localhost, or [::1], nor an absolute local directory`,
    );
  const directory = resolve(source);
  if (!existsSync(directory) || !statSync(directory).isDirectory())
    throw new PiShipError(
      "UPDATE_FAILED",
      `Update source directory ${directory} does not exist`,
    );
  return directory;
}

/**
 * Only https, or http to a loopback host, may serve updates; unless
 * `transport` is https, also http to a private or internal host. The host is
 * judged by its text, never by DNS.
 */
export function checkSourceUrl(url: URL, transport?: UpdateTransport): void {
  if (
    transport !== "https" &&
    url.protocol === "http:" &&
    !plainHttpUpdateAllowed(url, transport)
  )
    throw new PiShipError(
      "NETWORK_DENIED",
      `Plain HTTP is accepted only to a private or internal update host; ${url.host} is public`,
      {
        userAction: `Serve the update channel over https, or from ${PRIVATE_UPDATE_HOSTS}`,
      },
    );
  if (url.protocol !== "https:" && !plainHttpUpdateAllowed(url, transport))
    throw new PiShipError(
      "NETWORK_DENIED",
      `Update sources must use https (got ${url.protocol}//${url.host})`,
    );
  if (url.username || url.password)
    throw new PiShipError(
      "CONFIG_INVALID",
      "Update source URLs may not carry credentials",
    );
}

/**
 * Download a channel archive into `destination`, streaming, and check size and
 * SHA-256 against the signed entry. Returns the verified digest, which the
 * caller passes on instead of hashing the archive again.
 */
export async function downloadArchive(
  source: string,
  entry: ChannelRelease,
  destination: string,
  fetcher: typeof fetch = fetch,
  transport?: UpdateTransport,
  idleMs: number = ARCHIVE_IDLE_TIMEOUT_MS,
): Promise<string> {
  if (
    basename(entry.archive) !== entry.archive ||
    !entry.archive.endsWith(".tar.gz")
  )
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Unsafe archive name ${entry.archive}`,
    );
  let actual: string;
  if (isUrlSource(source)) {
    const url = new URL(
      entry.archive,
      source.endsWith("/") ? source : `${source}/`,
    );
    const response = await fetchSource(
      url,
      entry.archive,
      fetcher,
      ARCHIVE_TIMEOUT_MS,
      transport,
    );
    actual = await saveBody(
      response,
      destination,
      entry.archive,
      entry.bytes,
      idleMs,
    );
  } else {
    const path = join(resolve(source), entry.archive);
    if (statSync(path).size > entry.bytes)
      throw tooLarge(entry.archive, entry.bytes);
    cpSync(path, destination);
    actual = await sha256File(destination);
  }
  const size = statSync(destination).size;
  if (size !== entry.bytes || actual !== entry.sha256)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Downloaded ${entry.archive} does not match the signed channel metadata`,
      {
        userAction:
          "Do not install it; report the update source to the distribution owner",
      },
    );
  return actual;
}
