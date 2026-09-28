// Update sources: validating a directory or URL source and reading channel
// files and release archives from it with size and time limits.
import { cpSync, existsSync, readFileSync, statSync } from "node:fs";
import { basename, isAbsolute, join, resolve } from "node:path";
import { PiShipError, redact } from "@piship/contracts";
import { sha256File } from "../archive.js";
import type { ChannelRelease } from "./channel.js";

/** Channel metadata and signatures are small; anything larger is refused. */
const MAX_METADATA_BYTES = 1024 * 1024;
const METADATA_TIMEOUT_MS = 30_000;
const ARCHIVE_TIMEOUT_MS = 30 * 60_000;

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

/** Stream a response body into `destination`, stopping past `limit` bytes. */
async function saveBody(
  response: Response,
  destination: string,
  name: string,
  limit: number,
): Promise<void> {
  const { Readable, Transform } = await import("node:stream");
  const { pipeline } = await import("node:stream/promises");
  const { createWriteStream } = await import("node:fs");
  let received = 0;
  try {
    await pipeline(
      Readable.fromWeb(response.body as never),
      new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          received += chunk.length;
          callback(received > limit ? tooLarge(name, limit) : null, chunk);
        },
      }),
      createWriteStream(destination, { flags: "wx" }),
    );
  } catch (error) {
    if (["TimeoutError", "AbortError"].includes((error as Error).name))
      throw new PiShipError(
        "UPDATE_FAILED",
        `Update source stopped sending ${name} before the deadline`,
        { retryable: true },
      );
    throw error;
  }
}

async function fetchSource(
  url: URL,
  name: string,
  fetcher: typeof fetch,
  timeout: number,
): Promise<Response> {
  checkSourceUrl(url);
  let response: Response;
  try {
    response = await fetcher(url, {
      redirect: "error",
      signal: AbortSignal.timeout(timeout),
    });
  } catch (error) {
    if ((error as Error).name === "TimeoutError")
      throw new PiShipError(
        "UPDATE_FAILED",
        `Update source did not answer for ${name} within ${timeout / 1000} s`,
        { retryable: true },
      );
    throw error;
  }
  if (!response.ok || !response.body)
    throw new PiShipError(
      "UPDATE_FAILED",
      `Update source returned HTTP ${response.status} for ${name}`,
      { retryable: response.status >= 500 },
    );
  return response;
}

/** Reads a small file from a directory or an https (or loopback http) source. */
export async function readSourceFile(
  source: string,
  name: string,
  fetcher: typeof fetch = fetch,
): Promise<Buffer> {
  if (isUrlSource(source)) {
    const url = new URL(name, source.endsWith("/") ? source : `${source}/`);
    const response = await fetchSource(url, name, fetcher, METADATA_TIMEOUT_MS);
    const declared = Number(response.headers.get("content-length"));
    if (declared > MAX_METADATA_BYTES) throw tooLarge(name, MAX_METADATA_BYTES);
    const chunks: Buffer[] = [];
    let received = 0;
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      received += chunk.length;
      if (received > MAX_METADATA_BYTES)
        throw tooLarge(name, MAX_METADATA_BYTES);
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  const path = join(resolve(source), name);
  if (!existsSync(path))
    throw new PiShipError("UPDATE_FAILED", `Update source has no ${name}`);
  if (statSync(path).size > MAX_METADATA_BYTES)
    throw tooLarge(name, MAX_METADATA_BYTES);
  return readFileSync(path);
}

/**
 * A source written as `scheme:` (other than a Windows drive letter) is a URL;
 * anything else is a local directory path. A drive-relative Windows path such
 * as `C:foo` (no separator after the colon) matches the scheme pattern, so it
 * is treated as a URL and refused rather than resolved against the current
 * directory of drive C; write `C:\foo` or `C:/foo` instead.
 */
function isUrlSource(source: string): boolean {
  return (
    /^[a-z][a-z0-9+.-]*:/i.test(source) && !/^[a-z]:([\\/]|$)/i.test(source)
  );
}

/**
 * Validate an update source after `${NAME}` resolution or from `--from`, with
 * the same URL rules as the manifest: https, or http to a loopback host, with
 * no credentials, query string, or fragment. Any other value is a local
 * directory; one resolved from `updates.source` must be absolute, while a
 * `--from` directory may be relative to the working directory. Returns the
 * URL unchanged or the absolute directory path.
 */
export function checkUpdateSource(
  source: string,
  origin: "updates.source" | "--from",
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
    checkSourceUrl(url);
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

/** Only https, or http to a loopback host, may serve updates. */
export function checkSourceUrl(url: URL): void {
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
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

/** Download a channel archive into `destination`, streaming, and check size and SHA-256. */
export async function downloadArchive(
  source: string,
  entry: ChannelRelease,
  destination: string,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  if (
    basename(entry.archive) !== entry.archive ||
    !entry.archive.endsWith(".tar.gz")
  )
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Unsafe archive name ${entry.archive}`,
    );
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
    );
    await saveBody(response, destination, entry.archive, entry.bytes);
  } else {
    const path = join(resolve(source), entry.archive);
    if (statSync(path).size > entry.bytes)
      throw tooLarge(entry.archive, entry.bytes);
    cpSync(path, destination);
  }
  const size = statSync(destination).size;
  const actual = await sha256File(destination);
  if (size !== entry.bytes || actual !== entry.sha256)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Downloaded ${entry.archive} does not match the signed channel metadata`,
      {
        userAction:
          "Do not install it; report the update source to the distribution owner",
      },
    );
}
