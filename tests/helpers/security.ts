import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

// Helpers for the security suite: find a secret wherever a real run may have
// left it. A plain substring scan is blind to the restricted file store, which
// keeps every value base64url-encoded (an identity token bundle is JSON, so
// its tokens are not even contiguous there), and to anything that echoes a
// secret in an encoded form. Every scan here therefore also decodes what it
// reads before it compares.
//
// Limits, stated so a clean scan is not read as more than it is:
// - A secret is found in a base64 or base64url run of at least
//   MIN_RUN_LENGTH characters, at any of the four alignments. The ledger only
//   tracks secrets of 8 or more characters, which encode to at least 11.
//   Other encodings (URL-encoded, hex, compressed) are not searched.
// - A file over MAX_DECODED_BYTES is searched in plain form only;
//   `scanTreeReport` lists such files so a caller can assert there are none
//   where it matters.
// - A symbolic link is not followed.

/**
 * A secret and where it was found. The secret is only `secret #<n>`, n counting
 * the secrets given to the scan from 1: a failure is public CI output, and any
 * part of a secret printed there, a prefix included, is a leak.
 */
export interface Sighting {
  readonly where: string;
  readonly secret: string;
  readonly form: "plain" | "decoded";
  /** The text around a plain sighting with every known secret masked, to see what carried it. */
  readonly context?: string;
}

/** Shortest base64 run that can hold a secret the ledger tracks (8 bytes encode to 11 characters). */
const MIN_RUN_LENGTH = 10;
const BASE64_RUN = new RegExp(`[A-Za-z0-9+/_-]{${MIN_RUN_LENGTH},}={0,2}`, "g");
/** Larger files (an installed payload) are only searched for the plain secret. */
export const MAX_DECODED_BYTES = 2_000_000;
const CONTEXT = 80;

/**
 * Decodings of one run. A run that starts in the middle of a base64 quantum
 * (an identifier glued to the encoded value with no separator) decodes
 * misaligned, so every start offset of a quantum is tried, in both alphabets.
 */
function decodings(run: string): string[] {
  const decoded: string[] = [];
  for (let offset = 0; offset < 4; offset += 1) {
    const part = run.slice(offset);
    decoded.push(
      Buffer.from(part, "base64url").toString("latin1"),
      Buffer.from(part, "base64").toString("latin1"),
    );
  }
  return decoded;
}

/** What `text` holds of `secrets`, in plain form or inside a base64 or base64url run. */
export function sightings(
  where: string,
  text: string,
  secrets: readonly string[],
  { decode = true }: { decode?: boolean } = {},
): Sighting[] {
  const hits: Sighting[] = [];
  const named = secrets.flatMap((secret, index) =>
    secret.length > 0 ? [{ secret, label: `secret #${index + 1}` }] : [],
  );
  const wanted = named.map(({ secret }) => secret);
  const widest = Math.max(0, ...wanted.map((secret) => secret.length));
  const report = (label: string, form: Sighting["form"], context?: string) =>
    hits.push({
      where,
      secret: label,
      form,
      ...(context === undefined ? {} : { context }),
    });
  for (const { secret, label } of named) {
    const at = text.indexOf(secret);
    if (at < 0) continue;
    // Mask first, cut after: a window wide enough to hold a whole neighbouring
    // secret keeps the window's edge from printing half of one.
    const pad = CONTEXT + widest;
    let around = text.slice(Math.max(0, at - pad), at + secret.length + pad);
    for (const other of wanted) around = around.split(other).join("<secret>");
    const centre = around.indexOf("<secret>");
    const from = Math.max(0, centre - CONTEXT);
    report(
      label,
      "plain",
      around
        .slice(from, centre + "<secret>".length + CONTEXT)
        .replace(/\s+/g, " "),
    );
  }
  if (!decode) return hits;
  for (const [run] of text.matchAll(BASE64_RUN)) {
    const candidates = decodings(run);
    for (const { secret, label } of named)
      if (candidates.some((candidate) => candidate.includes(secret)))
        report(label, "decoded");
  }
  return hits;
}

/** The POSIX form of `path` below `root`. */
const below = (root: string, path: string) =>
  relative(root, path).split(sep).join("/");

/**
 * Every file under `directory`. `skip` names directories to leave out as
 * paths below `directory` with `/` separators, so a directory that merely
 * shares a name with one is still searched; `node_modules` is always left out
 * by name. Symbolic links are listed by neither `files` nor followed.
 */
export function filesUnder(
  directory: string,
  skip: readonly string[] = [],
): string[] {
  const files: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      const stat = lstatSync(child);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        if (name !== "node_modules" && !skip.includes(below(directory, child)))
          visit(child);
      } else files.push(child);
    }
  };
  if (existsSync(directory)) visit(directory);
  return files;
}

export interface ScanReport {
  readonly found: Sighting[];
  /** Files too large to decode, searched in plain form only. */
  readonly plainOnly: string[];
}

/** `scanTree`, and the files it could only search in plain form. */
export function scanTreeReport(
  directory: string,
  secrets: readonly string[],
  skip: readonly string[] = [],
): ScanReport {
  const found: Sighting[] = [];
  const plainOnly: string[] = [];
  for (const file of filesUnder(directory, skip)) {
    const text = readFileSync(file, "latin1");
    const decode = text.length <= MAX_DECODED_BYTES;
    if (!decode) plainOnly.push(file);
    found.push(...sightings(file, text, secrets, { decode }));
  }
  return { found, plainOnly };
}

/**
 * Files under `directory` that hold a secret, plain or encoded. The store's
 * own directory is where a stored secret belongs, so pass it in `skip` (see
 * `filesUnder`) to leave it out and check it separately.
 */
export function scanTree(
  directory: string,
  secrets: readonly string[],
  skip: readonly string[] = [],
): Sighting[] {
  return scanTreeReport(directory, secrets, skip).found;
}

/** One line per sighting, for an assertion that names what leaked and where. */
export function describeSightings(found: readonly Sighting[]): string[] {
  return found.map(
    (hit) =>
      `${hit.where} holds ${hit.secret} (${hit.form})${hit.context === undefined ? "" : ` in: ${hit.context}`}`,
  );
}

/**
 * The values the restricted file store holds, decoded. An identity token
 * bundle is a JSON object of tokens; each token is returned too, so a caller
 * gets every secret the store holds as one flat list.
 */
export function fileStoreSecrets(secretsDirectory: string): string[] {
  const values: string[] = [];
  for (const file of filesUnder(secretsDirectory)) {
    if (!file.endsWith(".secret")) continue;
    const record = JSON.parse(readFileSync(file, "utf8")) as { value?: string };
    if (typeof record.value !== "string") continue;
    const value = Buffer.from(record.value, "base64url").toString("utf8");
    values.push(value);
    try {
      const parsed: unknown = JSON.parse(value);
      if (parsed && typeof parsed === "object")
        for (const item of Object.values(parsed))
          if (typeof item === "string" && item.length >= 8) values.push(item);
    } catch {
      // Not a bundle: the value itself is the secret.
    }
  }
  return values;
}

/**
 * Every secret a scenario has seen, so a sweep at the end looks for all of
 * them, including ones a later step already replaced or deleted. Values
 * shorter than 8 characters are not tracked (see the limits above).
 */
export class SecretLedger {
  readonly #seen = new Set<string>();
  add(...values: readonly (string | undefined)[]): void {
    for (const value of values)
      if (value && value.length >= 8) this.#seen.add(value);
  }
  /** What the file store holds now. */
  observeFileStore(secretsDirectory: string): void {
    this.add(...fileStoreSecrets(secretsDirectory));
  }
  /**
   * What the local fixture services have issued so far: credentials, access
   * and refresh tokens, and ID tokens. ID tokens enter here, not only through
   * a file-store snapshot, so a run on the system secret store (which no
   * snapshot reads) still scans for them.
   */
  observeServices(services: {
    state: {
      credentials: Map<string, unknown>;
      accessTokens: Map<string, unknown>;
      refreshTokens: Map<string, unknown>;
      idTokens: Set<string>;
    };
  }): void {
    this.add(
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
      ...services.state.idTokens,
    );
  }
  all(): string[] {
    return [...this.#seen];
  }
  get size(): number {
    return this.#seen.size;
  }
}
