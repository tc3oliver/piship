import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// Helpers for the security suite: find a secret wherever a real run may have
// left it. A plain substring scan is blind to the restricted file store, which
// keeps every value base64url-encoded (an identity token bundle is JSON, so
// its tokens are not even contiguous there), and to anything that echoes a
// secret in an encoded form. Every scan here therefore also decodes what it
// reads before it compares.

/** A secret and where it was found; only a short prefix, so a failure prints nothing usable. */
export interface Sighting {
  readonly where: string;
  readonly secret: string;
  readonly form: "plain" | "decoded";
  /** The text around a plain sighting with the secret itself masked, to see what carried it. */
  readonly context?: string;
}

const BASE64_RUN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
/** Larger files (an installed payload) are only searched for the plain secret. */
const MAX_DECODED_BYTES = 2_000_000;

/** What `text` holds of `secrets`, in plain form or inside a base64 or base64url run. */
export function sightings(
  where: string,
  text: string,
  secrets: readonly string[],
): Sighting[] {
  const hits: Sighting[] = [];
  const wanted = secrets.filter((secret) => secret.length > 0);
  const report = (secret: string, form: Sighting["form"], context?: string) =>
    hits.push({
      where,
      secret: `${secret.slice(0, 8)}…`,
      form,
      ...(context === undefined ? {} : { context }),
    });
  for (const secret of wanted) {
    const at = text.indexOf(secret);
    if (at < 0) continue;
    // What surrounds the first sighting, every known secret masked.
    let around = text.slice(Math.max(0, at - 80), at + secret.length + 80);
    for (const other of wanted) around = around.split(other).join("<secret>");
    report(secret, "plain", around.replace(/\s+/g, " "));
  }
  if (text.length > MAX_DECODED_BYTES) return hits;
  for (const [run] of text.matchAll(BASE64_RUN)) {
    const decoded = [
      Buffer.from(run, "base64url").toString("latin1"),
      Buffer.from(run, "base64").toString("latin1"),
    ];
    for (const secret of wanted)
      if (decoded.some((candidate) => candidate.includes(secret)))
        report(secret, "decoded");
  }
  return hits;
}

/** Every file under `directory`, skipping the named subdirectories. */
export function filesUnder(
  directory: string,
  skip: readonly string[] = ["node_modules"],
): string[] {
  const files: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) {
        if (!skip.includes(name)) visit(child);
      } else files.push(child);
    }
  };
  if (existsSync(directory)) visit(directory);
  return files;
}

/**
 * Files under `directory` that hold a secret, plain or encoded. The store's
 * own directory is where a stored secret belongs, so pass `skip` to leave it
 * out and check it separately.
 */
export function scanTree(
  directory: string,
  secrets: readonly string[],
  skip: readonly string[] = ["node_modules"],
): Sighting[] {
  return filesUnder(directory, skip).flatMap((file) =>
    sightings(file, readFileSync(file, "latin1"), secrets),
  );
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
 * them, including ones a later step already replaced or deleted.
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
  /** What the local fixture services have issued so far. */
  observeServices(services: {
    state: {
      credentials: Map<string, unknown>;
      accessTokens: Map<string, unknown>;
      refreshTokens: Map<string, unknown>;
    };
  }): void {
    this.add(
      ...services.state.credentials.keys(),
      ...services.state.accessTokens.keys(),
      ...services.state.refreshTokens.keys(),
    );
  }
  all(): string[] {
    return [...this.#seen];
  }
  get size(): number {
    return this.#seen.size;
  }
}
