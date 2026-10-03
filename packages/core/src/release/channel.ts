// Signed update channels: adding verified releases to channel metadata and
// reading it back against the trusted keys.
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { syncDirectory, temporarySibling } from "@piship/credentials";
import { RELEASE_CHANNELS } from "@piship/schema";
import { sha256File } from "../archive.js";
import {
  buildSignatureEnvelope,
  type KeyedSigner,
  keyFingerprint,
  pemSigner,
  signVerified,
  verifySignature,
  type SignatureEnvelope,
  type TrustedKey,
} from "../signing.js";
import { CHANNEL_SCHEMA } from "./metadata.js";
import { readSourceFile } from "./source.js";
import { type VerifiedRelease, verifyRelease } from "./verify.js";

export interface ChannelRelease {
  readonly version: string;
  readonly target: string;
  /** Archive file name next to the channel metadata. */
  readonly archive: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly pi: string;
  readonly piship: string;
  readonly lockSha256: string;
}

export interface ChannelMetadata {
  readonly schema: typeof CHANNEL_SCHEMA;
  readonly distribution: string;
  readonly channel: string;
  /** Monotonic; a client never accepts a lower sequence than it has seen. */
  readonly sequence: number;
  readonly expires: string;
  readonly releases: readonly ChannelRelease[];
}

const SHA256 = /^[a-f0-9]{64}$/;
const VERSION =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const TARGET = /^(?:linux|darwin|win32)-(?:x64|arm64)$/;
const ARCHIVE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$/;

function validChannel(value: unknown): value is ChannelMetadata {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const doc = value as Record<string, unknown>;
  if (
    doc.schema !== CHANNEL_SCHEMA ||
    typeof doc.distribution !== "string" ||
    typeof doc.channel !== "string" ||
    typeof doc.expires !== "string" ||
    !Number.isSafeInteger(doc.sequence) ||
    (doc.sequence as number) < 1 ||
    !Array.isArray(doc.releases)
  )
    return false;
  return doc.releases.every((entry: unknown) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry))
      return false;
    const release = entry as Record<string, unknown>;
    return (
      typeof release.version === "string" &&
      VERSION.test(release.version) &&
      typeof release.target === "string" &&
      TARGET.test(release.target) &&
      typeof release.archive === "string" &&
      ARCHIVE.test(release.archive) &&
      typeof release.sha256 === "string" &&
      SHA256.test(release.sha256) &&
      Number.isSafeInteger(release.bytes) &&
      (release.bytes as number) > 0 &&
      typeof release.pi === "string" &&
      VERSION.test(release.pi) &&
      typeof release.piship === "string" &&
      VERSION.test(release.piship) &&
      typeof release.lockSha256 === "string" &&
      SHA256.test(release.lockSha256)
    );
  });
}

export type SignChannelOptions = SignChannelCommon &
  (
    | {
        /** A plaintext PKCS#8 PEM key; use `signer` for an encrypted one. */
        readonly privateKeyPem: string;
        readonly keyId: string;
        readonly signer?: undefined;
      }
    | {
        readonly signer: KeyedSigner;
        readonly privateKeyPem?: undefined;
        readonly keyId?: undefined;
      }
  );

interface SignChannelCommon {
  readonly directory: string;
  readonly channel: string;
  readonly archives: readonly string[];
  /**
   * Further public keys the existing metadata may be signed with, such as
   * the retiring key once signing has moved to its successor.
   */
  readonly previousKeys?: readonly TrustedKey[];
  readonly sequence?: number;
  readonly expiresDays?: number;
  readonly now?: () => Date;
}

/**
 * Replace a published channel file through a flushed temporary sibling and a
 * rename, so it is never seen truncated. Unlike the owner-only state files,
 * it keeps the default mode: a web server serves it.
 */
function replaceFile(path: string, content: string): void {
  const temporary = temporarySibling(path);
  try {
    writeFileSync(temporary, content, { flag: "wx", flush: true });
    renameSync(temporary, path);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  syncDirectory(dirname(path));
}

/**
 * The channel's existing metadata, which `sign-channel` extends only when it
 * is intact and its signature verifies with one of `accepted`.
 */
function existingChannel(
  path: string,
  channel: string,
  accepted: readonly TrustedKey[],
): ChannelMetadata {
  const refuse = (problem: string) =>
    new PiShipError(
      "INTEGRITY_FAILED",
      `Existing channel metadata ${path} ${problem}; refusing to extend it`,
      {
        userAction:
          "Restore the published metadata and its signature; if a key you trust signed it, pass that key with --previous-key <id>=<public-key>",
      },
    );
  const bytes = readFileSync(path);
  let metadata: unknown;
  try {
    metadata = JSON.parse(bytes.toString("utf8"));
  } catch {
    metadata = undefined;
  }
  if (!validChannel(metadata) || metadata.channel !== channel)
    throw refuse("is not valid channel metadata");
  if (!existsSync(`${path}.sig`)) throw refuse("has no signature");
  try {
    verifySignature(
      bytes,
      JSON.parse(readFileSync(`${path}.sig`, "utf8")) as unknown,
      accepted,
    );
  } catch (error) {
    throw refuse(
      `does not verify: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return metadata;
}

/**
 * Add verified release archives to a channel directory and sign its
 * metadata. Existing entries for other versions or targets are kept once the
 * existing metadata verifies with the signing key, a `previousKeys` key, or a
 * key an added release pins. Nothing is written until the
 * new metadata is signed; then the metadata and its signature are each
 * replaced through a temporary file and a rename.
 */
export async function signChannel(
  options: SignChannelOptions,
): Promise<{ readonly path: string; readonly metadata: ChannelMetadata }> {
  if (!(RELEASE_CHANNELS as readonly string[]).includes(options.channel))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Unknown channel ${options.channel}`,
    );
  // An unreadable or non-Ed25519 key fails here, before anything is written.
  const accepted: TrustedKey[] = [];
  const accept = (key: TrustedKey) => {
    if (
      !accepted.some(
        (item) => item.id === key.id && item.publicKey === key.publicKey,
      )
    )
      accepted.push(key);
  };
  const signer =
    options.signer ??
    pemSigner({ keyId: options.keyId, privateKeyPem: options.privateKeyPem });
  accept({ id: signer.keyId, publicKey: signer.publicKey });
  for (const key of options.previousKeys ?? []) accept(key);
  const verified: { archive: string; release: VerifiedRelease }[] = [];
  try {
    for (const archive of options.archives) {
      const release = await verifyRelease(archive);
      verified.push({ archive, release });
      for (const key of release.lock.updates?.trust.keys ?? []) accept(key);
    }
    const directory = resolve(options.directory);
    const path = join(directory, `${options.channel}.json`);
    const previous = existsSync(path)
      ? existingChannel(path, options.channel, accepted)
      : undefined;
    const entries = new Map(
      (previous?.releases ?? []).map((item) => [
        `${item.version} ${item.target}`,
        item,
      ]),
    );
    let distribution = previous?.distribution;
    for (const { release } of verified) {
      const id = release.metadata.distribution.id;
      if (distribution && distribution !== id)
        throw new PiShipError(
          "CONFIG_INVALID",
          `Channel ${options.channel} belongs to ${distribution}, not ${id}`,
        );
      distribution = id;
    }
    if (!distribution)
      throw new PiShipError("CONFIG_INVALID", "No release archives were given");
    for (const { archive, release } of verified) {
      const { metadata } = release;
      entries.set(`${metadata.distribution.version} ${metadata.target}`, {
        version: metadata.distribution.version,
        target: metadata.target,
        archive: basename(archive),
        sha256: await sha256File(archive),
        bytes: statSync(archive).size,
        pi: metadata.pi.version,
        piship: metadata.piship.version,
        lockSha256: metadata.lockSha256,
      });
    }
    const now = (options.now ?? (() => new Date()))();
    const metadata: ChannelMetadata = {
      schema: CHANNEL_SCHEMA,
      distribution,
      channel: options.channel,
      sequence: options.sequence ?? (previous?.sequence ?? 0) + 1,
      expires: new Date(
        now.getTime() + (options.expiresDays ?? 30) * 86_400_000,
      ).toISOString(),
      releases: [...entries.values()].sort((a, b) =>
        `${a.target} ${a.version}`.localeCompare(`${b.target} ${b.version}`),
      ),
    };
    if (previous && metadata.sequence <= previous.sequence)
      throw new PiShipError(
        "CONFIG_INVALID",
        `Channel sequence must increase (current ${previous.sequence})`,
      );
    // Both files are prepared, and the signature checked against the
    // signer's public key, before the channel directory is touched: a
    // failing or faulty signer changes nothing.
    const text = `${JSON.stringify(metadata, null, 2)}\n`;
    const signature = buildSignatureEnvelope([
      await signVerified(signer, Buffer.from(text)),
    ]);
    const signatureText = `${JSON.stringify(signature, null, 2)}\n`;
    mkdirSync(directory, { recursive: true });
    for (const { archive } of verified) {
      const destination = join(directory, basename(archive));
      if (resolve(archive) === destination) continue;
      copyFileSync(archive, destination);
      const entry = metadata.releases.find(
        (item) => item.archive === basename(archive),
      );
      if ((await sha256File(destination)) !== entry?.sha256)
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `${archive} changed while the channel was being signed`,
        );
    }
    // Each file is replaced whole, so neither is ever seen truncated. A
    // reader that gets a mismatched pair between the two replacements
    // refuses it, as does the next sign-channel.
    replaceFile(path, text);
    replaceFile(`${path}.sig`, signatureText);
    return { path, metadata };
  } finally {
    for (const { release } of verified) release.cleanup();
  }
}

/**
 * Fetch and verify signed channel metadata: a trusted key that is not
 * `retired`, the expected distribution and channel, not expired, and no older
 * than `minSequence`.
 */
export async function readChannel(
  source: string,
  channel: string,
  options: {
    readonly distribution: string;
    readonly trusted: readonly TrustedKey[];
    /**
     * Keys a release activated on this installation stopped pinning, matched
     * by public key fingerprint; refused even when `trusted` pins them.
     */
    readonly retired?: readonly {
      readonly id: string;
      readonly fingerprint: string;
      readonly release: string;
    }[];
    readonly minSequence?: number;
    readonly now?: () => Date;
    readonly fetcher?: typeof fetch;
  },
): Promise<{ readonly metadata: ChannelMetadata; readonly keyId: string }> {
  const answer: { date?: number } = {};
  const bytes = await readSourceFile(
    source,
    `${channel}.json`,
    options.fetcher,
    answer,
  );
  const signature = await readSourceFile(
    source,
    `${channel}.json.sig`,
    options.fetcher,
  );
  let envelope: SignatureEnvelope;
  try {
    envelope = JSON.parse(signature.toString("utf8")) as SignatureEnvelope;
  } catch {
    throw new PiShipError(
      "INTEGRITY_FAILED",
      "Channel signature is not valid JSON",
    );
  }
  const retired = new Map(
    (options.retired ?? []).map((key) => [key.fingerprint, key]),
  );
  const trusted = options.trusted.filter(
    (key) => !retired.has(keyFingerprint(key.publicKey)),
  );
  const named = (envelope as { keyId?: unknown } | null)?.keyId;
  if (!trusted.some((key) => key.id === named)) {
    const pinned = options.trusted.find((key) => key.id === named);
    const retirement = pinned && retired.get(keyFingerprint(pinned.publicKey));
    if (retirement)
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `Signature key ${retirement.id} was retired by the ${retirement.release} release of this installation; a rollback does not restore trust in it`,
        {
          component: "signing",
          userAction:
            "Ask the distribution owner to sign the channel with a current key, or reinstall from a release verified out of band",
        },
      );
  }
  const keyId = verifySignature(bytes, envelope, trusted);
  let metadata: unknown;
  try {
    metadata = JSON.parse(bytes.toString("utf8")) as unknown;
  } catch {
    throw new PiShipError(
      "INTEGRITY_FAILED",
      "Channel metadata is not valid JSON",
    );
  }
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata))
    throw new PiShipError(
      "INTEGRITY_FAILED",
      "Channel metadata is not an object",
    );
  if ((metadata as Record<string, unknown>).schema !== CHANNEL_SCHEMA)
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Unsupported channel metadata ${String((metadata as Record<string, unknown>).schema)}`,
    );
  if (!validChannel(metadata))
    throw new PiShipError(
      "INTEGRITY_FAILED",
      "Channel metadata has invalid fields or releases",
    );
  if (
    metadata.distribution !== options.distribution ||
    metadata.channel !== channel
  )
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Channel metadata is for ${metadata.distribution}/${metadata.channel}, not ${options.distribution}/${channel}`,
    );
  const now = (options.now ?? (() => new Date()))();
  const expires = Date.parse(metadata.expires);
  if (!(expires > now.getTime())) {
    // By the source's own clock the metadata is still valid: this
    // computer's clock is ahead, and re-signing would not help.
    if (answer.date !== undefined && expires > answer.date)
      throw new PiShipError(
        "UPDATE_FAILED",
        `This computer's clock (${now.toISOString()}) is ahead of the update source's (${new Date(answer.date).toISOString()}): the channel metadata is valid until ${metadata.expires}`,
        {
          userAction:
            "Correct this computer's date and time (turn on automatic time), then run update again",
        },
      );
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Channel metadata expired at ${metadata.expires} (this computer's clock reads ${now.toISOString()})`,
      {
        userAction:
          "If this computer's clock is wrong, correct it; otherwise the publisher must re-sign the channel (piship sign-channel)",
      },
    );
  }
  if (
    !Number.isSafeInteger(metadata.sequence) ||
    metadata.sequence < (options.minSequence ?? 0)
  )
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Channel metadata sequence ${metadata.sequence} is older than the ${options.minSequence} already seen; refusing a replayed channel`,
    );
  return { metadata, keyId };
}
