// Signed update channels: adding verified releases to channel metadata and
// reading it back against the trusted keys.
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { RELEASE_CHANNELS } from "@piship/schema";
import { sha256File } from "../archive.js";
import {
  signBytes,
  verifySignature,
  type SignatureEnvelope,
  type TrustedKey,
} from "../signing.js";
import { CHANNEL_SCHEMA } from "./metadata.js";
import { writeJson } from "./shared.js";
import { readSourceFile } from "./source.js";
import { verifyRelease } from "./verify.js";

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

export interface SignChannelOptions {
  readonly directory: string;
  readonly channel: string;
  readonly archives: readonly string[];
  readonly privateKeyPem: string;
  readonly keyId: string;
  readonly sequence?: number;
  readonly expiresDays?: number;
  readonly now?: () => Date;
}

/**
 * Add verified release archives to a channel directory and sign its
 * metadata. Existing entries for other versions or targets are kept.
 */
export async function signChannel(
  options: SignChannelOptions,
): Promise<{ readonly path: string; readonly metadata: ChannelMetadata }> {
  if (!(RELEASE_CHANNELS as readonly string[]).includes(options.channel))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Unknown channel ${options.channel}`,
    );
  const directory = resolve(options.directory);
  mkdirSync(directory, { recursive: true });
  const path = join(directory, `${options.channel}.json`);
  const previous = existsSync(path)
    ? (JSON.parse(readFileSync(path, "utf8")) as ChannelMetadata)
    : undefined;
  const entries = new Map(
    (previous?.releases ?? []).map((item) => [
      `${item.version} ${item.target}`,
      item,
    ]),
  );
  let distribution = previous?.distribution;
  for (const archive of options.archives) {
    const verified = await verifyRelease(archive);
    try {
      const { metadata } = verified;
      if (distribution && distribution !== metadata.distribution.id)
        throw new PiShipError(
          "CONFIG_INVALID",
          `Channel ${options.channel} belongs to ${distribution}, not ${metadata.distribution.id}`,
        );
      distribution = metadata.distribution.id;
      const name = basename(archive);
      const destination = join(directory, name);
      if (resolve(archive) !== destination) copyFileSync(archive, destination);
      entries.set(`${metadata.distribution.version} ${metadata.target}`, {
        version: metadata.distribution.version,
        target: metadata.target,
        archive: name,
        sha256: await sha256File(destination),
        bytes: statSync(destination).size,
        pi: metadata.pi.version,
        piship: metadata.piship.version,
        lockSha256: metadata.lockSha256,
      });
    } finally {
      verified.cleanup();
    }
  }
  if (!distribution)
    throw new PiShipError("CONFIG_INVALID", "No release archives were given");
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
  const bytes = Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`);
  writeFileSync(path, bytes);
  writeJson(
    `${path}.sig`,
    signBytes(bytes, options.privateKeyPem, options.keyId),
  );
  return { path, metadata };
}

/**
 * Fetch and verify signed channel metadata: a trusted key, the expected
 * distribution and channel, not expired, and no older than `minSequence`.
 */
export async function readChannel(
  source: string,
  channel: string,
  options: {
    readonly distribution: string;
    readonly trusted: readonly TrustedKey[];
    readonly minSequence?: number;
    readonly now?: () => Date;
    readonly fetcher?: typeof fetch;
  },
): Promise<{ readonly metadata: ChannelMetadata; readonly keyId: string }> {
  const bytes = await readSourceFile(
    source,
    `${channel}.json`,
    options.fetcher,
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
  const keyId = verifySignature(bytes, envelope, options.trusted);
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
  if (!(Date.parse(metadata.expires) > now.getTime()))
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `Channel metadata expired at ${metadata.expires}; the source must re-sign it`,
    );
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
