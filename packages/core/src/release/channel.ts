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
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { createTemporaryDirectory, PiShipError } from "@piship/contracts";
import { syncDirectory, temporarySibling } from "@piship/credentials";
import { RELEASE_CHANNELS, type UpdateTransport } from "@piship/schema";
import { sha256File } from "../archive.js";
import type { DistributionLock } from "../lock-schema.js";
import { channelTrustFromLock } from "../lock.js";
import {
  buildSignatureEnvelope,
  type KeyedSigner,
  keyFingerprint,
  pemSigner,
  type SignatureEntry,
  signVerified,
  verifySignature,
  verifyThreshold,
  type SignatureEnvelope,
  type TrustedKey,
} from "../signing.js";
import { canonicalJson } from "../digest.js";
import { CHANNEL_SCHEMA } from "./metadata.js";
import { refreshRoot, roleTrust, rootExpired } from "./root.js";
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

/** A runtime archive a pack pins, served from the channel directory. */
export interface ChannelPackRuntime {
  readonly archive: string;
  readonly sha256: string;
  readonly bytes: number;
}

/**
 * A Company Pack: a newer config for an official runtime. It is listed apart
 * from `releases`, whose entries every client validates by target, so a client
 * that does not know packs reads the channel and ignores this array.
 */
export interface ChannelPack {
  readonly version: string;
  readonly archive: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly pi: string;
  readonly piship: string;
  readonly lockSha256: string;
  /** The runtime archive this pack pins for each target it serves. */
  readonly runtimes: Readonly<Record<string, ChannelPackRuntime>>;
}

export interface ChannelMetadata {
  readonly schema: typeof CHANNEL_SCHEMA;
  readonly distribution: string;
  readonly channel: string;
  /** Monotonic; a client never accepts a lower sequence than it has seen. */
  readonly sequence: number;
  readonly expires: string;
  readonly releases: readonly ChannelRelease[];
  /** Optional; absent from a channel that serves only per-target releases. */
  readonly packs?: readonly ChannelPack[];
}

const SHA256 = /^[a-f0-9]{64}$/;
const VERSION =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const TARGET = /^(?:linux|darwin|win32)-(?:x64|arm64)$/;
const ARCHIVE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$/;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

function validArchiveRef(entry: Record<string, unknown>): boolean {
  return (
    typeof entry.archive === "string" &&
    ARCHIVE.test(entry.archive) &&
    typeof entry.sha256 === "string" &&
    SHA256.test(entry.sha256) &&
    Number.isSafeInteger(entry.bytes) &&
    (entry.bytes as number) > 0
  );
}

function validPack(entry: unknown): boolean {
  if (!isRecord(entry)) return false;
  return (
    typeof entry.version === "string" &&
    VERSION.test(entry.version) &&
    validArchiveRef(entry) &&
    typeof entry.pi === "string" &&
    VERSION.test(entry.pi) &&
    typeof entry.piship === "string" &&
    VERSION.test(entry.piship) &&
    typeof entry.lockSha256 === "string" &&
    SHA256.test(entry.lockSha256) &&
    isRecord(entry.runtimes) &&
    Object.entries(entry.runtimes).every(
      ([target, runtime]) =>
        TARGET.test(target) && isRecord(runtime) && validArchiveRef(runtime),
    )
  );
}

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
    !Array.isArray(doc.releases) ||
    (doc.packs !== undefined &&
      !(Array.isArray(doc.packs) && doc.packs.every(validPack)))
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
  /** Company Pack archives to list in `packs`; their pinned runtime archives are found beside them or in `runtimes`. */
  readonly packs?: readonly string[];
  /** Further files or directories to look in for the runtime archives the packs pin. */
  readonly runtimes?: readonly string[];
  /**
   * Further signers. Their signatures join the first signer's in
   * `signatures`; the first signer's stays the top-level signature that
   * v0.7 clients check.
   */
  readonly additionalSigners?: readonly KeyedSigner[];
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
export function replaceFile(path: string, content: string): void {
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
    verifyThreshold(
      bytes,
      JSON.parse(readFileSync(`${path}.sig`, "utf8")) as unknown,
      accepted,
      1,
    );
  } catch (error) {
    throw refuse(
      `does not verify: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return metadata;
}

/** The channel trust a release declares, as its clients will check it. */
interface DeclaredTrust {
  readonly label: string;
  readonly keys: readonly TrustedKey[];
  readonly threshold: number;
  /** v1alpha4 keys: a v0.7 client checks only the top-level signature. */
  readonly legacy: boolean;
}

/**
 * The channel role a release's clients trust today: the newest root in the
 * channel directory's `root/` reached from the lock's bootstrap (each
 * transition verified as a client would), or the v1alpha4 keys.
 */
async function declaredTrust(
  directory: string,
  lock: VerifiedRelease["lock"],
  distribution: string,
  now: Date,
): Promise<DeclaredTrust | undefined> {
  const trust = lock.updates?.trust;
  if (!trust) return undefined;
  if ("keys" in trust)
    return trust.keys.length
      ? {
          label: "the release's updates.trust.keys",
          keys: trust.keys,
          threshold: 1,
          legacy: true,
        }
      : undefined;
  if (!trust.bootstrap) return undefined;
  const { root } = await refreshRoot({
    source: directory,
    distribution,
    current: trust.bootstrap,
    accept: () => {},
  });
  if (rootExpired(root, now))
    throw new PiShipError(
      "CONFIG_INVALID",
      `Update root version ${root.version} expired at ${root.expires}; clients refuse any channel under it`,
      {
        userAction:
          "Publish the next root with a later expiry (piship trust-root next), then sign the channel",
      },
    );
  const role = roleTrust(root, "channel");
  return {
    label: `the channel role of update root ${root.version}`,
    keys: role.keys,
    threshold: role.threshold,
    legacy: false,
  };
}

interface ReadPack {
  readonly archive: string;
  readonly entry: ChannelPack;
  readonly lock: DistributionLock;
  readonly distribution: string;
  /** Where each pinned runtime archive was found, to be copied beside the channel. */
  readonly runtimeFiles: readonly string[];
}

/**
 * A Company Pack archive read and checked for the channel: it verifies as an
 * install would, and every runtime archive it pins is found, by name, in the
 * pack's directory, the channel directory, or `runtimes`, with the pinned
 * digest and size.
 */
async function readPack(
  archive: string,
  directory: string,
  runtimes: readonly string[],
): Promise<ReadPack> {
  // Imported here: the install modules import this package's index, which
  // imports the release modules.
  const { openPack } = await import("../install/compose.js");
  const scratch = createTemporaryDirectory(tmpdir(), "verify");
  try {
    const opened = await openPack(resolve(archive), scratch.path, undefined);
    const { metadata } = opened;
    const lock = JSON.parse(
      readFileSync(join(opened.directory, "pack", "piship.lock"), "utf8"),
    ) as DistributionLock;
    const places = [dirname(resolve(archive)), directory, ...runtimes];
    const refs: Record<string, ChannelPackRuntime> = {};
    const runtimeFiles: string[] = [];
    for (const [target, pinned] of Object.entries(metadata.runtime.archives)) {
      const found = places
        .map((place) =>
          existsSync(place) && statSync(place).isDirectory()
            ? join(place, pinned.name)
            : place,
        )
        .find((path) => basename(path) === pinned.name && existsSync(path));
      if (!found)
        throw new PiShipError(
          "CONFIG_INVALID",
          `The pack pins ${pinned.name} for ${target}, which was not found beside the pack, in the channel directory, or in --runtime`,
          {
            userAction: `Put ${pinned.name} next to the pack, or pass --runtime <path>`,
          },
        );
      if (
        (await sha256File(found)) !== pinned.sha256 ||
        statSync(found).size !== pinned.bytes
      )
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `${found} is not the ${pinned.name} the pack pins for ${target}`,
          { userAction: "Use the runtime archive the pack was built with" },
        );
      runtimeFiles.push(found);
      refs[target] = {
        archive: pinned.name,
        sha256: pinned.sha256,
        bytes: pinned.bytes,
      };
    }
    return {
      archive,
      lock,
      distribution: metadata.distribution.id,
      runtimeFiles,
      entry: {
        version: metadata.distribution.version,
        archive: basename(archive),
        sha256: await sha256File(archive),
        bytes: statSync(archive).size,
        pi: metadata.pi.version,
        piship: metadata.runtime.pishipVersion,
        lockSha256: metadata.lockSha256,
        runtimes: refs,
      },
    };
  } finally {
    scratch.remove();
  }
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
  const signers = [
    options.signer ??
      pemSigner({ keyId: options.keyId, privateKeyPem: options.privateKeyPem }),
    ...(options.additionalSigners ?? []),
  ];
  for (const signer of signers)
    accept({ id: signer.keyId, publicKey: signer.publicKey });
  for (const key of options.previousKeys ?? []) accept(key);
  const now = (options.now ?? (() => new Date()))();
  const directory = resolve(options.directory);
  const verified: { archive: string; release: VerifiedRelease }[] = [];
  const packs: ReadPack[] = [];
  const declared: DeclaredTrust[] = [];
  try {
    const declare = async (
      lock: DistributionLock,
      distribution: string,
    ): Promise<void> => {
      for (const key of channelTrustFromLock(lock)) accept(key);
      const trust = await declaredTrust(directory, lock, distribution, now);
      if (
        trust &&
        !declared.some((item) => canonicalJson(item) === canonicalJson(trust))
      ) {
        declared.push(trust);
        for (const key of trust.keys) accept(key);
      }
    };
    for (const archive of options.archives) {
      const release = await verifyRelease(archive);
      verified.push({ archive, release });
      await declare(release.lock, release.metadata.distribution.id);
    }
    for (const archive of options.packs ?? []) {
      const pack = await readPack(archive, directory, options.runtimes ?? []);
      packs.push(pack);
      await declare(pack.lock, pack.distribution);
    }
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
    const packEntries = new Map(
      (previous?.packs ?? []).map((item) => [item.version, item]),
    );
    let distribution = previous?.distribution;
    for (const id of [
      ...verified.map(({ release }) => release.metadata.distribution.id),
      ...packs.map((pack) => pack.distribution),
    ]) {
      if (distribution && distribution !== id)
        throw new PiShipError(
          "CONFIG_INVALID",
          `Channel ${options.channel} belongs to ${distribution}, not ${id}`,
        );
      distribution = id;
    }
    if (!distribution)
      throw new PiShipError(
        "CONFIG_INVALID",
        "No release or pack archives were given",
      );
    for (const pack of packs) packEntries.set(pack.entry.version, pack.entry);
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
      ...(packEntries.size
        ? {
            packs: [...packEntries.values()].sort((a, b) =>
              a.version.localeCompare(b.version),
            ),
          }
        : {}),
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
    const signed: SignatureEntry[] = [];
    for (const signer of signers)
      signed.push(await signVerified(signer, Buffer.from(text)));
    const signature = buildSignatureEnvelope(signed);
    // The signatures must satisfy the trust the releases declare, as their
    // clients will check it; otherwise nothing is published.
    for (const trust of declared)
      try {
        if (trust.legacy)
          verifySignature(Buffer.from(text), signature, trust.keys);
        else
          verifyThreshold(
            Buffer.from(text),
            signature,
            trust.keys,
            trust.threshold,
          );
      } catch (error) {
        throw new PiShipError(
          "INTEGRITY_FAILED",
          `The signing keys do not satisfy ${trust.label}: ${error instanceof Error ? error.message : String(error)}; nothing was written`,
          {
            userAction: trust.legacy
              ? "Sign with a key the release pins in updates.trust.keys as the first --key"
              : "Sign with enough keys of the current root's channel role (piship trust-root next changes the role)",
          },
        );
      }
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
    for (const pack of packs) {
      const files = [
        { path: pack.archive, sha256: pack.entry.sha256 },
        ...pack.runtimeFiles.map((path) => ({
          path,
          sha256: Object.values(pack.entry.runtimes).find(
            (runtime) => runtime.archive === basename(path),
          )?.sha256,
        })),
      ];
      for (const { path, sha256 } of files) {
        const destination = join(directory, basename(path));
        if (resolve(path) !== destination) copyFileSync(path, destination);
        if ((await sha256File(destination)) !== sha256)
          throw new PiShipError(
            "INTEGRITY_FAILED",
            `${path} changed while the channel was being signed`,
          );
      }
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
    /** Distinct `trusted` keys whose signatures are required; default 1. */
    readonly threshold?: number;
    readonly minSequence?: number;
    readonly now?: () => Date;
    readonly fetcher?: typeof fetch;
    /** The installation's `updates.transport`; absent admits plain HTTP to a private host. */
    readonly transport?: UpdateTransport;
  },
): Promise<{
  readonly metadata: ChannelMetadata;
  /** The first key whose signature counted. */
  readonly keyId: string;
  /** Every key whose signature counted toward the threshold. */
  readonly keyIds: readonly string[];
}> {
  const answer: { date?: number } = {};
  const bytes = await readSourceFile(
    source,
    `${channel}.json`,
    options.fetcher,
    answer,
    options.transport,
  );
  const signature = await readSourceFile(
    source,
    `${channel}.json.sig`,
    options.fetcher,
    undefined,
    options.transport,
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
  const keyIds = verifyThreshold(
    bytes,
    envelope,
    trusted,
    options.threshold ?? 1,
  );
  const keyId = keyIds[0] as string;
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
  return { metadata, keyId, keyIds };
}
