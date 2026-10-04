// Owner tooling for update roots: the bootstrap a manifest pins, and the
// next signed root version an update source publishes. Owners never
// hand-edit signed root JSON.
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import {
  AccessFieldError,
  parseUpdateRoot,
  PISHIP_SCHEMA_V1ALPHA5,
  PISHIP_SCHEMA_V1ALPHA6,
  readManifest,
  sharedRoleKeyIds,
  type UpdateRoot,
} from "@piship/schema";
import {
  buildSignatureEnvelope,
  type KeyedSigner,
  keyFingerprint,
  type SignatureEntry,
  signVerified,
  type TrustedKey,
} from "../signing.js";
import { replaceFile } from "./channel.js";
import {
  hostedRootText,
  refreshRoot,
  rootFileName,
  verifyRootTransition,
} from "./root.js";

function invalid(message: string, userAction?: string): PiShipError {
  return new PiShipError("CONFIG_INVALID", message, {
    component: "trust-root",
    ...(userAction ? { userAction } : {}),
  });
}

function parseRoot(body: unknown, path: string): UpdateRoot {
  try {
    return parseUpdateRoot(body, path);
  } catch (error) {
    if (error instanceof AccessFieldError)
      throw invalid(`${error.field}: ${error.message}`);
    throw error;
  }
}

/** An expiry from `expires` (a UTC timestamp) or `expiresDays` after now. */
export function rootExpiry(
  options: { readonly expires?: string; readonly expiresDays?: number },
  now: Date,
): string {
  if ((options.expires === undefined) === (options.expiresDays === undefined))
    throw invalid("Give the root's expiry with --expires or --expires-days");
  const expires =
    options.expires ??
    `${new Date(now.getTime() + (options.expiresDays as number) * 86_400_000).toISOString().slice(0, 19)}Z`;
  if (!(Date.parse(expires) > now.getTime()))
    throw invalid(`Root expiry ${expires} is not in the future`);
  return expires;
}

export interface TrustRootDescription {
  readonly root: UpdateRoot;
  /** The `updates:` YAML block a piship/v1alpha5 manifest pins. */
  readonly yaml: string;
  readonly fingerprints: readonly { id: string; fingerprint: string }[];
  readonly warnings: readonly string[];
}

/** The `updates.trust.bootstrap` YAML of a root, under `updates:`. */
export function bootstrapYaml(root: UpdateRoot): string {
  const role = (name: "root" | "channel") =>
    `        ${name}:\n          keyIds: [${root.roles[name].keyIds.join(", ")}]\n          threshold: ${root.roles[name].threshold}\n`;
  return `updates:\n  trust:\n    bootstrap:\n      version: ${root.version}\n      expires: ${root.expires}\n      keys:\n${root.keys
    .map(
      (key) =>
        `        - id: ${key.id}\n          publicKey: ${key.publicKey}\n`,
    )
    .join("")}      roles:\n${role("root")}${role("channel")}`;
}

/** Describe a root: its manifest YAML, key fingerprints, and warnings. */
export function describeTrustRoot(root: UpdateRoot): TrustRootDescription {
  const shared = sharedRoleKeyIds(root);
  return {
    root,
    yaml: bootstrapYaml(root),
    fingerprints: root.keys.map((key) => ({
      id: key.id,
      fingerprint: keyFingerprint(key.publicKey),
    })),
    warnings: shared.length
      ? [
          `The root and channel roles share ${shared.join(", ")}; a managed distribution needs distinct root and channel keys, and piship release refuses it`,
        ]
      : [],
  };
}

/**
 * Bootstrap root material from public keys: a validated root (version 1 by
 * default) and the manifest YAML that pins it.
 */
export function initTrustRoot(options: {
  readonly keys: readonly TrustedKey[];
  readonly rootKeyIds: readonly string[];
  readonly channelKeyIds: readonly string[];
  readonly rootThreshold?: number;
  readonly channelThreshold?: number;
  readonly expires?: string;
  readonly expiresDays?: number;
  readonly version?: number;
  readonly now?: () => Date;
}): TrustRootDescription {
  const now = (options.now ?? (() => new Date()))();
  return describeTrustRoot(
    parseRoot(
      {
        version: options.version ?? 1,
        expires: rootExpiry(options, now),
        keys: options.keys.map((key) => ({
          id: key.id,
          publicKey: key.publicKey,
        })),
        roles: {
          root: {
            keyIds: options.rootKeyIds,
            threshold: options.rootThreshold ?? 1,
          },
          channel: {
            keyIds: options.channelKeyIds,
            threshold: options.channelThreshold ?? 1,
          },
        },
      },
      "bootstrap",
    ),
  );
}

export interface TrustRootNextOptions {
  /** The update source directory; roots live in its `root/`. */
  readonly repository: string;
  /** The piship/v1alpha5 manifest whose bootstrap the chain starts from. */
  readonly manifest: string;
  readonly addKeys?: readonly TrustedKey[];
  /** Key ids to drop; they leave every role too. */
  readonly removeKeys?: readonly string[];
  readonly rootKeyIds?: readonly string[];
  readonly rootThreshold?: number;
  readonly channelKeyIds?: readonly string[];
  readonly channelThreshold?: number;
  readonly expires?: string;
  readonly expiresDays?: number;
  /** Every key whose signature the transition needs, collected at once. */
  readonly signers: readonly KeyedSigner[];
  readonly now?: () => Date;
}

export interface TrustRootNextResult {
  readonly path: string;
  readonly previous: UpdateRoot;
  readonly root: UpdateRoot;
  readonly signedBy: readonly string[];
}

/**
 * Publish root N+1: verify the chain from the manifest's bootstrap through
 * the repository's `root/` to the current root N, build N+1 with the asked
 * key and role changes, sign it with every signer (each signature checked
 * against the signer's public key), require the signatures to meet both
 * N's and N+1's root-role thresholds, and only then write
 * `root/<N+1>.json.sig` and `root/<N+1>.json`, each through a temporary file
 * and a rename (the signature first, so a client never finds the metadata
 * without it). A failing signer or an unmet threshold writes nothing.
 */
export async function nextTrustRoot(
  options: TrustRootNextOptions,
): Promise<TrustRootNextResult> {
  const now = (options.now ?? (() => new Date()))();
  const manifest = readManifest(options.manifest);
  const updates = manifest.lifecycle?.updates;
  const bootstrap =
    (manifest.schema === PISHIP_SCHEMA_V1ALPHA5 ||
      manifest.schema === PISHIP_SCHEMA_V1ALPHA6) &&
    updates &&
    "bootstrap" in updates.trust
      ? updates.trust.bootstrap
      : undefined;
  if (!bootstrap)
    throw invalid(
      `${options.manifest} pins no updates.trust.bootstrap; root versions extend a piship/v1alpha5 bootstrap root`,
      "Add one with piship trust-root init, or run piship migrate on a v1alpha4 manifest",
    );
  const distribution = manifest.app.id;
  const repository = resolve(options.repository);
  const { root: current } = await refreshRoot({
    source: repository,
    distribution,
    current: bootstrap,
    accept: () => {},
  });
  const removed = options.removeKeys ?? [];
  for (const id of removed)
    if (!current.keys.some((key) => key.id === id))
      throw invalid(`Root ${current.version} lists no key ${id} to remove`);
  const keys = [
    ...current.keys.filter((key) => !removed.includes(key.id)),
    ...(options.addKeys ?? []).map((key) => ({
      id: key.id,
      publicKey: key.publicKey,
    })),
  ];
  const role = (name: "root" | "channel") => ({
    keyIds:
      (name === "root" ? options.rootKeyIds : options.channelKeyIds) ??
      current.roles[name].keyIds.filter((id) => !removed.includes(id)),
    threshold:
      (name === "root" ? options.rootThreshold : options.channelThreshold) ??
      current.roles[name].threshold,
  });
  const next = parseRoot(
    {
      version: current.version + 1,
      expires: rootExpiry(options, now),
      keys,
      roles: { root: role("root"), channel: role("channel") },
    },
    `root ${current.version + 1}`,
  );
  if (!options.signers.length)
    throw invalid("Give the keys that sign the new root with --sign");
  const text = hostedRootText(distribution, next);
  const bytes = Buffer.from(text);
  const signed: SignatureEntry[] = [];
  for (const signer of options.signers)
    signed.push(await signVerified(signer, bytes));
  const envelope = buildSignatureEnvelope(signed);
  try {
    verifyRootTransition(bytes, envelope, current, next);
  } catch (error) {
    throw new PiShipError(
      "INTEGRITY_FAILED",
      `${error instanceof Error ? error.message : String(error)}; nothing was written`,
      {
        component: "trust-root",
        userAction: `Sign with root keys meeting both thresholds: root ${current.version} needs ${current.roles.root.threshold} of ${current.roles.root.keyIds.join(", ")}; root ${next.version} needs ${next.roles.root.threshold} of ${next.roles.root.keyIds.join(", ")}`,
      },
    );
  }
  const path = join(repository, rootFileName(next.version));
  // A signature without its metadata is an interrupted earlier run that no
  // client can use (the metadata is absent); it is replaced.
  if (existsSync(path))
    throw invalid(
      `${path} already exists; refusing to replace a published root version`,
    );
  mkdirSync(dirname(path), { recursive: true });
  replaceFile(`${path}.sig`, `${JSON.stringify(envelope, null, 2)}\n`);
  replaceFile(path, text);
  return {
    path,
    previous: current,
    root: next,
    signedBy: signed.map((entry) => entry.keyId),
  };
}
