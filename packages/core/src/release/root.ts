// Hosted update root metadata (`piship-update-root/v1`) and the bounded,
// sequential root refresh a client runs before it trusts a channel.
import { PiShipError } from "@piship/contracts";
import {
  AccessFieldError,
  parseUpdateRoot,
  type UpdateRoot,
  type UpdateRoleName,
  updateRoleKeys,
} from "@piship/schema";
import { digest } from "../digest.js";
import { type TrustedKey, verifyThreshold } from "../signing.js";
import { readOptionalSourceFile } from "./source.js";

export const ROOT_SCHEMA = "piship-update-root/v1";
/** Largest root metadata file a refresh reads. */
export const MAX_ROOT_BYTES = 64 * 1024;
/** Largest root signature envelope a refresh reads. */
export const MAX_ROOT_SIGNATURE_BYTES = 64 * 1024;
/** Most root transitions one update attempt accepts. */
export const MAX_ROOT_TRANSITIONS = 64;

function integrity(message: string, userAction?: string): PiShipError {
  return new PiShipError("INTEGRITY_FAILED", message, {
    component: "update",
    ...(userAction ? { userAction } : {}),
  });
}

/** Path of root version `version` under an update source. */
export function rootFileName(version: number): string {
  return `root/${version}.json`;
}

/** The canonical `sha256-<hex>` digest of a root body. */
export function rootDigest(root: UpdateRoot): string {
  return digest(root);
}

/** A role's keys and threshold, as `verifyThreshold` takes them. */
export function roleTrust(
  root: UpdateRoot,
  role: UpdateRoleName,
): { readonly keys: TrustedKey[]; readonly threshold: number } {
  return {
    keys: updateRoleKeys(root, role),
    threshold: root.roles[role].threshold,
  };
}

/** The published text of a root: schema, distribution, then the root body. */
export function hostedRootText(distribution: string, root: UpdateRoot): string {
  return `${JSON.stringify(
    {
      schema: ROOT_SCHEMA,
      distribution,
      version: root.version,
      expires: root.expires,
      keys: root.keys,
      roles: root.roles,
    },
    null,
    2,
  )}\n`;
}

/**
 * Parse hosted root metadata bytes: `piship-update-root/v1` for
 * `distribution`, with a valid root body. Throws INTEGRITY_FAILED.
 */
export function parseHostedRoot(
  bytes: Uint8Array,
  distribution: string,
  name = "Root metadata",
): UpdateRoot {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    throw integrity(`${name} is not valid JSON`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw integrity(`${name} is not an object`);
  const doc = value as Record<string, unknown>;
  if (doc.schema !== ROOT_SCHEMA)
    throw integrity(
      `${name} has schema ${String(doc.schema)}, not ${ROOT_SCHEMA}`,
    );
  if (doc.distribution !== distribution)
    throw integrity(
      `${name} is for ${String(doc.distribution)}, not ${distribution}`,
    );
  try {
    return parseUpdateRoot(value, "root", ["schema", "distribution"]);
  } catch (error) {
    throw integrity(
      `${name} is invalid: ${error instanceof AccessFieldError ? `${error.field}: ` : ""}${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Check that `next` may follow `current`: version exactly one higher, and
 * signatures over `bytes` meeting both the current and the new root role
 * thresholds (each key counts once per threshold).
 */
export function verifyRootTransition(
  bytes: Uint8Array,
  envelope: unknown,
  current: UpdateRoot,
  next: UpdateRoot,
): void {
  if (next.version !== current.version + 1)
    throw integrity(
      `Root version ${next.version} cannot follow trusted root ${current.version}; only version ${current.version + 1} can`,
    );
  for (const [root, which] of [
    [current, "trusted"],
    [next, "new"],
  ] as const) {
    const role = roleTrust(root, "root");
    try {
      verifyThreshold(bytes, envelope, role.keys, role.threshold);
    } catch (error) {
      throw integrity(
        `Root ${next.version} is not signed by the root role of the ${which} root ${root.version}: ${error instanceof Error ? error.message : String(error)}`,
        "Do not trust it; ask the distribution owner to publish root metadata signed by both the current and the new root keys (piship trust-root next)",
      );
    }
  }
}

/** Whether `root` has expired at `time`. */
export function rootExpired(root: UpdateRoot, time: Date): boolean {
  return !(Date.parse(root.expires) > time.getTime());
}

/**
 * Root refresh: starting from the trusted `current` root N, fetch
 * `root/N+1.json` and its signature, verify it, hand it to `accept` (which
 * persists it before anything else happens), and repeat. Only a source that
 * reports `root/N+1.json` as absent ends the refresh; any other failure
 * throws, so an update never proceeds to the channel on an unknown root.
 * Expiry is not checked here: an expired root may still authenticate its
 * successor; the caller checks the final root at its fixed update time.
 */
export async function refreshRoot(options: {
  readonly source: string;
  readonly distribution: string;
  readonly current: UpdateRoot;
  readonly accept: (root: UpdateRoot) => void;
  readonly fetcher?: typeof fetch;
}): Promise<{ readonly root: UpdateRoot; readonly transitions: number }> {
  let current = options.current;
  let transitions = 0;
  for (;;) {
    const version = current.version + 1;
    const name = rootFileName(version);
    const bytes = await readOptionalSourceFile(
      options.source,
      name,
      MAX_ROOT_BYTES,
      options.fetcher,
    );
    if (!bytes) return { root: current, transitions };
    if (transitions >= MAX_ROOT_TRANSITIONS)
      throw new PiShipError(
        "UPDATE_FAILED",
        `The update source has more than ${MAX_ROOT_TRANSITIONS} new root versions; accepted ${transitions} (now at root ${current.version}) and stopped before checking the channel`,
        {
          component: "update",
          retryable: true,
          userAction: "Run update again to continue from the accepted root",
        },
      );
    const signature = await readOptionalSourceFile(
      options.source,
      `${name}.sig`,
      MAX_ROOT_SIGNATURE_BYTES,
      options.fetcher,
    );
    if (!signature)
      throw integrity(
        `Update source has ${name} but no ${name}.sig; refusing to continue without verifying it`,
      );
    let envelope: unknown;
    try {
      envelope = JSON.parse(signature.toString("utf8"));
    } catch {
      throw integrity(`${name}.sig is not valid JSON`);
    }
    const next = parseHostedRoot(bytes, options.distribution, name);
    if (next.version !== version)
      throw integrity(`${name} records version ${next.version}`);
    verifyRootTransition(bytes, envelope, current, next);
    options.accept(next);
    current = next;
    transitions += 1;
  }
}
