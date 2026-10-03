// The piship/v1alpha5 update trust an owner pins in an example manifest: an
// offline root key and the release key that signs channels, each in a role
// of its own (a managed release refuses a key shared by both roles).
import { createPrivateKey, createPublicKey } from "node:crypto";

/** PKCS#8 DER prefix of an Ed25519 private key; a 32-byte seed follows. */
const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";

/**
 * A fixed root public key: the tests never sign root metadata, so every
 * build pins the same one and the releases of a fixture agree.
 */
export const ROOT_KEY = {
  id: "acme-root-e2e",
  publicKey: createPublicKey(
    createPrivateKey({
      key: Buffer.from(`${ED25519_PKCS8_PREFIX}${"11".repeat(32)}`, "hex"),
      format: "der",
      type: "pkcs8",
    }),
  )
    .export({ type: "spki", format: "der" })
    .toString("base64"),
} as const;

/**
 * `updates.trust` YAML (two-space indented under `updates:`) with a bootstrap
 * root whose root role is ROOT_KEY and whose channel role is `channel`.
 */
export function bootstrapTrust(channel: {
  readonly id: string;
  readonly publicKey: string;
}): string {
  return `  trust:
    bootstrap:
      version: 1
      expires: 2099-01-01T00:00:00Z
      keys:
        - id: ${ROOT_KEY.id}
          publicKey: ${ROOT_KEY.publicKey}
        - id: ${channel.id}
          publicKey: ${channel.publicKey}
      roles:
        root: { keyIds: [${ROOT_KEY.id}], threshold: 1 }
        channel: { keyIds: [${channel.id}], threshold: 1 }
`;
}
