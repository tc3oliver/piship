# Credentials

`@piship/credentials` obtains, stores, refreshes, and revokes the runtime credential used for inference. It receives an identity session only as input and hands inference only a non-secret `CredentialRef` plus a request-time secret.

## Contracts

```ts
interface CredentialProvider {
  readonly mode: "http-broker" | "local-secret" | "pi-native" | "none" | "adapter";
  readonly requiresIdentity: boolean;
  acquire(identity: IdentitySession | null, ctx: CredentialContext): Promise<RuntimeCredential | null>;
  refresh?(identity: IdentitySession | null, current: RuntimeCredential, ctx: CredentialContext): Promise<RuntimeCredential>;
  revoke?(credential: RuntimeCredential, ctx: CredentialContext): Promise<void>;
}

interface SecretStore {
  readonly kind: string;
  readonly description: string;
  put(ref: string, value: SecretValue): Promise<void>;
  get(ref: string): Promise<SecretValue | null>;
  delete(ref: string): Promise<void>;
}
```

A `RuntimeCredential` has `kind` (`api_key`, `bearer`, or `opaque`), a `SecretValue`, and optional `expiresAt`, `credentialId`, and metadata such as entitled `models` and `baseUrl`.

## Modes

| `credential.provider` | Behavior | Allowed in |
| --- | --- | --- |
| `http-broker` | Organization broker issues a scoped credential for the signed-in user | Managed, personal with identity |
| `adapter` | Packaged module that default-exports a `CredentialProvider` factory | Managed, personal |
| `local-secret` | User-owned key entered at `login`, stored in the secret store; no expiry or remote revocation | Personal |
| `none` | The endpoint needs no credential. PiShip sends the non-secret placeholder bearer `piship-no-credential` | Personal |
| `pi-native` | Explicit delegation to Pi's own auth in isolated state. PiShip does not read, copy, or store it; use Pi's `/login` in the session | Personal |

## http-broker protocol

Acquire and refresh:

```http
POST <credential.broker.endpoint>
Authorization: Bearer <identity access token>
Content-Type: application/json

{"distribution": "<app id>", "purpose": "inference"}
```

A 2xx response must be JSON:

| Field | Required | Meaning |
| --- | --- | --- |
| `credential_type` | yes | `api_key`, `bearer`, or `opaque` |
| `credential` | yes | The secret, at least 8 characters |
| `credential_id` | no | Non-secret identifier, used for display and revocation |
| `expires_at` | no | ISO 8601 time; an already expired credential is rejected |
| `models` | no | Entitled model IDs; narrows the catalog |
| `base_url` | no | Must match the declared `inference.baseUrl` |

Revocation, when `revokeEndpoint` is declared:

```http
POST <credential.broker.revokeEndpoint>
Authorization: Bearer <runtime credential>
Content-Type: application/json

{"credential_id": "<id or null>", "distribution": "<app id>"}
```

A 401 or 404 from the revoke endpoint counts as already revoked. Broker responses are never logged or echoed in errors.

| Broker response | Result |
| --- | --- |
| 401 | `IDENTITY_EXPIRED`; PiShip refreshes the identity once and retries |
| 403 | `CREDENTIAL_ACQUIRE_FAILED`: user or distribution denied |
| 429 | `CREDENTIAL_ACQUIRE_FAILED`, retryable, with `Retry-After` when present |
| Other 3xx, 4xx, or 5xx | `CREDENTIAL_ACQUIRE_FAILED`; retryable for 5xx |
| Malformed body, undeclared `base_url` | `CREDENTIAL_ACQUIRE_FAILED` |

## Secret stores

| Store | Mechanism |
| --- | --- |
| macOS Keychain | `/usr/bin/security`; the secret is written in interactive (`-i`) mode on standard input |
| Linux Secret Service | `secret-tool` (libsecret); the secret is passed on standard input |
| Windows Credential Manager | PowerShell calling `advapi32` `CredWrite`/`CredRead`/`CredDelete`; the secret is passed on standard input |
| File (explicit opt-in) | One file per reference under `<state>/secrets/`, 0700 directory and 0600 files, written through a temporary file and atomic rename. Values are base64url-encoded, not encrypted. On Windows the directory gets an owner-only ACL (`icacls /inheritance:r /grant:r <user>:(OI)(CI)F`); if it cannot be applied, the store fails with `SECRET_STORE_UNAVAILABLE` |

The macOS and Windows stores limit the size of one item, so values larger than one item (OIDC token bundles can reach several KB) are split across part items named `<ref>+<n>`, and the primary item records the part count. Replacing or deleting a value also removes its parts.

`storage.provider: system` selects the store for the current platform and never falls back to a file. A failing store raises `SECRET_STORE_UNAVAILABLE` with guidance to unlock or install the platform store or opt in to the file fallback. Managed manifests must set `acknowledgePlaintext: true` for the file store.

## Lifecycle

`CredentialManager` keeps one runtime credential per distribution:

- Metadata in `credentials-metadata/inference.json` (`piship-credential-metadata/v1`) holds a generation reference such as `piship:<id>:inference#3`, the kind, credential ID, expiry, acquisition time, entitled models, and base URL. It never holds the secret.
- Replacement is crash-safe: the new secret is written under the next generation before metadata switches to it, then older generations are deleted. A crash leaves metadata pointing at the previous or the new complete credential; references that could not be deleted are retried later.
- A credential is refreshed when it is within `refresh.beforeExpiry` of expiry. If refresh fails while the credential is still valid, PiShip continues with a notice. An expired credential that cannot be renewed fails closed with `CREDENTIAL_EXPIRED`.
- A gateway rejection of a broker or adapter credential marks the metadata `rejected_at`, so this and later processes renew before reuse. If renewal fails, the result is `CREDENTIAL_REVOKED`, except that specific codes such as `IDENTITY_EXPIRED` or `NETWORK_DENIED` are kept. A rejected `local-secret` cannot be renewed automatically, so it is left in place and the launch fails with `CREDENTIAL_REVOKED` and guidance to replace it with `login`.
- Refreshes are serialized within a process and across processes by a lock file beside the metadata, so concurrent launches share one renewal instead of racing. A lock older than two minutes is treated as abandoned.
- Metadata from an incompatible version, or metadata whose secret is missing, is cleared rather than reused, together with every secret it references, and the user must sign in again.
- `logout` revokes when supported, then deletes the current, orphaned, and possibly pending next-generation secrets and the metadata. The revocation outcome is audited as `credential.revoke` (`revoked`, `failed`, `unsupported`, or `skipped`), and `login` revokes the credential it replaces. `credential.acquire` is recorded only for a new acquisition, and renewals as `credential.refresh`.
- When update, rollback, or migration must clear a credential the target cannot read, the switching release first revokes it where supported (best effort; a failure is a warning), then deletes every reference, including orphaned and pending generations.
- A credential adapter that requires an identity is rejected with `CONFIG_INVALID` under `identity.mode: none`.

Launches acquire a broker or adapter credential automatically after `login`. `local-secret` is captured only by `login`; without it a launch fails with `CREDENTIAL_REQUIRED`. `login` always replaces the current runtime credential.

See [inference](inference.md#failure-policy) for the combined failure policy.
