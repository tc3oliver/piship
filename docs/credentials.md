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

A `RuntimeCredential` has `kind` (`api_key`, `bearer`, or `opaque`), a `SecretValue`, and optional `expiresAt`, `credentialId`, and metadata such as entitled `models` and `baseUrl`. A `credentialId` is 1 to 256 letters, digits, `.`, `_`, `:`, or `-` whichever provider issues it (it reaches notices, audit events, and `doctor`); any other value fails the acquire with `CREDENTIAL_ACQUIRE_FAILED`.

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
Idempotency-Key: <random UUID, one per logical acquire>

{"distribution": "<app id>", "purpose": "inference"}
```

`Idempotency-Key` comes from `CredentialContext.idempotencyKey`. `CredentialManager` generates a random UUID for each acquire or renewal it sends, unless the caller passes a key; a caller retrying the same acquire passes the key from the failure's `detail.idempotencyKey`. A key must be 1 to 255 visible ASCII characters without spaces, or the acquire fails with `reason: contract` before anything is sent. A provider called directly without a key sends no header. What a broker does with the key, and which failures are safe to retry, is in the [enterprise integration contract](enterprise-integration.md#idempotency-and-retries).

A 2xx response must be JSON:

| Field | Required | Meaning |
| --- | --- | --- |
| `credential_type` | yes | `api_key`, `bearer`, or `opaque` |
| `credential` | yes | The secret, at least 8 characters, visible ASCII only (it is sent in a header) |
| `credential_id` | no | Non-secret identifier, used for display and revocation: 1 to 256 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, and `-` |
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

Acquire and revoke share one transport. Each call has a 30 s timeout (`timeoutMs`) that covers the response body; a caller's `CredentialContext.signal` can cancel it sooner but never removes the timeout. Nothing is retried automatically.

| Broker outcome | Acquire and refresh | Revoke | `retryable` | `detail.reason` |
| --- | --- | --- | --- | --- |
| 401 | `IDENTITY_EXPIRED`; PiShip refreshes the identity once and retries | Counts as revoked | no | `authentication` |
| 403 | `CREDENTIAL_DENIED`: user or distribution denied | `CREDENTIAL_DENIED` | no | `denied` |
| 404 | `CREDENTIAL_ACQUIRE_FAILED` | Counts as revoked | no | `rejected` |
| 409 or 422 to an acquire that sent a key | `CREDENTIAL_ACQUIRE_FAILED`: the key was used for a different request | (no key sent) | no | `idempotency-conflict` |
| 429 | `CREDENTIAL_ACQUIRE_FAILED` | `CREDENTIAL_REVOKED` | yes, with `Retry-After` | `rate-limited` |
| 5xx, including a proxy's HTML error page | `CREDENTIAL_ACQUIRE_FAILED` | `CREDENTIAL_REVOKED` | yes, with `Retry-After` when sent | `unavailable` |
| Other 3xx or 4xx | `CREDENTIAL_ACQUIRE_FAILED` | `CREDENTIAL_REVOKED` | no | `rejected` |
| 2xx with a malformed body, contract violation, undeclared `base_url` | `CREDENTIAL_ACQUIRE_FAILED` | (body not read) | no | `contract` |
| No answer within the timeout | `CREDENTIAL_ACQUIRE_FAILED` | `CREDENTIAL_REVOKED` | yes | `timeout` |
| Unreachable (connection failure) | `CREDENTIAL_ACQUIRE_FAILED` | `CREDENTIAL_REVOKED` | yes | `unreachable` |
| Cancelled by the caller's signal | `CREDENTIAL_ACQUIRE_FAILED` | `CREDENTIAL_REVOKED` | no | `cancelled` |
| Network or TLS policy refusal | `NETWORK_DENIED` or `TLS_POLICY_VIOLATION` | same | no | none |

`Retry-After` (seconds or HTTP date) becomes `retryAfterMs` and is shown as `Retry after: <n> s`. The error's `detail` holds only non-secret fields: `operation` (`acquire` or `revoke`), `reason`, `status` when the broker answered, `idempotencyKey` on an acquire that sent one, and, for `timeout`, `unreachable`, and `cancelled`, `outcome`: `not-sent` when the request never left PiShip (connection refused, DNS failure, connect timeout, an already cancelled signal), `unknown` when the broker may have received it and issued a credential. Nothing is re-sent after an `unknown` outcome; retry the same acquire with the same key. Error messages, actions, and details never contain the identity token, the runtime credential, or the broker's response body. A revoke failure is reported as a warning and never keeps the local secret.

## Secret stores

| Store | Mechanism |
| --- | --- |
| macOS Keychain | `/usr/bin/security`; the secret is written in interactive (`-i`) mode on standard input |
| Linux Secret Service | `secret-tool` (libsecret); the secret is passed on standard input |
| Windows Credential Manager | PowerShell calling `advapi32` `CredWrite`/`CredRead`/`CredDelete`; the secret is passed on standard input |
| File (explicit opt-in) | One file per reference under `<state>/secrets/`, 0700 directory and 0600 files, written through a temporary file and atomic rename; a temporary a killed writer left is removed by `logout` and when the distribution next starts. Values are base64url-encoded, not encrypted. On Windows the directory gets an owner-only ACL (`icacls /inheritance:r /grant:r <user>:(OI)(CI)F`); if it cannot be applied, the store fails with `SECRET_STORE_UNAVAILABLE` |

The macOS, Windows, and Linux Secret Service stores limit the size of one item (`secret-tool` keeps only the first 8192 bytes of standard input and still exits successfully, so the Linux store splits a value above 8000 characters), so values larger than one item (OIDC token bundles can reach several KB) are split across part items named `<ref>+<n>`, and the primary item records the part count. Replacing or deleting a value also removes its parts. On Linux each part also carries its primary's reference as a `parent` attribute, so a write that fails halfway leaves no part behind, a value with a missing or extra part is refused instead of read, and deleting a value clears its parts by that attribute and reports an error if anything is still stored. Each part also carries the random id of the write that made it, which the primary item records, so two writers of one value can never leave a mix of their parts. A locked keyring is an error, not an absent secret: `secret-tool lookup` answers a locked keyring exactly as it answers a missing item, so a miss is confirmed with `secret-tool search`, and an item that exists makes the read or the delete fail with a message to unlock the keyring.

Credential and identity metadata, and their discarded markers, record which store holds their references (`secret_store`: `file` or `system`). A release never looks a reference up in a store other than the one recorded: metadata recorded for the other store (state left by a release with the other `storage.provider`, without the switch below) is never used; the runtime credential is revoked where supported and every reference is deleted from the recorded store, confirmed, and the user signs in again (`The credential stored in the <old> secret store was deleted from it: this distribution now stores credentials in the <new> store. A new credential is required`). While that store is not available, the references stay listed in a discarded marker that records it, and the command fails closed with `SECRET_STORE_UNAVAILABLE`. Changing `storage.provider` in an update or rollback clears both classes from the old store before the switch ([update lifecycle](release/update-lifecycle.md#migration-check-and-local-data)). Metadata written before the store was recorded is taken to belong to the configured store; a storage change that an earlier release switched without clearing cannot be recognized from it, so run `logout` before such an update.

`storage.provider: system` selects the store for the current platform and never falls back to a file. A failing store raises `SECRET_STORE_UNAVAILABLE` with guidance to unlock or install the platform store or opt in to the file fallback. Managed manifests must set `acknowledgePlaintext: true` for the file store.

### Headless runs

A [workload identity](identity.md#workload-identity-headless-runs) is never stored, but the runtime credential is, in the configured store, so that later runs reuse it until it needs renewal. Which store works depends on the runner:

| Runner | `storage.provider: system` | `storage.provider: file` with `acknowledgePlaintext: true` |
| --- | --- | --- |
| macOS | Not qualified for a headless job (the headless E2E uses the file store); it works only where the job can use an unlocked keychain | Works |
| Windows | Not qualified for a headless job (the headless E2E uses the file store); expected to work when the job runs with a user profile | Works |
| Linux with an unlocked Secret Service (a desktop session, or `gnome-keyring-daemon` started in the job) | Works | Works |
| Linux without a Secret Service (most containers and CI runners) | Fails closed with `SECRET_STORE_UNAVAILABLE` | Works: plaintext at rest under `<state>/secrets/`, 0600, deleted on renewal and `logout` |

The headless E2E uses the file store on every target.

There is no memory-only option yet: a headless Linux runner without a Secret Service must accept the plaintext file store or fail. Keep its state directory on storage private to the job and discard it with the job, prefer short-lived broker credentials, and run `logout` at the end of the job so the credential is revoked where the broker supports it.

## Lifecycle

`CredentialManager` keeps one runtime credential per distribution:

- Metadata in `credentials-metadata/inference.json` (`piship-credential-metadata/v1`) holds a generation reference such as `piship:<id>:inference#3`, the kind, credential ID, expiry, acquisition time, entitled models, base URL, and the principal (issuer and subject) the credential was issued to. It never holds the secret.
- A credential, and the entitlement in its metadata, is used only by the principal it was issued to. Before any use, the bound principal is compared with the signed-in identity (no identity matches only a credential issued without one); on a mismatch, including metadata written before credentials were bound, the credential is revoked where supported (`credential.revoke` with reason `principal-change`, or `unbound` when the metadata records no principal), every secret it references is deleted, and a new one is acquired or the launch fails with `CREDENTIAL_REQUIRED`. It is never used.
- Every deletion is verified: after a delete, the store is read back, and a delete that fails, a secret that is still there, or a read that fails counts as not deleted, never as absent. Metadata whose secrets could not all be deleted is replaced by a discarded marker (`piship-credential-discarded/v1`) that lists only the references still to delete. No release reads the marker as a credential; the next launch or login deletes the secrets first and fails closed with `SECRET_STORE_UNAVAILABLE` while it cannot. A replaced generation whose deletion fails after a renewal stays listed in the metadata's `orphans`, is reported as a notice, and is retried by the next renewal, logout, or discard. Identity token bundles follow the same rule ([user switching](security.md#user-switching)).
- Replacement is crash-safe: the new secret is written under the next generation before metadata switches to it, then older generations are deleted. A crash leaves metadata pointing at the previous or the new complete credential; references that could not be deleted are retried later.
- A credential is refreshed when it is within `refresh.beforeExpiry` of expiry. If refresh fails while the credential is still valid, PiShip continues with a notice. An expired credential that cannot be renewed fails closed with `CREDENTIAL_EXPIRED`.
- A gateway rejection of a broker or adapter credential marks the metadata `rejected_at`, so this and later processes renew before reuse. If renewal fails, the result is `CREDENTIAL_REVOKED`, except that specific codes such as `IDENTITY_EXPIRED`, `CREDENTIAL_DENIED`, or `NETWORK_DENIED` are kept. A failed renewal, forced or on expiry, keeps the failure's `retryable`, `retryAfterMs`, and `detail`, so a broker outage or rate limit stays retryable. A rejected `local-secret` cannot be renewed automatically, so it is left in place and the launch fails with `CREDENTIAL_REVOKED` and guidance to replace it with `login`.
- The entitlement (`models`) is read only when a credential is acquired or renewed: at `login`, at a renewal before expiry, and after the gateway denies a model with 403, when `DistributionAccess.refreshEntitlement()` renews the credential once per credential generation through the refresh path (audited as `credential.refresh` with reason `entitlement`; a failure prints `Notice: the model entitlement could not be re-read: <error>` and keeps the current credential). A credential without `expires_at` is otherwise never renewed, so its entitlement stays as issued until one of these events. A re-read entitlement never widens the distribution allowlist; see [entitlement freshness](inference.md#entitlement-freshness).
- Refreshes are serialized within a process and across processes by a lock file beside the metadata, so concurrent launches share one renewal instead of racing. The holder writes a unique token into the lock and changes the lock's mtime as a heartbeat and before each blocking secret-store command. A waiter takes the lock over only after it has seen the same token with the same mtime for 75 s on the monotonic clock (moved aside atomically, then checked again): the holder made no progress, such as a crashed process. The mtime is only compared with what the waiter saw before, never with the wall clock, so a clock correction, a manual change, or a resumed VM never lets a waiter break a live holder's lock and never keeps an abandoned one forever. A lock whose content the waiter cannot read (a root-owned file a crashed `sudo` command left) is judged by its mtime alone and taken over the same way; a directory or symlink at the lock's path is never moved or deleted, so the waiter fails after its wait. The waiter's own 90 s wait is monotonic too. A holder releases only its own lock, and a waiter that runs out of time fails with retryable `CREDENTIAL_ACQUIRE_FAILED`. Credential and token expiry still use the wall clock. The identity session file uses the same lock.
- Metadata from an incompatible version, or metadata whose secret is missing, is cleared rather than reused, together with every secret it references, and the user must sign in again. If a secret cannot be deleted, the launch fails closed as above.
- Ownership of a secret never depends on its metadata still being valid JSON. The references a credential or identity file names are read from its text as well, so a truncated or damaged file (`Damaged credential metadata was cleared after the secrets it names were deleted`) still has the secrets it names deleted, with the same neighboring generations, before it is removed; one that cannot be deleted stays listed in a discarded marker as above. The same holds for `update`, `rollback`, and `purge`. A secret store cannot be listed, so a file too damaged to name any reference is cleared with a notice that a secret it referenced may remain in the store. A first generation (a credential, or an identity token bundle, with no metadata before it) is named by a discarded marker before the secret is written, so a process that stops between writing the secret and committing its metadata leaves the secret tracked, never usable, and deleted by the next command.
- `logout` revokes when supported, then deletes the current, orphaned, and possibly pending next-generation secrets and the metadata. The revocation outcome is audited as `credential.revoke` (`revoked`, `failed`, `unsupported`, or `skipped` when the store holds no secret for it). A secret store that cannot be read is a `failed` revocation with a problem entry, since the credential may still be valid at the broker. A secret that cannot be deleted is a problem entry, and the discarded marker keeps it tracked; the branded `logout` then exits non-zero with `SECRET_STORE_UNAVAILABLE`, naming what was and was not cleared. When a runtime variable is not set or a provider cannot be loaded, the branded `logout` still deletes local secrets (confirmed) without contacting the broker: a credential the provider could revoke gets `revocation: failed`, `retryPending: true`, and a pending revocation entry. `credential.acquire` is recorded only for a new acquisition, and renewals as `credential.refresh`.
- `login` runs under the credential lock from clearing the previous credential to acquiring the new one, so no launch, renewal, or other login interleaves with it. It revokes the credential it replaces and deletes it, confirming the deletion, before it stores the new identity; a deletion that cannot be confirmed fails the login before the new identity is stored. A failed revocation does not stop the login: it is a notice, a `credential.revoke` event with `revocation: failed` and `retryPending: true`, and an entry in `credentials-metadata/revocation-retry.json` (credential ID, generation, reason, times; never the secret). Every later `login` checks the entries, drops those whose credential has expired, and repeats the rest as notices; `DistributionAccess.pendingRevocations()` (or `readPendingRevocations(path)` from `@piship/credentials`) returns their count and ages, and `doctor` shows them in the Secret Store group (count and oldest age, never an ID) with a warning. The revocation cannot be sent again: the broker authenticates it with the credential, whose secret is already deleted. An entry without an expiry stays until the state is purged; at most 20 entries are kept, and older ones are dropped with only their number kept and reported.
- When update, rollback, or migration must clear a credential the target cannot read (always including a discarded marker), the switching release first revokes it where supported (best effort; a failure is a warning), then deletes every reference, including orphaned and pending generations, and confirms each deletion. A reference that cannot be deleted stops the switch before activation with `SECRET_STORE_UNAVAILABLE`, and every metadata file is kept, so the secret stays tracked. The store is selected from the lock, never from resolved runtime variables.
- A credential adapter that requires an identity is rejected with `CONFIG_INVALID` under `identity.mode: none`.

Launches acquire a broker or adapter credential automatically after `login`. `local-secret` is captured only by `login`; without it a launch fails with `CREDENTIAL_REQUIRED`. `login` always replaces the current runtime credential.

See [inference](inference.md#failure-policy) for the combined failure policy.
