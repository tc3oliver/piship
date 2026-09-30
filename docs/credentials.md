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

`Idempotency-Key` comes from `CredentialContext.idempotencyKey`. For an `http-broker` or `adapter` runtime credential, `CredentialManager` generates a random UUID for each logical acquire or renewal (or takes the caller's key), records it as the pending issuance before the request is sent, and sends the same key on every later attempt until the request is resolved, including from another process after a crash; see [pending issuance](#pending-issuance). A key must be 1 to 255 visible ASCII characters without spaces, or the acquire fails with `reason: contract` before anything is sent. A provider called directly without a key sends no header. What a broker does with the key, and which failures are safe to retry, is in the [enterprise integration contract](enterprise-integration.md#idempotency-and-retries).

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

`Retry-After` (seconds or HTTP date) becomes `retryAfterMs` and is shown as `Retry after: <n> s`. The error's `detail` holds only non-secret fields: `operation` (`acquire` or `revoke`), `reason`, `status` when the broker answered, `idempotencyKey` on an acquire that sent one, `transport` on `unreachable` when the connection failed with a system error (the code alone, such as `ECONNRESET` or `ECONNREFUSED`, also at the end of the message: `The credential broker is unreachable (ECONNRESET)`, or `(network error)` without a system code; never the gateway's `GATEWAY_UNREACHABLE` that the managed fetch reports every transport failure with, the host, a URL, a header, or a body), and, for `timeout`, `unreachable`, and `cancelled`, `outcome`: `not-sent` when the request never left PiShip (connection refused, DNS failure, connect timeout, an already cancelled signal), `unknown` when the broker may have received it and issued a credential. Nothing is re-sent within the attempt; the next attempt sends the same key. Error messages, actions, and details never contain the identity token, the runtime credential, or the broker's response body. A revoke failure is reported as a warning and never keeps the local secret.

## Secret stores

| Store | Mechanism |
| --- | --- |
| macOS Keychain | `/usr/bin/security`; the secret is written in interactive (`-i`) mode on standard input |
| Linux Secret Service | `secret-tool` (libsecret); the secret is passed on standard input |
| Windows Credential Manager | PowerShell calling `advapi32` `CredWrite`/`CredRead`/`CredDelete`; the secret is passed on standard input |
| File (explicit opt-in) | One file per reference under `<state>/secrets/`, 0700 directory and 0600 files, written through a temporary file that is written completely, flushed, and atomically renamed, so a failed write keeps the previous entry; a temporary a killed writer left is removed by `logout` and when the distribution next starts. Values are base64url-encoded, not encrypted. On Windows the directory gets an owner-only ACL (`icacls /inheritance:r /grant:r <user>:(OI)(CI)F`); if it cannot be applied, the store fails with `SECRET_STORE_UNAVAILABLE` |

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

### Pending issuance

A broker (or adapter) may issue a credential and lose the answer, or PiShip may stop before it stores it. So that the next attempt recovers that credential instead of issuing another, the idempotency key of an `http-broker` or `adapter` acquire or renewal is recorded in `credentials-metadata/pending-issuance.json` (`piship-credential-issuance/v1`) before the request is sent, and reused until the request is resolved. The record holds the key, the provider mode, the kind of request (`acquire`, `renewal`, `rejected` for a renewal after a gateway rejection, or `entitlement` for an entitlement re-read), a SHA-256 hash of where the request goes (the broker endpoint, or for an adapter its module and resolved endpoints), the principal (issuer and subject) it was sent for, the credential it renews (reference and acquisition time, absent for a first acquire), and when it was created; never a secret. The reference of the renewed credential is only compared, never deleted: an update, rollback, purge, or logout never takes a secret to delete from this record. It is written with the shared atomic writer, owner-only (0600), under the credential lock, so concurrent launches and logins take turns and the second one sends the first one's key. When it cannot be written, nothing is sent (`CREDENTIAL_ACQUIRE_FAILED`, `detail.outcome: not-sent`). `CredentialManager.pendingIssuance()` returns the key and its age for diagnostics.

Before any operation under the lock changes the stored credential, the record is kept only when it still names an unresolved request: recorded for the configured provider mode and the same destination (a key is never sent to another broker endpoint or adapter configuration), for the signed-in principal, and with no credential committed since (the stored credential is absent or still the one it renews). Otherwise it is dropped and the next request gets a new key. A record that still names an unresolved request but is 24 hours old or more, or dated more than a minute ahead of the clock, is neither dropped nor sent: the request fails closed ([below](#pending-issuance-age)). It is also dropped when the provider gives a final answer (403, 409 or 422, another 4xx except 401, a contract violation, an unusable or already expired credential); kept after a failure that may have come after the request took effect or invites a retry (`outcome` set, `retryable`, a 401 or other identity failure, a network or TLS policy refusal, or an error that is not a `PiShipError`); removed by `logout` (also without the runtime variables), by `login` of another principal, by purge, by an update or rollback to a release that cannot read it, and whenever an update or rollback clears the runtime credential. A credential adapter should report an ambiguous failure with `retryable: true` or `detail.outcome`; any other `PiShipError` it throws ends the request.

Which request repeats a pending key:

- A retry of the same request, in this process or another: always.
- A `login` of the same principal: it repeats the pending key whatever request recorded it, so a login retried after a lost answer recovers the credential already issued.
- A renewal after a gateway rejection, and an entitlement re-read after a model denial: only a key recorded by the same kind of request. A key of another kind is replaced by a new one, because a conforming broker would replay that older request's credential (for a re-read, its old model list).
- A caller-supplied `CredentialContext.idempotencyKey` is used only when no key is pending. A different caller key never replaces a pending one, which may already have issued a credential that only it can recover; the pending key is sent instead.

Committing a credential and removing the record are two steps, because they are two files:

| Process stops, or the state changes | Left on disk | Next attempt |
| --- | --- | --- |
| After recording the key, before or while sending | The record; nothing or something issued | Sends the same key: the broker issues once, or replays what it issued |
| After recording the key, nothing sent, then another principal signs in | The record, bound to the previous principal | The sign-in drops it (the principals differ); the new principal's request gets a new key |
| After the broker issued, before the answer is read (lost answer, kill) | The record | Sends the same key; the broker replays the credential |
| After the secret is written, before metadata switches to it | The record; the new secret under the next generation (a first generation is named by a discarded marker) | The unused secret is deleted as before; the same key is sent, the replayed credential committed |
| After metadata switches, before the record is removed | The record, and metadata of a credential committed after it | The record is recognized as resolved (the stored credential is no longer the one it renews) and dropped before anything else, including a `login` that clears the credential, so its key is never sent again |
| The record is 24 hours old or more, or dated more than a minute ahead of the clock | The record | Nothing is sent: `CREDENTIAL_ACQUIRE_FAILED` until the user checks the broker for the key, runs `logout` (which drops the record), and signs in again with a new key |
| The record is dropped unresolved (logout, a change of principal, mode, or destination, or a rejection renewal or entitlement re-read that replaces it with its own key) after the broker may have issued | Nothing pending | A new key. A credential the broker issued for the dropped key and PiShip never read stays valid until it expires or the broker's rotation deletes it; PiShip can no longer name or revoke it |
| After the record is removed on commit | Nothing pending | A later renewal is a new request with a new key |

Limit: logout or a change of principal with an unresolved request leaves a credential the broker may have issued valid until it expires. Logout revokes only the stored credential, and PiShip does not re-send the request to learn about the other one.

<a id="pending-issuance-age"></a>The age uses the wall clock, which cannot prove how long a broker has kept a key, so a record past the broker's promised retention is never turned into a new key automatically. When a pending record is 24 hours old or more, or dated more than a minute ahead of the clock (a clock set back, so its age is unknown), an acquire or renewal sends nothing and fails with `CREDENTIAL_ACQUIRE_FAILED` (component `credential`); the user action asks to check the broker for the pending key (`pendingIssuance()` names it) and revoke a credential it issued, then run the branded `logout` and `login` commands. Only `logout` removes the record: a `login` of the same principal keeps it and fails the same way. A clock set forward makes a record reach this state early. A clock set back by less than a minute still repeats the key, and one set back on an older record makes it look younger, so its key can be sent after more than 24 hours of real time, which a broker that already forgot it answers with a new credential.

## Sandbox credential

A remote sandbox backend that declares `sandbox.credential: stored` uses a second, separate credential slot, filled only by `<command> sandbox login` ([sandbox credentials](sandbox.md#credentials)). It never replaces or reads the runtime credential.

- Metadata in `credentials-metadata/sandbox.json` (`piship-sandbox-credential-metadata/v1`) holds the source (`stored`), the kind (`api_key` or `bearer`), a generation reference such as `piship:<id>:sandbox#1`, a random credential ID, the acquisition time, the principal (issuer and subject) that stored it, the origins it may be sent to, and `rejected_at` once the service rejected it. It never holds the secret. `metadataSecretRefs` finds its current, orphaned, and pending references, so `logout`, `purge`, update, and rollback delete them.
- It uses the configured secret store (`access.credential.storage`, else `system`) and the same verified deletion and discarded marker as the runtime credential. Its operations run under their own lock (`credentials-metadata/sandbox.json.lock`), taken after the credential lock and before the identity lock.
- Before the secret is read, one bound to another principal (or to none, once identity is configured) is deleted and refused, a rejected one is refused, and every URL it would reach must be one of its recorded origins. It has no remote revocation: `sandbox logout`, `logout`, a change of principal, and `purge` delete it.
- Events are `credential.acquire` and `credential.revoke` with `purpose: "sandbox"`, `source`, `kind`, `generation`, a random `credentialId`, and `reason`; never the secret, the origins, or the endpoint.
- `SandboxCredentialAccess` (`@piship/contracts`) is what a session receives: the source, kind, and origins, `secret()` for one request, and `rejected()`. A custom adapter's own `sandboxCredential` export is held by `AdapterSandboxCredential` in memory only and is never stored.


See [inference](inference.md#failure-policy) for the combined failure policy.
