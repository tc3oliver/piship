# Reference credential broker

The credential broker of the [enterprise reference stack](../README.md): it implements PiShip's [`http-broker` contract](../../../docs/enterprise-integration.md#credential-broker-http-broker) in front of LiteLLM. It takes the user's Keycloak access token, decides which models the user may use, and returns a LiteLLM virtual key scoped to them. LiteLLM cannot accept an OIDC token itself, so a company runs something like this; PiShip ships no broker.

It is example code for tests and local exploration, not a package and not a production service. It uses Node 22 built-ins only (`node:http`, `node:crypto`, `fetch`) and has no dependencies to install.

| File | Contents |
| --- | --- |
| [`server.mjs`](server.mjs) | Entry point: configuration from the environment, HTTP server |
| [`src/broker.mjs`](src/broker.mjs) | Routes, entitlement table, principal mapping, idempotency, rate limit, rotation, revoke |
| [`src/token.mjs`](src/token.mjs) | Access token validation and the JWKS cache |
| [`src/litellm.mjs`](src/litellm.mjs) | The LiteLLM admin calls |
| [`src/log.mjs`](src/log.mjs) | The allowlisting, scrubbing logger |
| [`test/`](test) | Contract test with a fake Keycloak and a fake LiteLLM, and the same broker driven by PiShip's own client |
| [`live-check.mjs`](live-check.mjs) | Happy path against the running stack |

## Endpoints

| Request | Answer |
| --- | --- |
| `POST /v1/credential`, `Authorization: Bearer <Keycloak access token>`, body `{"distribution": "acmecode", "purpose": "inference"}`, optional `Idempotency-Key` | A new LiteLLM virtual key: `{"credential_type": "api_key", "credential", "credential_id", "expires_at", "models", "base_url", "subject"}` |
| `POST /v1/revoke`, `Authorization: Bearer <that virtual key>`, body `{"credential_id": <id or null>, "distribution": "acmecode"}` | The key is deleted from LiteLLM: `{"revoked": true, "credential_id"}` |
| `GET /health` | `{"status": "ok"}` |

In `piship.yaml` these are `credential.broker.endpoint: http://127.0.0.1:<BROKER_PORT>/v1/credential` and `revokeEndpoint: http://127.0.0.1:<BROKER_PORT>/v1/revoke`, with `inference.baseUrl: http://127.0.0.1:<LITELLM_PORT>/v1`.

Every answer is JSON with `cache-control: no-store`. An error body is only `{"error": "<code>"}`: never an upstream message, a token, or a key.

### Status codes

| Status | When | PiShip reads it as |
| --- | --- | --- |
| 200 | Issued, or an idempotent replay; revoke done | Success |
| 400 | Body not a JSON object, `purpose` not `inference`, `Idempotency-Key` not 1 to 255 visible ASCII characters | `CREDENTIAL_ACQUIRE_FAILED`, `rejected` |
| 401 | No bearer, or the access token fails any check below. Revoke: no bearer | `IDENTITY_EXPIRED` (PiShip refreshes the identity once and retries); on revoke, "revoked" |
| 403 | Valid token but not entitled: no `groups` claim, or no group in the table below; another `distribution`. Revoke: another `distribution` in the body | `CREDENTIAL_DENIED` |
| 404 | Revoke of a key LiteLLM does not have (deleted, or never issued), confirmed under the master key; or of a key this broker did not issue, answered the same way | Revoked |
| 413, 415 | Body over 4 KiB; not `application/json` | `rejected` |
| 422 | `Idempotency-Key` already used by this principal with another body | `idempotency-conflict` |
| 429 + `Retry-After` (s) | More than `BROKER_ACQUIRE_LIMIT_PER_MINUTE` new acquires by this principal in the current minute; more than `BROKER_REVOKE_LIMIT_PER_MINUTE` revokes from this client address | Retryable, `rate-limited` |
| 502 | A key may have been created but the broker could not confirm it was cleaned up | Retryable, `unavailable`; retry with the same key |
| 503 + `Retry-After` | LiteLLM failed or is unreachable (nothing issued, or the half-issued key was deleted; on revoke, the key may still exist); the realm's JWKS is unavailable with nothing cached; the same `Idempotency-Key` is still in progress, or `BROKER_REVOKE_MAX_CONCURRENT` revokes are already waiting on LiteLLM (`Retry-After: 1`) | Retryable, `unavailable` |

## Token validation

The access token is checked in this order, and nothing from its payload is used before the signature is verified:

1. Three base64url segments, at most 8 KiB. The header's `alg` must be exactly `RS256`: `none`, `HS256` (the RSA-public-key-as-HMAC-secret confusion), `RS512`, `PS256` and every other value are refused before a key is looked up. A `crit` header is refused.
2. The key is the realm JWKS entry with the header's `kid`, `kty: RSA`, 2048 bits or more, `use` and `alg` absent or `sig` and `RS256`. Only its public members are imported, as a public key object.
3. The RSA-SHA256 signature over the first two segments.
4. `iss` equals `BROKER_ISSUER` exactly; `aud` contains `piship-reference-broker`; `exp` is present and not past; `nbf` and `iat`, when present, are not in the future; `azp` is `acmecode`; `typ`, when present, is `Bearer` (Keycloak's ID tokens say `ID`); `sub` is a non-empty string. `exp`, `nbf` and `iat` allow 30 s of clock skew (`BROKER_CLOCK_TOLERANCE_SECONDS`).
5. `groups` must be a string array with at least one group path in the entitlement table; otherwise 403.

The JWKS is fetched from `BROKER_JWKS_URL` (Keycloak's back channel, `http://keycloak:8080/...` on the compose network, while the issuer stays the loopback URL; outside a loopback host or a container network it must be `https`) and cached. It is fetched again when the cache is older than 10 minutes, or for a `kid` the cache does not have (a rotated key); either way at most once per 30 s, including while Keycloak is failing, so tokens with random `kid`s never turn into one JWKS request each. While Keycloak is down, known keys keep working from the cache for at most `BROKER_JWKS_MAX_STALE_SECONDS` (default 1 hour) after the last successful fetch, so a signing key the realm withdrew cannot stay trusted indefinitely; past that, or with no cache at all, the cache is dropped and acquires answer 503 `identity_provider_unavailable` until a fetch succeeds.

The broker does not introspect tokens: an access token of a session signed out at Keycloak stays usable here until it expires (5 minutes in the reference realm).

## Entitlement: groups to models

| Keycloak group (full path) | Models | Reference user |
| --- | --- | --- |
| `/engineering` | `acme/coder`, `acme/general` | alice |
| `/support` | `acme/coder` | bob |

The key is the group's full path, because it must be unique in the realm and a Keycloak group name is not: `/contractors/engineering` is also named `engineering`, and keyed by name it would inherit `/engineering`'s models. The realm's `groups` mapper therefore sends full paths (`full.path: true`), and a bare name matches nothing. Whatever an adaptation keys entitlement by (a group path, a client role), it must be unique in the realm. A user gets the union over their groups; other groups grant nothing. The table is `GROUP_MODELS` in [`src/broker.mjs`](src/broker.mjs). The models are written into the key, so LiteLLM itself refuses any other model (`key_model_access_denied`, 403); PiShip then narrows its catalog to the same list. The entitlement is read at every acquire: a group change applies to the next key, and keys already issued keep their models until they expire or are rotated out.

## Principal, budget and keys (D-01)

- **One LiteLLM user per principal.** `user_id` is `oidc-` plus the first 40 hex characters of SHA-256 over `[iss, sub]` (`principalUserId`). It depends on the issuer and subject only, never on the token, the username, or the email, so every key one employee is issued, and every rotation, belongs to the same user. The user's LiteLLM `metadata` records `iss` and `sub` for an operator.
- **The budget is on the user, not the key, and keys have no `team_id`.** The first acquire creates the user with `/user/new`: `max_budget` `BROKER_USER_MAX_BUDGET` (default 10), `budget_duration` `BROKER_USER_BUDGET_DURATION` (default `30d`), optional `tpm_limit` and `rpm_limit`, role `internal_user_viewer`, and `auto_create_key: false`. A LiteLLM key with a `team_id` is governed by team budgets only and ignores the user's personal budget, so the broker never sets one. An existing user keeps its budget and spend; the broker refuses to issue for an existing user whose role is not `internal_user_viewer` (503).
- **The role limits what a key can do.** A key of an `internal_user_viewer` user cannot call `/key/generate`, `/key/delete`, or `/user/new` (LiteLLM answers 401), so a user cannot mint a key with more models than the broker gave. It can still list the user's own keys (hashed, never the key values).
- **The key.** `/key/generate` with `user_id`, `models`, `duration` (`BROKER_KEY_TTL_SECONDS`, default 8 hours, at most 24), `key_alias`, `metadata` (`issued_by: piship-reference-broker`, `distribution`), and optionally `max_parallel_requests`. No `team_id`, no per-key or per-model budget. LiteLLM must report an expiry with an explicit zone no later than the requested lifetime; otherwise the key is deleted and the acquire fails.
- **`credential_id` is the key alias:** `pb-` and 24 random hex characters. PiShip requires `[A-Za-z0-9._:-]{1,256}`; LiteLLM accepts more (`:` included), so the broker, not LiteLLM, keeps the alias inside PiShip's alphabet. It reveals nothing about the key.
- **Only open-source LiteLLM features.** `/key/{key}/regenerate`, key auto-rotation, and per-model budgets are Enterprise-only and are not used.
- **Rotation is "generate new, then delete old".** After each new key, the broker keeps that key and the newest `BROKER_MAX_KEYS_PER_USER` (default 3) minus one other keys it issued to that user for this distribution, and deletes the rest by alias, before it answers. It reads every page of `/key/list`; a key without a readable `created_at` counts as the oldest. Issuing and retiring run one at a time per user, so two acquires of one user cannot both count the keys before the other's new key exists. More than one live key allows a user on two machines, and PiShip's renewal does not revoke the key it replaces. Deletion failures are only logged; every key also expires. A key the broker did not issue is never deleted.
- **PostgreSQL.** The broker keeps no database of its own. The mapping is a pure function of `(iss, sub)`, and users, keys, budgets and spend live in LiteLLM (whose PostgreSQL the stack runs).

## Idempotency

As [docs/enterprise-integration.md](../../../docs/enterprise-integration.md#idempotency-and-retries) specifies:

| Request | Broker answer |
| --- | --- |
| New `Idempotency-Key` | Issues; the answer is stored under the key only once issuing started, never for a 401, 403, 429 or 503 |
| Same key, same input, first finished | The stored answer: same credential, same `credential_id`; nothing is issued |
| Same key, same principal, different body | 422; nothing issued, the stored credential never returned |
| Same key while the first is still running | 503, `Retry-After: 1` |
| No key | Issues every time |

"Input" is the verified `iss` and `sub` plus the request body with its keys sorted, never the token, so a retry after an identity refresh still matches. Records are scoped to the principal: they are kept per `user_id` and key, so the same key sent by another principal is a separate request that issues that principal's own credential; it can neither read nor block someone else's. A replay is not counted against the rate limit. A stored answer is kept until its credential expires; the record of a request in progress for 2 minutes. A principal keeps at most twice `BROKER_MAX_KEYS_PER_USER` records: a new one drops that principal's oldest finished record, so a retry of that old key issues a new credential, and a principal whose records are all still in progress gets 503. Only past 10 000 records in all are other principals' oldest finished records dropped. A replay returns the stored credential as issued, even if rotation has deleted it since; the gateway then refuses it with 401 and PiShip renews.

The store is **in memory**: a broker restart forgets every key, so a retry after a restart issues a new credential (the old one expires, or rotation deletes it). A production broker with several instances needs a shared store; so does the per-principal rate limit, which is also in memory.

When LiteLLM fails after `/key/generate` may have created a key (the connection dropped before its answer), the broker deletes that key by its alias. If the deletion is confirmed, nothing was issued and the answer is 503; if not, 502.

## Revoke

The bearer is the virtual key itself. The broker asks LiteLLM `GET /key/info` **with that key as the bearer**: only its holder can, and the answer describes that key. LiteLLM refusing that lookup does not mean the key is gone: it also refuses a key that still exists but is expired or blocked (401), and other releases answer 400 or 403 for such keys or 401 for a route the key may not use. So after any 4xx there the broker asks again under the master key, `GET /key/info?key=<SHA-256 hex of the key>` (LiteLLM stores keys hashed and accepts the hash, so the key never appears in a URL or an access log). If that lookup also answers 404, LiteLLM never had the key: 404. LiteLLM still describes a key there after it was deleted, so a deleted key goes on to `/key/delete`, whose 404 answers 404 (below). If the lookup fails, the answer is 503, never a 404 for a key that may still work. A key without the broker's `issued_by` mark, or marked for another distribution, is not deleted and gets the same 404 as an unknown key, so revoke cannot tell a caller whether a string is a working LiteLLM key; the log records `reason: foreign-key`. Otherwise the broker deletes it with `POST /key/delete` `{"keys": [<key>]}` under the master key (a key of an `internal_user_viewer` cannot delete itself); a 404 from LiteLLM there also means revoked. The `credential_id` in the body is informational: the key presented is what is revoked, and a mismatch is logged. LiteLLM rejects a deleted key at once with 401.

Revoke is authenticated only by the key it revokes, so it is limited by where it comes from: at most `BROKER_REVOKE_LIMIT_PER_MINUTE` (default 60) requests per client address per minute, counted before anything else is checked, then 429. An IPv6 address counts by its /64 prefix, since one host usually holds a whole /64. At most 10 000 addresses are tracked; past that, new addresses share one overflow window that refuses no one, so a caller who fills the table with made-up addresses cannot lock everyone else out of revoke, and only the concurrency cap below limits the load. The address is the socket's peer; `X-Forwarded-For` is read only when that peer is listed in `BROKER_TRUSTED_PROXIES`, and then its right-most address that is not a trusted proxy counts. At most `BROKER_REVOKE_MAX_CONCURRENT` (default 16) revokes wait on LiteLLM at once, across all callers; the next one gets 503 with `Retry-After: 1`.

## Secrets and logs

- The broker holds one secret, `LITELLM_MASTER_KEY`, used only as the bearer of LiteLLM admin calls. It never needs `LITELLM_SALT_KEY` or any other value from `.env`, and compose gives it none. It never returns either.
- Logs are one JSON line per request with a fixed set of fields: event, route, status, reason, `user_id` (the hash), `credential_id`, models, idempotency outcome, upstream status, duration. Any other field passed to the logger is dropped, and every string is scrubbed of the master key, `sk-…` key shapes and JWT shapes. No token, key, request body or upstream response is logged; LiteLLM's own error messages quote key fragments, so they are never read into a log or an answer.
- Configuration errors name the variable, never its value.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `BROKER_ISSUER` | required | Exact `iss` |
| `BROKER_JWKS_URL` | required | Realm certs endpoint. Must be `https`, except on a loopback host or with `BROKER_ALLOW_INSECURE_BACKCHANNEL` |
| `BROKER_LITELLM_URL` | required | LiteLLM admin origin. Must be `https`, except on a loopback host or with `BROKER_ALLOW_INSECURE_BACKCHANNEL` |
| `BROKER_ALLOW_INSECURE_BACKCHANNEL` | `false` | `true` also allows plain `http` for those two URLs on a single-label host name, a container network name such as `keycloak`; any other host still needs `https`. Compose sets it, since its back channel never leaves the compose network. Never set it where the path to the host crosses a network someone else can read: a JWKS read in clear lets a forged token with any `sub` through, and the admin calls carry the master key |
| `LITELLM_MASTER_KEY` | required | LiteLLM admin key (`sk-…`) |
| `BROKER_GATEWAY_BASE_URL` | required | Returned as `base_url`; must equal PiShip's `inference.baseUrl` |
| `BROKER_AUDIENCE` | `piship-reference-broker` | Required `aud` member |
| `BROKER_AUTHORIZED_PARTY` | `acmecode` | Required `azp` |
| `BROKER_DISTRIBUTION` | `acmecode` | The only `distribution` served |
| `BROKER_LISTEN_HOST`, `BROKER_LISTEN_PORT` | `127.0.0.1`, `8080` | Compose sets `0.0.0.0` inside the container and publishes the port on `127.0.0.1` only |
| `BROKER_KEY_TTL_SECONDS` | `28800` | Key lifetime, 600 to 86400. Choose it well above PiShip's `refresh.beforeExpiry` |
| `BROKER_USER_MAX_BUDGET`, `BROKER_USER_BUDGET_DURATION` | `10`, `30d` | Set on a user when it is created |
| `BROKER_USER_TPM_LIMIT`, `BROKER_USER_RPM_LIMIT`, `BROKER_KEY_MAX_PARALLEL_REQUESTS` | unset | Optional LiteLLM user and key limits |
| `BROKER_MAX_KEYS_PER_USER` | `3` | Live broker keys kept per user by rotation |
| `BROKER_ACQUIRE_LIMIT_PER_MINUTE` | `20` | New acquires per principal per minute |
| `BROKER_CLOCK_TOLERANCE_SECONDS` | `30` | Skew allowed on `exp`, `nbf`, `iat` |
| `BROKER_JWKS_MAX_STALE_SECONDS` | `3600` | How long after the last successful JWKS fetch its keys are still trusted while refetches fail, 600 to 86400 |
| `BROKER_REVOKE_LIMIT_PER_MINUTE` | `60` | Revokes per client address (IPv6: per /64) per minute |
| `BROKER_REVOKE_MAX_CONCURRENT` | `16` | Revokes waiting on LiteLLM at once, across all callers |
| `BROKER_TRUSTED_PROXIES` | unset | Comma-separated IP addresses of reverse proxies whose `X-Forwarded-For` is believed; unset, the header is ignored |

## Limits

What this reference deliberately leaves to a production broker:

- **One instance.** The idempotency records, every rate limit, and the per-user serialization of issue and rotation are in memory: a restart forgets them, and two instances would each keep their own, so two instances could together leave a user above `BROKER_MAX_KEYS_PER_USER` until the next acquire or expiry. A production broker keeps them in a shared store and lock.
- **Revoke is limited per client address, not per user.** Behind Docker's port publishing every client on the host reaches the broker from the same address and shares one revoke window; behind a reverse proxy, set `BROKER_TRUSTED_PROXIES` so the forwarded address counts.

## Run and test

With the stack (see [the stack README](../README.md)), the broker starts as the `broker` service on `127.0.0.1:${BROKER_PORT:-18070}`:

```sh
docker compose up --wait
node broker/live-check.mjs            # alice and bob sign in, get keys, use them; revoke; deleted key refused
```

The contract test needs no Docker (Node 22.19 or later):

```sh
cd broker
node --test test/*.test.mjs
```

[`test/contract.test.mjs`](test/contract.test.mjs) runs the broker between a fake Keycloak (RS256 keys, JWKS, token minting, including forged tokens) and a fake LiteLLM (users, keys, faults, and error bodies that quote keys like the real one) and checks each row above: the response fields and headers, `credential_id` format, the `subject` echo, each token check (by the reason it logs), the JWKS cache bounds, entitlement, each idempotency row, 429, the upstream failures including a lost `/key/generate` answer, rotation, revoke, no Enterprise call, and a scan of every log line for the master key, every issued key, every token, and planted sentinels.

[`test/piship-client.test.mjs`](test/piship-client.test.mjs) drives the same broker with PiShip's `HttpBrokerCredentialProvider` from `packages/credentials`, so it needs the repository built first (`npm ci && npm run build` at the root; `PISHIP_REPO_ROOT` points it at another checkout). It checks that PiShip reads every answer as documented: the credential and its metadata, a same-key retry, `IDENTITY_EXPIRED`, `CREDENTIAL_DENIED`, the idempotency conflict, retryable 503 and 429 with their `Retry-After`, and revoke.

## Observed LiteLLM behavior (v1.103.0)

From the D-01 check against the pinned image, which the broker relies on:

- Two keys without `team_id` for one `user_id` accrue one user spend: the user's spend equals the sum of the keys' spends. A user over `max_budget` is refused on every key, including a key that never spent (429, `budget_exceeded`).
- Spend is written in batches: key and user spend appeared 2 to 5 s after the requests, so a test must poll.
- `/user/new` issues a key unless `auto_create_key: false`; a second `/user/new` for the same `user_id` answers 409. `/user/info` for an unknown user answers 404.
- `key_alias` must be unique (400 otherwise) and may contain `:`.
- `/key/generate` reports `expires` with `Z`; `/key/info` reports it with `+00:00`.
- A key of an `internal_user_viewer` user gets 401 from `/key/generate`, `/key/delete` and `/user/new`, and can read `/key/info` about itself.
- `/key/delete` accepts `keys` or `key_aliases` and answers 404 when none is found. A deleted key is refused with 401 on `/v1/models` and completions.
- `GET /key/info` with the key as the bearer answers 200 for a live key and also for a key over its own or its user's `max_budget` (the budget is refused only on model calls, 429 `budget_exceeded`); 401 `expired_key` for an expired key, 401 `auth_error` for a blocked key (`/key/block`), and 401 `token_not_found_in_db` for an unknown or deleted one.
- `GET /key/info?key=<SHA-256 hex of the key>` under the master key finds the key by its hash: 200 with the key's metadata for a live, expired, blocked, or over-budget key; 404 `not_found_error` for a hash LiteLLM never issued. It still answers 200 for a deleted key (checked 150 s after `/key/delete`), so only the delete tells a deleted key apart.
