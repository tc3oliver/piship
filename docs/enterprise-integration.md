# Enterprise integration contract

This page is for the infrastructure or platform team that connects a managed PiShip distribution to company services. It lists the endpoints you provide and exactly how PiShip calls them. It describes current `main`; the managed surface is a **candidate**. It is verified with the deterministic [local fixtures](../examples/demo-company/fixtures/local-services.mjs) and, on Ubuntu, against the [enterprise reference stack](../examples/enterprise-reference/README.md): a real Keycloak, a reference credential broker, and LiteLLM in front of a mock model, run by the nightly and manual Reference E2E. The reference stack stands in for a company's services and is not one: no production identity provider, broker, or gateway integration has been recorded ([status](status.md)).

## At a glance

You provide three services. Their URLs go in `piship.yaml` either as plain `https` URLs, which are locked and shipped with every release, or as `${NAME}` [runtime references](manifest.md#runtime-references) resolved from the launch environment ([company setup](#company-setup) compares the two); the manifest and lock never hold secrets.

| Service | Manifest field | Called by | When |
| --- | --- | --- | --- |
| OIDC identity provider | `identity.oidc.issuer` | PiShip; the browser for the authorization page | `login`; launches that need a fresh identity token; `logout` |
| Workload identity (headless, instead of OIDC) | `identity.adapter` with `interactive: false` | The adapter, in the PiShip process | Every launch, `doctor`, and `login` ([headless runs](#headless-and-workload-runs)) |
| Credential broker: acquire | `credential.broker.endpoint` | PiShip | `login`; any launch or model request without a valid runtime credential |
| Credential broker: revoke (optional) | `credential.broker.revokeEndpoint` | PiShip | `logout`; `login` (replaces the previous credential); update, rollback, or migration that must clear it |
| LLM gateway: model list | `inference.baseUrl` + `/models` | PiShip | Launch with `inference.liveCatalog: true`; `doctor` |
| LLM gateway: inference | `inference.baseUrl` + `/chat/completions` or `/responses` | Pi, in the same process | Every model turn and `--smoke-model` |
| Sandbox backend (optional) | `sandbox.provider`, `sandbox.endpoint` | PiShip | Launch (create and check), each `bash` or `!` command, session end |
| Audit collector (optional) | `audit.sinks[].url` (`type: http`) | PiShip | Launch and `login`, `logout`, `update`, `rollback` (readiness probe of a required sink), then batches during and at the end of each |

```text
user ──login──▶ IdP (browser, PKCE) ──tokens──▶ PiShip
PiShip ──POST broker (Bearer identity access token)──▶ runtime credential
Pi ──POST gateway (Bearer runtime credential)──▶ completions
```

The identity token goes only to the broker (and to the IdP revocation endpoint on logout). The gateway sees only the runtime credential.

## Manifest snippet

The access sections of a managed `piship/v1alpha5` manifest; the complete file is [`examples/enterprise-litellm/piship.yaml`](../examples/enterprise-litellm/piship.yaml).

```yaml
variables: [ACMECODE_OIDC_ISSUER, ACMECODE_OIDC_CLIENT_ID, ACMECODE_CREDENTIAL_BROKER_URL, ACMECODE_CREDENTIAL_REVOKE_URL, ACMECODE_LLM_GATEWAY_URL]
identity:
  mode: oidc
  oidc:
    issuer: ${ACMECODE_OIDC_ISSUER}
    clientId: ${ACMECODE_OIDC_CLIENT_ID}
    flow: authorization_code_pkce
    scopes: [openid, profile, email, offline_access]
    redirectUri: http://127.0.0.1:8765/callback
credential:
  provider: http-broker
  broker:
    endpoint: ${ACMECODE_CREDENTIAL_BROKER_URL}
    revokeEndpoint: ${ACMECODE_CREDENTIAL_REVOKE_URL}
  storage: { provider: system }
  refresh: { beforeExpiry: 5m }
inference:
  provider: openai-compatible
  baseUrl: ${ACMECODE_LLM_GATEWAY_URL}
  api: openai-completions
  liveCatalog: true
models:
  default: acme/coder
  allowed: [acme/coder, acme/general]
  catalog:
    acme/coder: { name: Acme Coder, contextWindow: 128000, maxOutputTokens: 8192, tools: true, policyTags: [code] }
    acme/general: { name: Acme General, contextWindow: 64000, maxOutputTokens: 4096, tools: true, policyTags: [general] }
network:
  publicFallback: deny
  privateOnly: true
  allowHosts: []
```

## Company setup

### Running the CLI from your own repository

Keep the distribution (`piship.yaml`, `piship.lock`, resources, and adapters) in a repository of your own. The PiShip CLI is not published to npm: clone PiShip, run `npm ci` and `npm run build` once, then run its CLI by path against your manifest. Relative paths in the manifest resolve from the manifest's directory, not from the PiShip clone.

```bash
node ~/src/piship/packages/cli/dist/bin.js validate ./piship.yaml
node ~/src/piship/packages/cli/dist/bin.js lock ./piship.yaml
node ~/src/piship/packages/cli/dist/bin.js release ./piship.yaml
```

`validate` fails on any setting that is certain to fail on every employee's machine, and prints a `Warning:` for one that fails only in some environments or has no effect. Treat the warnings as release blockers unless you know why they do not apply.

| `validate` | When |
| --- | --- |
| Fails | A required HTTP audit sink on a host outside `network.allowHosts` and the endpoint hosts (managed mode is always private-only, so every launch fails with `AUDIT_UNAVAILABLE`) |
| Fails | `sandbox.credential: runtime` with a plain `sandbox.endpoint` or `sandbox.router` on another origin than `inference.baseUrl`, or with no runtime credential at all (`pi-native` inference or `credential.provider: none`); the required sandbox fails every launch with `SANDBOX_UNAVAILABLE` |
| Fails | A required Streamable HTTP MCP server with a plain `url` that can never start: on a host outside `network.allowHosts` and the endpoint hosts, or with `credential: runtime` on another origin than `inference.baseUrl` or with no runtime credential at all; every launch fails with `MCP_UNHEALTHY` |
| Warns | The same audit, sandbox, or MCP URL as a runtime variable (or with a templated endpoint), an optional audit sink whose events would be dropped, or an optional MCP server that would never start |
| Warns | A relative `network.tls.additionalCA` path ([CA bundles](#ca-bundles)) |
| Warns | `sandbox.network.mode: deny` without `sandbox.required: true`; the sandbox is activated only when required, so nothing enforces it |

### Plain URLs or runtime variables

| | Plain URL (`baseUrl: https://llm.corp.example/v1`) | Runtime variable (`baseUrl: ${ACMECODE_LLM_GATEWAY_URL}`) |
| --- | --- | --- |
| Where the value lives | In `piship.yaml` and the lock, shipped in every release | In the environment of every process that starts the branded command |
| Employee setup | None | Each variable set on each machine, for every way the command is started |
| Changing it | A new release, which users get with `update` | Changing the environment on every machine; no release |
| Checked by `validate` | Fully, including the cross-field checks above | Syntax only; the value is checked at launch |
| Fits | Production endpoints that are the same for everyone | One build used against several environments, such as a staging and a production gateway, or local fixtures |

Prefer plain URLs for production. Endpoint URLs are not secrets, and a plain URL removes the per-machine setup. Use a variable only where the value differs between machines that run the same release.

The branded command reads variables only from its own process environment. A variable exported in a shell profile reaches commands started from that shell, but not ones started by an IDE, a desktop launcher, or a scheduled job, which then fail with `CONFIG_UNAVAILABLE`. Deliver variables the way you deliver other machine configuration (device management, a login script, or the environment of the launching tool), and check them on a real machine with `<command> config explain` or `<command> doctor`.

`validate` lists the variables in two groups. Variables needed at launch are read by the branded command: the access endpoints, CA bundles, and MCP, audit, and sandbox URLs. A variable referenced only by `updates.source` is read only by `<command> update`; launch works without it. `validate` notes which of each group are unset in the shell it runs in.

### CA bundles

Give each `network.tls.additionalCA` entry as an absolute path that your device management installs at the same place on every machine, such as `/etc/acme/ca.pem` or `C:\ProgramData\Acme\ca.pem`. The bundle is not packaged into the release or recorded in the lock; it is read on the employee's machine at launch. A relative path is read from whatever directory the command is started in, so it works only by accident. When the location differs between platforms or machines, use a runtime variable for the whole path (`${ACMECODE_CA_BUNDLE}`). A missing or unreadable bundle fails the launch with `CONFIG_UNAVAILABLE`.

### How changes reach employees

An installed release runs the `piship.yaml` and `piship.lock` it was built from; nothing reads your repository at launch. A change to policy, allowed models, endpoints, allowed hosts, sandbox, or audit therefore reaches employees only as a new release: lock, `release`, `sign-channel`, and serve the channel ([owner workflow](release/owner-workflow.md)). Employees get it with `<command> update`, which verifies and activates it ([update lifecycle](release/update-lifecycle.md)); until they run it they keep the previous settings. Only runtime variables and the employee's own permitted preferences and policy narrowing (`config/policy.json`) change without a release.

## Identity provider (OIDC)

Built on `openid-client`, as a native **public** client ([identity](identity.md)).

| Requirement | Detail |
| --- | --- |
| Discovery | `GET {issuer}/.well-known/openid-configuration`. Its `issuer` must equal the configured issuer. PiShip uses `authorization_endpoint`, `token_endpoint`, `jwks_uri`, and, if present, `revocation_endpoint` |
| Flow | Authorization Code + PKCE `S256` with `state` and `nonce`. This is the only flow (`identity.oidc.flow: authorization_code_pkce`); device flow is not supported. If discovery lists `code_challenge_methods_supported` without `S256`, login is refused |
| Client | Public client, `token_endpoint_auth_method: none`, no client secret (a `clientSecret` in the manifest is rejected). `client_id` is sent in the token request body |
| Redirect URI | Loopback only, `http://127.0.0.1:<port>/<path>` or `http://[::1]:<port>/<path>` (`localhost` is rejected). Register the exact URI, for example `http://127.0.0.1:8765/callback`. Without a port, PiShip binds an ephemeral port, so the IdP must accept any loopback port (RFC 8252 section 7.3) |
| Scopes | `identity.oidc.scopes`, default `[openid, profile, email]`; `openid` is required. Add whatever your IdP needs to issue a refresh token (often `offline_access`) and any scope the broker requires in the access token |
| Audience | Optional `identity.oidc.audience`, sent as the `audience` authorization request parameter when set. Use it if your IdP issues broker-scoped access tokens this way |
| ID token | Required at login. PiShip checks signature (JWKS), `iss`, `aud`, `azp`, `exp`, `nbf` (30 s clock tolerance), and `nonce`. The `alg` must be in `id_token_signing_alg_values_supported`, or `RS256` when that is absent. On refresh an ID token is optional; if returned, `sub` and `iss` must not change |
| Claims | `sub` and `iss` are required. PiShip keeps only `sub`, `iss`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `name`, `preferred_username`, `email`, `email_verified`, and `groups` (scalar or string-array values only), for display; claims from an identity adapter are filtered to the same allowlist. It makes no authorization decision from claims; that is the broker's job |
| Refresh | `grant_type=refresh_token` when the access token has less than 60 s left (from `expires_in`) or after the broker returns 401. A rotated refresh token is stored; refresh is serialized across processes. Without a refresh token, the user must run `login` again when the access token expires |
| Revocation | On `logout`, if discovery advertises `revocation_endpoint`: the refresh token, then the access token (RFC 7009 with `token_type_hint`). A failure is a warning; local state is still cleared |
| Timeouts | 30 s per OIDC HTTP request; a timeout fails with retryable `GATEWAY_UNREACHABLE`. The browser sign-in waits up to 5 minutes |
| Token endpoint failures | A 5xx (including a proxy's HTML error page) or a `server_error` / `temporarily_unavailable` error fails with retryable `GATEWAY_UNREACHABLE`, and a 429 with retryable `GATEWAY_RATE_LIMITED`; both carry the server's `Retry-After`. `invalid_grant` is `IDENTITY_EXPIRED` ("run login"); other token errors are `IDENTITY_INVALID`. PiShip never retries a token request automatically, because a refresh token may rotate on use |

## Headless and workload runs

A managed distribution's non-interactive surfaces can run in CI, scheduled automation, or a managed worker, with no person, no browser, and no prior `login`: the `--smoke` and `--smoke-model` acceptance runs and the subcommands (`doctor`, `models`, `login`, `logout`, `update`, and the others in `--help`). There is no non-interactive prompt, print, or RPC mode in this release; the interactive command needs a terminal and, without one, fails at once with `CONFIG_INVALID` instead of starting. The identity is a workload identity from an identity adapter that declares `interactive: false` ([identity](identity.md#workload-identity-headless-runs)); the manifest is an ordinary managed manifest with `identity.mode: adapter`:

```yaml
identity:
  mode: adapter
  adapter: ./adapters/workload-identity.mjs   # interactive: false
credential:
  provider: http-broker
  broker:
    endpoint: ${ACMECODE_CREDENTIAL_BROKER_URL}
    revokeEndpoint: ${ACMECODE_CREDENTIAL_REVOKE_URL}
  storage: { provider: file, acknowledgePlaintext: true }   # headless Linux; see below
  refresh: { beforeExpiry: 5m }
```

```text
workload platform ──token (file, endpoint)──▶ identity adapter ──session (memory only)──▶ PiShip
PiShip ──POST broker (Bearer workload access token)──▶ runtime credential
Pi ──POST gateway (Bearer runtime credential)──▶ completions
```

| You provide | Detail |
| --- | --- |
| The workload token | Issued by your platform (a Kubernetes projected service account token, a CI job's OIDC token, a token exchange at your IdP). The adapter reads it; PiShip never stores it |
| The identity adapter | `interactive: false` and a `login()` that returns `issuer`, `subject`, `accessToken`, and `expiresAt` without a person. It must not call `openUrl`, must use `context.fetch` for any request, and must not expect a token in a credential-named environment variable: managed mode removes those before adapters load |
| Broker acceptance of the workload token | The broker validates the workload token as it validates a person's access token (issuer, audience, signature, expiry) and decides which models the workload gets. Idempotency, retries, and revocation are unchanged ([below](#credential-broker-http-broker)) |
| A credential store the runner can use | `system` where the runner has an unlocked platform store; otherwise the file store with `acknowledgePlaintext: true` ([headless storage](credentials.md#headless-runs)) |

What PiShip does on every run: it obtains the session from the adapter, binds the runtime credential to the workload principal `(iss, sub)`, reuses the stored credential while it is valid, renews it within `refresh.beforeExpiry` presenting the current workload token, obtains a new session when the old one expires within 60 s or the broker answers 401, and enforces the manifest's model allowlist, entitlement, and network policy exactly as for a person. A run whose workload principal differs from the previous run's gets nothing of it: the previous credential is revoked where supported and deleted, and its model selection cleared. Provider keys in the environment and any personal Pi sign-in (`~/.pi/agent/auth.json`, another distribution's state) are never used, and a missing or failing workload identity fails the run closed; there is no fallback.

What a headless run can and cannot prove is in [security](security.md#headless-and-workload-runs).

## Credential broker (`http-broker`)

The broker turns the user's identity into a short-lived gateway credential. Protocol details are also in [credentials](credentials.md#http-broker-protocol).

### Acquire and renew

Acquisition and renewal are the same call.

```http
POST {credential.broker.endpoint}
Authorization: Bearer <identity access token>
Content-Type: application/json
Accept: application/json
Idempotency-Key: 0b8f5a4e-3c1d-4e2f-9a6b-7c8d9e0f1a2b
PiShip-Client: distribution="acmecode", version="1.4.0", piship="0.7.0", protocol=1

{"distribution": "acmecode", "purpose": "inference"}
```

`distribution` is `app.id`; `purpose` is always `inference`. `Idempotency-Key` names one logical acquire or renewal; see [idempotency and retries](#idempotency-and-retries). `PiShip-Client` says which distribution release and PiShip sent the request ([client identification](#client-identification-piship-client)). Success is any 2xx with a JSON body:

```json
{
  "credential_type": "api_key",
  "credential": "sk-...",
  "credential_id": "vk_1234",
  "expires_at": "2026-09-28T18:00:00Z",
  "models": ["acme/coder", "acme/general"]
}
```

| Field | Required | Rules |
| --- | --- | --- |
| `credential_type` | yes | `api_key`, `bearer`, or `opaque`. All three are sent to the gateway as `Authorization: Bearer <credential>` |
| `credential` | yes | String of at least 8 characters, visible ASCII only (no spaces or control characters), because it is sent as a header value |
| `credential_id` | no | Non-secret string of 1 to 256 letters, digits, `.`, `_`, `:`, or `-` (`/^[A-Za-z0-9._:-]{1,256}$/`); any other value rejects the response with `CREDENTIAL_ACQUIRE_FAILED`. Recorded in audit events and status output, and sent back on revoke |
| `subject` | no | The subject the broker authenticated. If present it must equal the identity subject PiShip sent, or the acquire fails as a `contract` failure: a stored credential is reused on the strength of the principal the identity adapter asserted, and this makes a broker that authenticated someone else visible |
| `expires_at` | no | ISO 8601, parsed with JavaScript `Date.parse`: include `Z` or an offset, or it is read as local time. Must be in the future. Without it the credential never expires locally and is replaced only after a gateway rejection |
| `models` | no | Array of model IDs the credential is entitled to; narrows the catalog, never widens it |
| `base_url` | no | If present, must equal `inference.baseUrl` (trailing slash ignored), or the response is rejected |

An optional field set to `null` is read as absent, so a serializer that writes `null` for an unset field needs no change; a `subject: null` checks no principal, exactly like an absent `subject`. A field of the wrong type fails as a `contract` failure whose message and `sanitizedDetail.field` name the field, never its value.

| Broker status | PiShip behavior |
| --- | --- |
| 401 | Treated as an expired identity: PiShip refreshes the identity once and retries once; otherwise `IDENTITY_EXPIRED`, "run login" |
| 403 | `CREDENTIAL_DENIED`: user or distribution denied. Not retryable |
| 422, or 409 with `{"error": "idempotency_key_reused"}` | `CREDENTIAL_ACQUIRE_FAILED`, not retryable, `reason: idempotency-conflict`: the key was already used for a different request |
| Any other 409 | `CREDENTIAL_ACQUIRE_FAILED`, retryable, `reason: idempotency-in-progress`, with `Retry-After` when sent: the first request with the key is still running, and the next attempt sends the same key |
| 429 | `CREDENTIAL_ACQUIRE_FAILED`, retryable; `Retry-After` (seconds or HTTP date) is shown as `Retry after: <n> s`. No automatic retry |
| 5xx | `CREDENTIAL_ACQUIRE_FAILED`, retryable, with `Retry-After` when sent. No automatic retry |
| 3xx, other 4xx, malformed JSON, contract violation | `CREDENTIAL_ACQUIRE_FAILED`. Redirects are never followed |
| Timeout (30 s) or unreachable | `CREDENTIAL_ACQUIRE_FAILED`, retryable. No automatic retry |
| Cancelled by the caller | `CREDENTIAL_ACQUIRE_FAILED`, not retryable |
| Network or TLS policy refusal | `NETWORK_DENIED` or `TLS_POLICY_VIOLATION`, unchanged |

The timeout always applies; a caller's cancellation signal can end a request sooner but never removes the timeout. Where failures share a code, the error's `detail` tells them apart: `operation` (`acquire` or `revoke`), `reason` (`unreachable`, `timeout`, `cancelled`, `authentication`, `denied`, `rate-limited`, `unavailable`, `rejected`, `contract`, or `idempotency-conflict`), the HTTP `status` when there was one, `transport` (the system error code, such as `ECONNRESET`, when the connection failed with one), `outcome` for a failure without an answer, and the acquire's `idempotencyKey`. Broker responses are never logged or echoed in errors.

### Idempotency and retries

A lost answer can hide an issued credential: the broker may create a gateway key, then the connection drops, or the PiShip process stops, before PiShip stores it. PiShip therefore never re-sends a credential request by itself within one attempt, and gives each logical request a key that it keeps until the request is resolved, so that the next attempt, in this process or a later one, is recognized as the same request.

**What PiShip sends.** Every acquire and renewal carries `Idempotency-Key`: a random UUID (version 4), unquoted. It is not secret and is never derived from the identity, a token, or the user. The key names one logical acquire or renewal, and PiShip records it (`credentials-metadata/pending-issuance.json`, with the principal it is for and the credential it renews; never a secret) before the request is sent; if it cannot be recorded, nothing is sent. Every later attempt of the same request sends the same key: a retry after a timeout, a connection reset, a 5xx, a 429 or 503, a 401, a crash or kill of the PiShip process, a second `login` of the same principal, or a concurrent launch that waited for the credential lock. The key is released, and the next request gets a new one, when:

- the credential is committed locally (after a commit, a later renewal is a new request with a new key);
- the broker gives a final answer: 403, a 409 or 422 key conflict, another non-2xx that is not 401, 409, 429 or 5xx, or a 2xx that breaks this contract;
- the principal changes, the user runs `logout` (also without the runtime variables), the state is purged, or an update or rollback moves to a release that cannot read the record or clears the runtime credential;
- the destination changes: the record holds a hash of the broker endpoint (or of an adapter's module and endpoints), and a key is never sent to another broker than the one it was recorded for.

A key recorded 24 hours ago or more by PiShip's clock, or dated more than a minute ahead of it, is not released and not sent: PiShip assumes the broker keeps a key at least 24 hours ([below](#what-a-broker-must-do)), past which a repeated key may no longer recover anything while a new key could issue a second credential. An acquire or renewal fails with `CREDENTIAL_ACQUIRE_FAILED` (`detail.reason: issuance-retention`, naming the key) until the user runs `logout`, which releases it, and then `login`; a launch that can use the stored credential is not affected. A credential the broker may have issued for the released key stays unused until it expires, as for any [dropped key](#idempotency-and-retries).

A renewal after a gateway rejection and an entitlement re-read after a model denial are requests of their own: they repeat only a key recorded by the same kind of request, never an older request's key, whose credential the broker would replay. A `login` of the same principal repeats whatever key is pending. A caller that passes its own `CredentialContext.idempotencyKey` has it recorded and sent only when no key is pending; a pending key is never replaced by a different caller key. Details are in [pending issuance](credentials.md#pending-issuance).

A dropped key can leave a credential behind: logout or a change of principal with an unresolved request, or a rejection renewal or entitlement re-read that replaces the pending key of another request with its own, leaves a credential the broker may have issued valid until it expires (or the broker's rotation deletes it). Logout revokes only the stored credential, and PiShip does not re-send the request to find the other one.

The key also appears in the `credential.acquire` and `credential.refresh` audit events (`idempotencyKey`, with `resumed: true` when it was repeated) and in the error's `detail.idempotencyKey`, so broker logs can be matched to PiShip's. PiShip does not send the retention it assumes; it is part of this contract.

**What PiShip does not do.** It never retries an acquire, a renewal, or a revocation automatically within one attempt, whatever the failure. The one exception is a 401: the broker rejected the identity token before doing any work, so PiShip refreshes the identity once and sends the same request again, with the same key.

#### What a broker must do

Repeating a key must return the same issuance, or an equivalent result PiShip can recover from safely, never a second credential. A broker must scope keys to the authenticated principal (issuer and subject): the same key from another principal is a different request, which never returns, blocks, or conflicts with the first principal's credential. The broker defines how long it keeps a key; it must keep it at least as long as the credential it issued stays valid or 24 hours, whichever is shorter, including across a restart and without evicting the record of a credential that is still valid. PiShip cannot tell whether a broker honors the key: there is no capability negotiation, and a broker that ignores `Idempotency-Key` gets a new credential for every repeated request after a lost answer (the key only helps a conforming broker; PiShip never claims exactly-once issuance). Such a broker should keep credentials short-lived, so an unused one expires soon.

| Request | Broker answer |
| --- | --- |
| New key | Issue as usual. Store the answer under the key only when issuing started: never for a 401, 403, 429, or 503 |
| Same key, same input, first request finished | Return the stored answer, same credential, same `credential_id`. Do not issue again |
| Same key, different input | 422, or 409 with the JSON body `{"error": "idempotency_key_reused"}`. Do not issue, and never return the stored credential |
| Same key while the first request is still running | 503 with `Retry-After`, or 409 (with `Retry-After` when the broker knows a wait). PiShip keeps the key and sends it again on the next attempt |

PiShip reads a 409 as a conflict only when its JSON body's `error` is `idempotency_key_reused`; any other 409 (no body, another code, a proxy's page) is read as a request still in progress. Releasing the key of a request that is in fact still running would let the next attempt issue a second credential, while keeping the key of a real conflict only costs a retry that fails the same way. Before v0.7.x, PiShip read every 409 as a conflict; a broker that answers a different-input conflict with a bare 409 should send 422 or add the code. The body is read (at most 64 KiB, under the same timeout) only to compare that one field; it is never logged or shown.

"Same input" is the authenticated principal (issuer and subject) plus the request body. It is **not** the access token: an identity refresh changes the token but not the user, and a retry after it must still match. A key sent by another principal is different input, so one user's key never returns another user's credential. A replayed credential that expired meanwhile is refused by PiShip (`CREDENTIAL_EXPIRED`), which releases the key; one that was revoked since is refused by the gateway, and PiShip renews with a new key. A broker that loses its records issues again for a repeated key: that credential is the one PiShip stores, and the first stays unused until it expires. The [reference broker](../examples/enterprise-reference/broker/README.md#idempotency) does not meet the retention minimum in three cases (a restart, its per-principal record cap, and a 502 with an unknown upstream outcome); its README says what a production broker needs instead.

**Which failures are safe to retry.** The error's `retryable` says whether trying again can succeed; `detail.outcome` (on failures without an answer) says whether the broker may already have acted:

| Failure | Did the broker act? | Safe to retry |
| --- | --- | --- |
| 401 | No: the token was rejected before any work | Yes, after an identity refresh (PiShip does this once) |
| 429 with `Retry-After` | No: the broker refused the work | Yes, after `Retry-After` |
| 503 with `Retry-After` | No: the broker refused the work | Yes, after `Retry-After` |
| Refused before sending: `outcome: not-sent` (connection refused, DNS failure, connect timeout, a signal that was already cancelled) | No: the request never left PiShip | Yes |
| Timeout, connection reset, or cancellation after sending: `outcome: unknown` | Maybe: a credential may have been issued | Only with the same `Idempotency-Key` (PiShip's next attempt sends it), and only if the broker honors it |
| 500, 502, 504 | Maybe, depending on where it failed | Only with the same key (PiShip's next attempt sends it), if the broker honors it |
| 409 for a request still in progress | No: the first request is still running | Yes, with the same key (PiShip's next attempt sends it) |
| 403, 409 or 422 key conflict, other 4xx, contract violation | Decided | No; PiShip's next attempt is a new request with a new key |

### Revoke

Only when `credential.broker.revokeEndpoint` is declared:

```http
POST {credential.broker.revokeEndpoint}
Authorization: Bearer <runtime credential>
Content-Type: application/json
PiShip-Client: distribution="acmecode", version="1.4.0", piship="0.7.0", protocol=1

{"credential_id": "vk_1234", "distribution": "acmecode"}
```

The bearer is the **runtime credential**, not the identity token; `credential_id` is `null` if the broker did not return one. Any 2xx, 401, or 404 counts as revoked. Other statuses and transport failures are reported as a warning, and local secrets are deleted anyway. Revocation uses the same transport, timeout (30 s), cancellation, and `detail` as acquisition: a 403 is `CREDENTIAL_DENIED`; a 429, 5xx, timeout, or unreachable endpoint is a retryable `CREDENTIAL_REVOKED` with any `Retry-After`; other statuses and a cancellation are a non-retryable `CREDENTIAL_REVOKED`. Without a revoke endpoint, a credential stays valid at the gateway until it expires.

### Caching and renewal

- The credential is stored in the platform secret store (Keychain, Secret Service, Credential Manager); non-secret metadata (`credential_id`, `expires_at`, `models`) is kept in distribution state.
- It is reused until it is within `credential.refresh.beforeExpiry` (default `5m`) of `expires_at`, then renewed with the acquire call. Choose a lifetime well above that window, or every request renews.
- If renewal fails while the credential is still valid, PiShip keeps using it with a notice. An expired credential that cannot be renewed fails with `CREDENTIAL_EXPIRED`, or with the identity error when sign-in is needed.
- A gateway 401 marks the credential rejected; the next request renews it once. If that fails: `CREDENTIAL_REVOKED`. A 403 during renewal stays `CREDENTIAL_DENIED`.
- A renewal that fails for a temporary reason (5xx, 429, a timeout, an unreachable broker, a 409 for a request still in progress) is not `CREDENTIAL_REVOKED` or `CREDENTIAL_EXPIRED`: it stays the broker failure, a retryable `CREDENTIAL_ACQUIRE_FAILED` with its `Retry-After` and `detail`, whose action is to try again later rather than to sign in again.
- A renewal whose answer was lost is not re-sent. While the current credential is valid, PiShip keeps using it, and the next renewal is a new logical acquire with a new key; a credential the broker issued for the lost answer is never used, so let it expire.
- Renewal replaces the local copy but does **not** call the revoke endpoint for the old credential; rely on its expiry.
- Concurrent launches share one renewal through a lock file. A live holder keeps changing the lock, so it is never broken while held, whatever the wall clock does; only a lock a waiter has seen unchanged for 75 s (monotonic), or whose holder process on the same host no longer exists, is taken over. A waiter says after about 2 s which process holds the lock. A waiter that times out fails with retryable `CREDENTIAL_ACQUIRE_FAILED`.

## LLM gateway (OpenAI-compatible)

### Inference

Pi sends requests with its OpenAI-compatible client to the URL formed from `inference.baseUrl`:

| `inference.api` | Request |
| --- | --- |
| `openai-completions` (default) | `POST {baseUrl}/chat/completions` |
| `openai-responses` | `POST {baseUrl}/responses` |

- `Authorization: Bearer <runtime credential>`; requested per call, so renewals apply without a restart.
- `model` is the catalog ID exactly as in `models.allowed` (for example `acme/coder`), not prefixed with the app ID.
- Requests stream (`"stream": true`, server-sent events). With Pi 1.0.0, chat completions also carry `stream_options.include_usage`, `tools` when tools are offered, and may carry `max_completion_tokens`, `store: false`, and a `developer` role message. The request body is owned by Pi and may change with the pinned Pi version.
- Only allowed and available models are ever requested; PiShip never substitutes another model.

### Model list

```http
GET {baseUrl}/models
Authorization: Bearer <runtime credential>
Accept: application/json
```

```json
{"object": "list", "data": [{"id": "acme/coder", "object": "model"}, {"id": "acme/general", "object": "model"}]}
```

PiShip reads **only** `data[].id`. A model missing from the list becomes `MODEL_UNAVAILABLE`. Capability metadata (`contextWindow`, `maxOutputTokens`, `input`, `reasoning`, `tools`, `streaming`, `structuredOutput`, `policyTags`) comes from `models.catalog` in `piship.yaml`, never from the gateway; capability `requirements` are checked against that catalog, and missing metadata never satisfies a requirement. Timeout: 15 s, covering connection and body.

The effective catalog is `models.allowed` ∩ broker `models` ∩ gateway `data[].id` (when `liveCatalog: true`) ∩ the user's narrowing ([inference](inference.md#model-catalog)).

### Gateway status mapping

For `GET /models` at launch and in `doctor`:

| Status | Code |
| --- | --- |
| 401 | `CREDENTIAL_REVOKED`; PiShip renews the credential once and retries the launch |
| 403 | `MODEL_DENIED` |
| 404 | `MODEL_UNAVAILABLE` |
| 429 | `GATEWAY_RATE_LIMITED`, retryable; `Retry-After` (seconds or HTTP date) is shown as `Retry after: <n> s` |
| 5xx, unreachable, timeout | `GATEWAY_UNREACHABLE`, retryable |
| Other 4xx, non-JSON, no `data` array | `GATEWAY_PROTOCOL_ERROR` |

Each result is also counted in the local `<state>/logs/metrics.json`, which holds error codes and counts only, never the URL or a response. `GATEWAY_UNREACHABLE` (including 5xx) counts as unreachable; any other status counts as reachable, because the gateway answered. A successful live list also records the time and the number of models.

During a session Pi performs the request and reports errors in the conversation. PiShip recognizes an authentication rejection (401, "unauthorized", "invalid api key", "authentication failed" in Pi's error) and renews the credential before the next request; the rejected request is not replayed. A 401 or 403 that LiteLLM relays from its model provider (its error message starts with `litellm.` and its type is not one of LiteLLM's own key or model refusals) is the gateway's provider refusing, not the gateway refusing the credential or the model: PiShip leaves the credential and its entitlement alone and classifies it as `GATEWAY_UNREACHABLE`, not retryable. A 429 without `Retry-After` takes LiteLLM's `llm_provider-retry-after`, at most one hour.

## Sandbox backend (optional)

By default contained commands run in the native OS sandbox and nothing here is needed. A distribution can instead run them in the company's own sandbox or remote execution service: a `custom` adapter module, an `e2b-compatible` API (E2B, CubeSandbox, or another service that implements it), or Kubernetes Agent Sandbox. PiShip owns policy and governance; the sandbox backend owns execution isolation. The [sandbox contract](sandbox.md) has the fields, lifecycle, and wire calls.

```yaml
variables: [ACMECODE_SANDBOX_URL]
sandbox:
  required: true
  provider: e2b-compatible
  endpoint: ${ACMECODE_SANDBOX_URL}
  template: acmecode-workspace
  credential: runtime   # the sandbox API is behind the LLM gateway's origin
  # user: root          # for CubeSandbox; E2B uses the default, user
```

| PiShip does | Your sandbox service owns |
| --- | --- |
| Decides every command against the policy before the backend sees it; enforces `sandbox.filesystem` path rules for its local file tools | Isolating the command: filesystem inside the sandbox, network, processes, and resource limits. Remote backends do not apply PiShip's path rules; the template or image decides what commands can read and write |
| Sends one command, its workspace-relative directory, and the approved environment; never files, host paths such as `PATH` or `HOME`, or credential-looking variables | Providing the workspace contents (template, image, volume, or clone) and a usable shell |
| Sends the inference runtime credential only with `credential: runtime`, and only to the inference gateway origin; with `credential: stored`, the sandbox credential a user stored with `sandbox login`, only to the origins it was stored for; with a custom adapter, the adapter's own in-memory credential ([credentials](sandbox.md#credentials)) | Fronting the sandbox API with the company gateway, issuing sandbox keys or tokens to users, or an adapter credential source |
| Checks declared capabilities and fails closed on a gap, an unavailable service, or a failed check | Honoring the declared capabilities, including network denial for `sandbox.network.mode: deny` |
| Times out and cancels commands, then kills the remote process or deletes the claim | Stopping commands promptly and removing sandboxes that are deleted or expire |

## Audit collector (`piship-audit-batch/v1`)

An `http` audit sink POSTs metadata-only audit events to a collector you run, for example an ingest endpoint in front of your SIEM. PiShip ships no vendor-specific adapter; anything that accepts this contract works.

```yaml
variables: [ACMECODE_AUDIT_URL]
audit:
  enabled: true
  sinks:
    - { id: local, type: file, required: false }
    - { id: company, type: http, url: "${ACMECODE_AUDIT_URL}", required: true }
  buffer: { maxEvents: 1000, flushInterval: 2s }
```

**Request.** `POST <url>` with `content-type: application/json` and one batch as the body. The URL must be `https` (plain `http` only on loopback), must not embed credentials, and goes through the managed fetch (proxy, CA, and private-only rules above; list its host in `network.allowHosts`). PiShip sends **no authentication header**: expose the collector only on the company network or behind your own ingress. Redirects are not followed. Any `2xx` means the whole batch was stored; any other status, a network error, or no answer within 10 seconds is a failure. The response body is ignored.

**Readiness probe.** When a required sink opens (every launch, and every `login`, `logout`, `update`, and `rollback` that records events), PiShip first sends an empty batch, `{"schema":"piship-audit-batch/v1","events":[]}`, and needs a `2xx`. Optional sinks are not probed.

**Batching.** Each sink has its own queue of at most `audit.buffer.maxEvents` events. PiShip delivers every `audit.buffer.flushInterval`, as soon as a queue is half full, and when the session or command ends (within 5 seconds). One request carries at most 500 events, oldest first.

**Retries and de-duplication.** A failed batch for a required sink stays queued and is sent again, with the same events, on the next flush; for an optional sink it is dropped and counted. PiShip cannot tell whether a failed request was stored (a timeout after your collector wrote the batch, for example), so an event can arrive more than once. Every event carries an `id`, a random UUID assigned once when it is emitted and never changed by a retry. To de-duplicate, store an event only if its `id` is not already stored (a unique key on `id` does this), and still answer `2xx` for a batch whose events are all or partly duplicates; otherwise PiShip keeps resending it. Store a hash of the whole event next to each `id`: every property, including `id`, `time`, and `user`, in a canonical form such as RFC 8785 JSON Canonicalization (not just the `content` property, which is usually absent). A retry resends identical content, so an `id` that arrives again with a different hash is not a retry. Still answer `2xx`, because any other status makes PiShip resend the batch forever; keep both events in full, treat neither as the authoritative one, and raise an alert (a faulty or hostile sender). Events are unauthenticated claims: any host that can reach the collector can submit events or claim ids in advance, so restrict and identify senders at your own ingress, and treat `id` as a correlation key, not an integrity guarantee. Retries of one event can span a whole session, so compare against every stored ID rather than a short window. Order events by `time`, not by arrival: a retried batch can arrive after newer events. On the wire `id` is always present, and the schema requires it. Only lines in a local `audit.jsonl` written before `id` was added have none, and PiShip never sends those. What PiShip does when a required collector keeps failing is the [audit failure policy](security.md#audit).

**Privacy.** Events hold metadata: the event type, time, identity subject (never a token), session, distribution, and, where relevant, resource, decision, policy, rule, enforcement plane, and a short `detail` map. Prompt, response, command, and source content appear in `content` only for classes the distribution opts in to under `audit.capture`, and are redacted. Credential and token values are never sent: values of secret-named `detail` keys become `[REDACTED]`, and token shapes are scrubbed from every string.

**Schema.** The body is valid against this JSON Schema (draft 2020-12). A receiver should accept properties it does not know: `piship-audit-batch/v1` may gain optional properties, as it gained `id`, without a version change.

<!-- piship-audit-batch/v1 schema: tested by packages/audit/src/wire-schema.test.ts -->

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "piship-audit-batch/v1",
  "type": "object",
  "required": ["schema", "events"],
  "properties": {
    "schema": { "const": "piship-audit-batch/v1" },
    "events": {
      "type": "array",
      "maxItems": 500,
      "items": { "$ref": "#/$defs/event" }
    }
  },
  "$defs": {
    "event": {
      "type": "object",
      "required": ["schema", "id", "event", "time", "user", "session", "distribution"],
      "properties": {
        "schema": { "const": "piship-audit/v1" },
        "id": { "type": "string", "format": "uuid", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" },
        "event": {
          "enum": [
            "session.start", "session.end",
            "identity.login", "identity.refresh", "identity.logout",
            "credential.acquire", "credential.refresh", "credential.revoke",
            "model.request", "model.denied",
            "resource.load", "resource.denied",
            "provider.load", "provider.denied",
            "tool.request", "tool.allowed", "tool.denied",
            "mcp.server.start", "mcp.call", "mcp.denied",
            "policy.loaded", "policy.violation",
            "policy.auto_enabled", "policy.auto_disabled", "policy.auto_approved",
            "runtime.update", "runtime.rollback"
          ]
        },
        "time": { "type": "string", "format": "date-time", "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$" },
        "user": { "type": ["string", "null"], "maxLength": 512 },
        "session": { "type": ["string", "null"], "maxLength": 512 },
        "distribution": { "type": "string", "minLength": 1, "maxLength": 128 },
        "resource": { "type": "string", "maxLength": 512 },
        "decision": { "enum": ["allowed", "denied", "asked", "approved"] },
        "policy": { "type": "string", "maxLength": 512 },
        "rule": { "type": "string", "maxLength": 512 },
        "enforcement": { "enum": ["control-plane", "sandbox", "audit-only"] },
        "detail": {
          "type": "object",
          "maxProperties": 32,
          "propertyNames": { "pattern": "^[A-Za-z][A-Za-z0-9_.-]{0,63}$" },
          "additionalProperties": { "type": ["string", "number", "boolean", "null"], "maxLength": 256 }
        },
        "content": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "prompt": { "type": "string", "maxLength": 8192 },
            "response": { "type": "string", "maxLength": 8192 },
            "command": { "type": "string", "maxLength": 8192 },
            "source": { "type": "string", "maxLength": 8192 }
          }
        }
      }
    }
  }
}
```

`user` is the principal as one string, the issuer, `#`, then the subject (`%` and `#` inside the issuer are percent-encoded), or `null` without identity or outside a session's identity (update and rollback). v0.6 wrote the bare subject under the same `piship-audit/v1`; from v0.7 this form is fixed, and changing it again needs a new schema ([decision 29](decisions.md)). `session` is `null` outside a governed session (sign-in, sign-out, update, rollback, and `<command> auto on|off`). `policy` is `<policy id>@<version>`. The `policy.auto_*` events come only from distributions that allow [user auto mode](manifest.md#user-auto-mode): `policy.auto_enabled` and `policy.auto_disabled` record the user switching it (`detail.source` is `command` or `session`), and a session that starts with auto mode on (`detail.source: state`), and `policy.auto_approved` records each `ask` it approved without a prompt, with the resource, policy, rule, enforcement, and `detail` of the action's own event (`detail.approval: auto`, which the action's own event also carries). They were added to `piship-audit/v1` after v0.8.0; a collector that validates against an older copy of this schema must take the new names. The `content` classes map to `audit.capture` as `prompt` to `promptContent`, `response` to `responseContent`, `command` to `commandText`, and `source` to `sourceContent`. Longer strings are cut to the limit and end in `…[truncated]`.

## Client identification (`PiShip-Client`)

Every request PiShip sends to the credential broker (acquire, renewal, and revoke) and to the LLM gateway (the model list and every inference request) carries a `PiShip-Client` header, so a broker or gateway can see which distribution release, built with which PiShip, is calling, and apply a minimum version of its own:

```http
PiShip-Client: distribution="acmecode", version="1.4.0", piship="0.7.0", protocol=1
```

| Member | Value |
| --- | --- |
| `distribution` | `app.id` |
| `version` | `app.version` of the active release |
| `piship` | The PiShip version the release was built with |
| `protocol` | An integer for the broker and gateway wire behavior this client speaks. `1` is this contract as of v0.7.x; it increases only when PiShip's requests, or its reading of answers, change in a way a service must know about, and that change is listed in the changelog |

The value is an [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) structured field dictionary. Parse it as one, ignore members you do not know (members may be added, never removed or redefined while `protocol` stays the same), and treat a missing header as a client from before v0.7.x.

**Enforcing a minimum version.** The header is how a company retires a release that carries old policy: the broker refuses to issue credentials below a version, and the gateway refuses requests, and employees then run `<command> update`. Answer the broker acquire with 403 (PiShip reports `CREDENTIAL_DENIED`, not retryable) and the gateway with 403 (at launch, `MODEL_DENIED`; during a session, Pi reports the error in the conversation; see [gateway status mapping](#gateway-status-mapping)), and tell employees out of band why: PiShip does not read or show an error body. Do not answer 401, which PiShip reads as an expired sign-in and retries once after a refresh, or 426, which it treats as any other refusal.

**It is a label, not a proof.** The header is self-reported and unauthenticated: anyone holding a valid token or credential can send any value. Use it to steer well-behaved clients onto supported releases, never as an authorization decision on its own; who may get a credential is still decided by the identity token. PiShip itself never makes a decision from it: it sends it and nothing else. An identity provider, an MCP server, an audit collector, a sandbox service, and the update source do not receive it.

## Network and TLS

Applies to every PiShip-managed request above and to Pi's in-process requests ([security](security.md#network-and-tls)).

| Rule | Detail |
| --- | --- |
| HTTPS | Required; plain HTTP only for loopback fixtures. TLS verification cannot be disabled; `NODE_TLS_REJECT_UNAUTHORIZED=0` fails with `TLS_POLICY_VIOLATION`. The update channel alone may use plain HTTP to a private or internal host when the manifest sets `updates.transport: http-allowed`, for an intranet without a certificate: no CA bundle is needed, the proxy rule below still applies, and update integrity comes from the signed update metadata ([manifest](manifest.md#plain-http-update-channel-v1alpha5)). OIDC, the broker, the gateway, MCP servers, and audit sinks still need HTTPS |
| Enterprise CA | `network.tls.additionalCA`: PEM bundles added to the default roots, read on the employee's machine at launch; use absolute paths ([CA bundles](#ca-bundles)). A bundle that does not contain the server's certificate fails the request; verification is never relaxed to make it pass |
| Proxy | `HTTP(S)_PROXY` and `NO_PROXY` (either case) are honored unless `network.proxy.inheritEnvironment: false`. A host in `NO_PROXY` is contacted directly; every other request, including to a private endpoint, goes through the proxy |
| Child processes | In a managed distribution, commands the agent runs receive only the proxy variables the policy approves (never a proxy URL that embeds credentials) and, for a single declared bundle, `NODE_EXTRA_CA_CERTS`. Other proxy, CA, and TLS-verification variables are dropped ([security](security.md#child-process-network-environment)) |
| Private-only | Always in effect in managed mode (`network.publicFallback` must be `deny`, and that is enforced whatever `network.privateOnly` says). Only the hosts of the issuer, broker, revoke, and gateway URLs, `network.allowHosts`, and, for update commands, the `updates.source` host may be contacted; others fail with `NETWORK_DENIED`. Add to `allowHosts` any OIDC endpoint that discovery returns on another host (token, JWKS, revocation) and every Streamable HTTP MCP server or HTTP audit sink host; `doctor` warns about undeclared ones. The match is on the exact hostname only: a declared host admits every port and scheme on it but no other name, so list every host by its full name (there are no wildcards or domain suffixes; see [`network.allowHosts`](manifest.md#access-fields-v1alpha2-and-later)), and PiShip does not check that the host is a private address. The authorization page opens in the browser and is not subject to this rule |
| MCP and the runtime credential | A `credential: runtime` Streamable HTTP MCP server must have the same origin (scheme, host, port) as `inference.baseUrl`; otherwise it fails to start with `MCP_UNHEALTHY` and never receives the credential |
| Redirects | Not followed; serve each endpoint directly. The update source is the one exception: a redirect within its own origin is followed, at most five times ([update lifecycle](release/update-lifecycle.md)) |
| Ambient keys | In managed mode, provider keys such as `OPENAI_*` are removed from the runtime environment |

## Token semantics

| Token | Issued by | Lifetime | Renewal | Sent to |
| --- | --- | --- | --- | --- |
| Identity access token | IdP | `expires_in` | Refresh grant under 60 s left, or after broker 401 | Broker; IdP revocation endpoint on logout |
| Refresh token | IdP | IdP policy | Rotation honored | IdP token and revocation endpoints |
| ID token | IdP | Checked at login | Optional on refresh | Nowhere |
| Runtime credential | Broker | `expires_at` (optional) | Acquire call within `beforeExpiry`, when expired, or after a gateway 401 | Gateway; revoke endpoint |

| Event | Identity tokens | Runtime credential | Local secrets |
| --- | --- | --- | --- |
| `login` | New session replaces the old | Previous one revoked (if supported), new one acquired | Replaced |
| Renewal | Refreshed | New one acquired; old one **not** revoked | Old one deleted |
| `logout` | Revoked at IdP (if advertised) | Revoked at broker (if configured) | Deleted |
| `update`, `rollback` | Kept if the target release can read them; otherwise cleared without IdP revocation | Kept if readable; otherwise revoked best effort, then cleared | Cleared only when unreadable |
| `uninstall` | Kept | Kept, not revoked | Kept |
| `purge` | Not revoked | Not revoked | State directory deleted; secret-store entries its metadata references are deleted first, each deletion confirmed, and a secret that cannot be deleted fails the purge with `SECRET_STORE_UNAVAILABLE` before any state is removed, so it can be run again. Run `logout` first to revoke |

## Responsibility boundary

| PiShip does | Your infrastructure owns |
| --- | --- |
| Public-client PKCE login, ID token validation, refresh, and revocation calls | IdP client registration, sign-in and MFA policy, token lifetimes, refresh token policy, group assignment |
| Sends the identity access token to the broker only | Validating that token (issuer, audience, signature, expiry) and deciding who gets which models |
| Stores tokens and the credential in the OS secret store and renews before expiry | Issuing short-lived, per-user, scoped credentials and revoking them |
| Narrows models to allowlist ∩ entitlement ∩ live list; refuses anything else | Model allowlist per user or group, quotas, budgets, rate limits, logging, and data retention at the gateway |
| Enforces HTTPS, private-only hosts, and the declared CA | TLS certificates, network reachability, proxies, and the enterprise CA bundle |
| Keeps secrets out of `piship.yaml` and the lock; endpoints are runtime references | Distributing endpoint values to users, rotating broker and upstream provider keys |
| Declares model capabilities from `models.catalog` | Keeping that catalog accurate for the models the gateway serves |
| Governs commands and owns their timeout, cancellation, environment, and credentials | Execution isolation in a custom, e2b-compatible, or Kubernetes sandbox backend |

## Connecting a LiteLLM gateway

[LiteLLM](https://docs.litellm.ai/) proxy serves an OpenAI-compatible API, so it can be the gateway. The files in [`examples/enterprise-litellm`](../examples/enterprise-litellm/README.md) are a starting point. The [enterprise reference stack](../examples/enterprise-reference/README.md) runs LiteLLM v1.103.0 with that proxy config unchanged and tests the broker flow, the key budgets, and the gateway's error answers against it; that is a reference, not a production gateway.

- **Gateway fit.** Set `inference.baseUrl` to the proxy with `/v1` (for example `https://llm.corp.example/v1`) and `api: openai-completions`. LiteLLM's `GET /v1/models` returns `{"data": [{"id": ...}]}`, which is all PiShip reads. The IDs are the LiteLLM `model_name` values, and they must match `models.allowed`.
- **Extra metadata is needed.** LiteLLM's model list does not supply the capability fields PiShip uses; declare them in `models.catalog`.
- **The broker is yours.** LiteLLM has no endpoint that accepts an OIDC access token and returns the http-broker response. Put a small broker in front of it that:
  1. Validates the identity access token against your IdP and decides the user's models.
  2. Calls LiteLLM `POST /key/generate` with the master key, for example `{"models": ["acme/coder"], "duration": "8h", "user_id": "<principal user ID>", "key_alias": "<unique id>"}`. Derive `user_id` from the principal, the issuer **and** the subject, as PiShip does ([principal](identity.md#principal)), never from `sub` alone: a subject is unique only within its issuer, so two identity providers (or a migrated realm) can issue the same `sub` to different people, who would then share one LiteLLM user and its budget, rate limits, and spend. A stable hash of both works, such as the reference broker's `oidc-` plus 40 hex characters of SHA-256 over `[iss, sub]` ([one LiteLLM user per principal](../examples/enterprise-reference/broker/README.md#principal-budget-and-keys)). Do not use the username or email either: they can change or be reused.
  3. Returns `{"credential_type": "api_key", "credential": <key>, "credential_id": <key_alias>, "expires_at": <expiry as ISO 8601 with Z>, "models": [...]}`.
  4. For revocation, accepts the virtual key as the bearer and calls LiteLLM `POST /key/delete` with `{"keys": ["<that key>"]}`; holding the key is the proof.
- **Keep the master key in the broker.** Never put it or a shared virtual key in `piship.yaml`, a runtime variable, or the user's environment. Budgets, rate limits, and spend tracking are LiteLLM key settings you choose in step 2.

## Testing your own broker and audit collector

Before employees depend on them, run your own credential broker and audit collector, ideally staging instances, against PiShip itself. Two tests do this, and neither uses PiShip's test fixtures or reference services.

**1. PiShip's real client: your own distribution.** A build of your distribution is the client employees will run, with its real `http-broker` provider, `http` audit sink, managed fetch, proxy, and CA settings. Build it from a copy of your manifest whose endpoints point at staging (runtime variables make this one build; [plain URLs or runtime variables](#plain-urls-or-runtime-variables)), install it under a throwaway install home, and drive it with a test user:

```bash
node ~/src/piship/packages/cli/dist/bin.js build ./piship.yaml
node dist/<id>/piship.mjs install dist/<id>
<command> login           # acquire: Authorization, Idempotency-Key, the response contract
<command> doctor          # identity, credential, gateway, sandbox, and audit sink state
<command> --smoke         # a gateway request with the credential; a required audit sink is probed and receives the session's events
<command> models          # the entitlement (`models`) narrows the catalog
<command> logout          # revoke: the runtime credential as the bearer
```

Then check your side: the broker logged one issuance per `Idempotency-Key` and the revocation of the same `credential_id`; the collector stored the `identity.login`, `credential.acquire`, `session.start`, `session.end`, and `credential.revoke` events, each once, with `user` in the `<issuer>#<subject>` form. Every PiShip failure names its code, and [troubleshooting](troubleshooting.md) says what to do.

**2. The contract edges: the service kits.** A real client exercises the normal path; it does not, on demand, send a request again with a used `Idempotency-Key`, resend a batch, or present an invalid token. `@piship/adapter-conformance` has two kits for that, the other direction from its [adapter kits](adapter-sdk.md#credential-conformance-kit): they send your service the requests PiShip sends and hold its answers to this contract. They import only `@piship/adapter-sdk` and Node built-ins.

| Kit | Checks |
| --- | --- |
| `testCredentialBroker` | `acquire` (2xx and the [response fields](#acquire-and-renew); a redirect fails), `idempotent replay` (the same request with the same key returns the same credential and `credential_id`), `key reuse` (a different request with a used key answers 422 or 409 `idempotency_key_reused`, never a credential; a broker that refuses the changed request first is reported `skipped`), `authentication` (no bearer and an invalid bearer answer 401), and `revoke` (2xx, 401, or 404 for each credential the kit obtained; `skipped` without `revokeEndpoint`) |
| `testAuditCollector` | `readiness probe` (the empty batch answers 2xx), `batch`, `duplicate batch` (a resent batch answers 2xx and is stored once), `conflicting id` (an ID resent with other content answers 2xx and both are kept), and `unknown property` (an optional property the collector does not know answers 2xx). With `stored`, the kit also reads back what the collector kept |

The package is private and unpublished: run the kits from a checkout of PiShip, in a test file inside the workspace, as for the adapter kits. The identity token is a live credential of a test user: give it to the test from your secret manager or an environment variable, never on a command line or in a file in the repository, and never print it. The kits never put a credential or token in a report.

```ts
import { testAuditCollector, testCredentialBroker } from "@piship/adapter-conformance";
import { expect, it } from "vitest";

it("our staging broker follows the http-broker contract", async () => {
  const report = await testCredentialBroker({
    endpoint: "https://broker.staging.acme.example/v1/llm-credential",
    revokeEndpoint: "https://broker.staging.acme.example/v1/revoke",
    distribution: "acmecode",
    identityToken: () => process.env.ACME_TEST_USER_TOKEN ?? "",
  });
  expect(report.results.filter((result) => result.status === "failed")).toEqual([]);
});

it("our staging collector follows piship-audit-batch/v1", async () => {
  const report = await testAuditCollector({
    url: "https://audit.staging.acme.example/v1/batches",
    distribution: "acmecode",
  });
  expect(report.results.filter((result) => result.status === "failed")).toEqual([]);
});
```

The broker kit obtains up to two credentials for the test user and revokes them at the end when `revokeEndpoint` is given; otherwise they stay valid until they expire. The collector kit stores test events with the user `piship-conformance` and `detail.conformance: true`, so run it against staging or filter them out. The broker kit passes against the [reference broker](../examples/enterprise-reference/broker/README.md) (`examples/enterprise-reference/broker/test/conformance-kit.test.mjs`). A pass means these requests got conforming answers; it does not show that the broker validates tokens correctly for every issuer, scopes keys per principal (that needs a second test user), or keeps keys for 24 hours across a restart ([what a broker must do](#what-a-broker-must-do)).

## Reference implementation

[`examples/demo-company/fixtures/local-services.mjs`](../examples/demo-company/fixtures/local-services.mjs) implements this whole contract on loopback: discovery, PKCE, JWKS, token and revocation endpoints; `POST /broker/v1/llm-credential` and `/broker/v1/revoke`; and `GET /gateway/v1/models` and streaming `POST /gateway/v1/chat/completions`. Use it to see exact request and response shapes. It auto-approves every sign-in and is test infrastructure, not evidence of a live integration. For the same contract against real components, the [enterprise reference stack](../examples/enterprise-reference/README.md) runs Keycloak, a [reference broker](../examples/enterprise-reference/broker/README.md) (which shows what a production broker still needs, such as idempotency records that survive a restart), and LiteLLM in Docker Compose. The [demo company example](../examples/demo-company/README.md#authorized-live-path) shows the variables to set for a real deployment.
