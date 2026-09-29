# Enterprise integration contract

This page is for the infrastructure or platform team that connects a managed PiShip distribution to company services. It lists the endpoints you provide and exactly how PiShip calls them. It describes current `main`; the managed surface is a **candidate** verified only with the deterministic [local fixtures](../examples/demo-company/fixtures/local-services.mjs), and no live identity provider, broker, or gateway integration has been recorded ([status](status.md)).

## At a glance

You provide three services. Their URLs are `${NAME}` [runtime references](manifest.md#runtime-references) in `piship.yaml`, resolved from the launch environment; the manifest and lock never hold secrets.

| Service | Manifest field | Called by | When |
| --- | --- | --- | --- |
| OIDC identity provider | `identity.oidc.issuer` | PiShip; the browser for the authorization page | `login`; launches that need a fresh identity token; `logout` |
| Credential broker: acquire | `credential.broker.endpoint` | PiShip | `login`; any launch or model request without a valid runtime credential |
| Credential broker: revoke (optional) | `credential.broker.revokeEndpoint` | PiShip | `logout`; `login` (replaces the previous credential); update, rollback, or migration that must clear it |
| LLM gateway: model list | `inference.baseUrl` + `/models` | PiShip | Launch with `inference.liveCatalog: true`; `doctor` |
| LLM gateway: inference | `inference.baseUrl` + `/chat/completions` or `/responses` | Pi, in the same process | Every model turn and `--smoke-model` |
| Sandbox backend (optional) | `sandbox.provider`, `sandbox.endpoint` | PiShip | Launch (create and check), each `bash` or `!` command, session end |

```text
user ──login──▶ IdP (browser, PKCE) ──tokens──▶ PiShip
PiShip ──POST broker (Bearer identity access token)──▶ runtime credential
Pi ──POST gateway (Bearer runtime credential)──▶ completions
```

The identity token goes only to the broker (and to the IdP revocation endpoint on logout). The gateway sees only the runtime credential.

## Manifest snippet

The access sections of a managed `piship/v1alpha4` manifest; the complete file is [`examples/enterprise-litellm/piship.yaml`](../examples/enterprise-litellm/piship.yaml).

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

## Credential broker (`http-broker`)

The broker turns the user's identity into a short-lived gateway credential. Protocol details are also in [credentials](credentials.md#http-broker-protocol).

### Acquire and renew

Acquisition and renewal are the same call.

```http
POST {credential.broker.endpoint}
Authorization: Bearer <identity access token>
Content-Type: application/json
Accept: application/json

{"distribution": "acmecode", "purpose": "inference"}
```

`distribution` is `app.id`; `purpose` is always `inference`. Success is any 2xx with a JSON body:

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
| `credential` | yes | String of at least 8 characters |
| `credential_id` | no | Non-secret string; recorded in audit events and status output, and sent back on revoke |
| `expires_at` | no | ISO 8601, parsed with JavaScript `Date.parse`: include `Z` or an offset, or it is read as local time. Must be in the future. Without it the credential never expires locally and is replaced only after a gateway rejection |
| `models` | no | Array of model IDs the credential is entitled to; narrows the catalog, never widens it |
| `base_url` | no | If present, must equal `inference.baseUrl` (trailing slash ignored), or the response is rejected |

| Broker status | PiShip behavior |
| --- | --- |
| 401 | Treated as an expired identity: PiShip refreshes the identity once and retries once; otherwise `IDENTITY_EXPIRED`, "run login" |
| 403 | `CREDENTIAL_DENIED`: user or distribution denied. Not retryable |
| 429 | `CREDENTIAL_ACQUIRE_FAILED`, retryable; `Retry-After` (seconds or HTTP date) is shown as `Retry after: <n> s`. No automatic retry |
| 5xx | `CREDENTIAL_ACQUIRE_FAILED`, retryable, with `Retry-After` when sent. No automatic retry |
| 3xx, other 4xx, malformed JSON, contract violation | `CREDENTIAL_ACQUIRE_FAILED`. Redirects are never followed |
| Timeout (30 s) or unreachable | `CREDENTIAL_ACQUIRE_FAILED`, retryable |
| Cancelled by the caller | `CREDENTIAL_ACQUIRE_FAILED`, not retryable |
| Network or TLS policy refusal | `NETWORK_DENIED` or `TLS_POLICY_VIOLATION`, unchanged |

The timeout always applies; a caller's cancellation signal can end a request sooner but never removes the timeout. Where failures share a code, the error's `detail` tells them apart: `operation` (`acquire` or `revoke`), `reason` (`unreachable`, `timeout`, `cancelled`, `authentication`, `denied`, `rate-limited`, `unavailable`, `rejected`, or `contract`), and the HTTP `status` when there was one. Broker responses are never logged or echoed in errors.

### Revoke

Only when `credential.broker.revokeEndpoint` is declared:

```http
POST {credential.broker.revokeEndpoint}
Authorization: Bearer <runtime credential>
Content-Type: application/json

{"credential_id": "vk_1234", "distribution": "acmecode"}
```

The bearer is the **runtime credential**, not the identity token; `credential_id` is `null` if the broker did not return one. Any 2xx, 401, or 404 counts as revoked. Other statuses and transport failures are reported as a warning, and local secrets are deleted anyway. Revocation uses the same transport, timeout (30 s), cancellation, and `detail` as acquisition: a 403 is `CREDENTIAL_DENIED`; a 429, 5xx, timeout, or unreachable endpoint is a retryable `CREDENTIAL_REVOKED` with any `Retry-After`; other statuses and a cancellation are a non-retryable `CREDENTIAL_REVOKED`. Without a revoke endpoint, a credential stays valid at the gateway until it expires.

### Caching and renewal

- The credential is stored in the platform secret store (Keychain, Secret Service, Credential Manager); non-secret metadata (`credential_id`, `expires_at`, `models`) is kept in distribution state.
- It is reused until it is within `credential.refresh.beforeExpiry` (default `5m`) of `expires_at`, then renewed with the acquire call. Choose a lifetime well above that window, or every request renews.
- If renewal fails while the credential is still valid, PiShip keeps using it with a notice. An expired credential that cannot be renewed fails with `CREDENTIAL_EXPIRED`, or with the identity error when sign-in is needed.
- A gateway 401 marks the credential rejected; the next request renews it once. If that fails: `CREDENTIAL_REVOKED`. A 403 during renewal stays `CREDENTIAL_DENIED`.
- A failed renewal keeps the broker failure's `retryable`, `Retry-After`, and `detail`, so a broker outage or rate limit on renewal is still retryable rather than a request to sign in again.
- Renewal replaces the local copy but does **not** call the revoke endpoint for the old credential; rely on its expiry.
- Concurrent launches share one renewal through a lock file. A live holder refreshes the lock, so it is never broken while held; only a lock left unrefreshed for 75 s is taken over. A waiter that times out fails with retryable `CREDENTIAL_ACQUIRE_FAILED`.

## LLM gateway (OpenAI-compatible)

### Inference

Pi sends requests with its OpenAI-compatible client to the URL formed from `inference.baseUrl`:

| `inference.api` | Request |
| --- | --- |
| `openai-completions` (default) | `POST {baseUrl}/chat/completions` |
| `openai-responses` | `POST {baseUrl}/responses` |

- `Authorization: Bearer <runtime credential>`; requested per call, so renewals apply without a restart.
- `model` is the catalog ID exactly as in `models.allowed` (for example `acme/coder`), not prefixed with the app ID.
- Requests stream (`"stream": true`, server-sent events). With Pi 0.87.1, chat completions also carry `stream_options.include_usage`, `tools` when tools are offered, and may carry `max_completion_tokens`, `store: false`, and a `developer` role message. The request body is owned by Pi and may change with the pinned Pi version.
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

During a session Pi performs the request and reports errors in the conversation. PiShip recognizes an authentication rejection (401, "unauthorized", "invalid api key", "authentication failed" in Pi's error) and renews the credential before the next request; the rejected request is not replayed.

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
| Sends the inference runtime credential only with `credential: runtime`, and only to the inference gateway origin; there is no separate sandbox credential yet ([limits](sandbox.md#credentials)) | Authenticating that credential by fronting the sandbox API with the company gateway, or exposing an endpoint that needs no client credential |
| Checks declared capabilities and fails closed on a gap, an unavailable service, or a failed check | Honoring the declared capabilities, including network denial for `sandbox.network.mode: deny` |
| Times out and cancels commands, then kills the remote process or deletes the claim | Stopping commands promptly and removing sandboxes that are deleted or expire |

## Network and TLS

Applies to every PiShip-managed request above and to Pi's in-process requests ([security](security.md#network-and-tls)).

| Rule | Detail |
| --- | --- |
| HTTPS | Required; plain HTTP only for loopback fixtures. TLS verification cannot be disabled; `NODE_TLS_REJECT_UNAUTHORIZED=0` fails with `TLS_POLICY_VIOLATION` |
| Enterprise CA | `network.tls.additionalCA`: PEM bundles added to the default roots |
| Proxy | `HTTP(S)_PROXY` and `NO_PROXY` are honored unless `network.proxy.inheritEnvironment: false` |
| Private-only | Always in effect in managed mode (`network.publicFallback` must be `deny`, and that is enforced whatever `network.privateOnly` says). Only the hosts of the issuer, broker, revoke, and gateway URLs, `network.allowHosts`, and, for update commands, the `updates.source` host may be contacted; others fail with `NETWORK_DENIED`. Add to `allowHosts` any OIDC endpoint that discovery returns on another host (token, JWKS, revocation) and every Streamable HTTP MCP server or HTTP audit sink host; `doctor` warns about undeclared ones. The authorization page opens in the browser and is not subject to this rule |
| MCP and the runtime credential | A `credential: runtime` Streamable HTTP MCP server must have the same origin (scheme, host, port) as `inference.baseUrl`; otherwise it fails to start with `MCP_UNHEALTHY` and never receives the credential |
| Redirects | Not followed; serve each endpoint directly |
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
| `purge` | Not revoked | Not revoked | State directory deleted; secret-store entries its metadata references are deleted best effort (failures are warnings). Run `logout` first to revoke |

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

[LiteLLM](https://docs.litellm.ai/) proxy serves an OpenAI-compatible API, so it can be the gateway. The files in [`examples/enterprise-litellm`](../examples/enterprise-litellm/README.md) are a starting point; they are not tested against a live LiteLLM.

- **Gateway fit.** Set `inference.baseUrl` to the proxy with `/v1` (for example `https://llm.corp.example/v1`) and `api: openai-completions`. LiteLLM's `GET /v1/models` returns `{"data": [{"id": ...}]}`, which is all PiShip reads. The IDs are the LiteLLM `model_name` values, and they must match `models.allowed`.
- **Extra metadata is needed.** LiteLLM's model list does not supply the capability fields PiShip uses; declare them in `models.catalog`.
- **The broker is yours.** LiteLLM has no endpoint that accepts an OIDC access token and returns the http-broker response. Put a small broker in front of it that:
  1. Validates the identity access token against your IdP and decides the user's models.
  2. Calls LiteLLM `POST /key/generate` with the master key, for example `{"models": ["acme/coder"], "duration": "8h", "user_id": "<sub>", "key_alias": "<unique id>"}`.
  3. Returns `{"credential_type": "api_key", "credential": <key>, "credential_id": <key_alias>, "expires_at": <expiry as ISO 8601 with Z>, "models": [...]}`.
  4. For revocation, accepts the virtual key as the bearer and calls LiteLLM `POST /key/delete` with `{"keys": ["<that key>"]}`; holding the key is the proof.
- **Keep the master key in the broker.** Never put it or a shared virtual key in `piship.yaml`, a runtime variable, or the user's environment. Budgets, rate limits, and spend tracking are LiteLLM key settings you choose in step 2.

## Reference implementation

[`examples/demo-company/fixtures/local-services.mjs`](../examples/demo-company/fixtures/local-services.mjs) implements this whole contract on loopback: discovery, PKCE, JWKS, token and revocation endpoints; `POST /broker/v1/llm-credential` and `/broker/v1/revoke`; and `GET /gateway/v1/models` and streaming `POST /gateway/v1/chat/completions`. Use it to see exact request and response shapes. It auto-approves every sign-in and is test infrastructure, not evidence of a live integration. The [demo company example](../examples/demo-company/README.md#authorized-live-path) shows the variables to set for a real deployment.
