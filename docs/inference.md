# Inference

`@piship/inference` binds a distribution to an inference endpoint and computes the effective model catalog. It receives a `CredentialRef` and a request-time secret accessor, never an identity token.

## Contract

```ts
interface InferenceProvider {
  readonly kind: string;
  listModels(identity: IdentitySession | null, credential: CredentialRef | null): Promise<ModelDefinition[]>;
  resolveModel(requested: string, ctx: InferenceContext): Promise<ResolvedModel>;
  configureRuntime(ctx: RuntimeConfigurationContext): Promise<RuntimeProviderConfiguration>;
}
```

A `ModelDefinition` has an ID, name, provider, capabilities (input, reasoning, tools, streaming, context window, max output), policy tags, and availability with a reason.

## Modes

| `inference.provider` | Behavior |
| --- | --- |
| `openai-compatible` | An explicit gateway or local server at `inference.baseUrl`, using `openai-completions` or `openai-responses`. Required in managed mode |
| `pi-native` | Pi's own provider catalog and auth in isolated state. Personal only; `models.allowed` entries (`provider/model`) narrow it |

These are the only two providers. A manifest can load identity, credential, sandbox, and policy adapters but has no field that loads an `InferenceProvider` adapter, so a gateway that is not OpenAI-compatible is not supported; the [status page](status.md#capability-matrix) lists it as not claimed.

For `openai-compatible`, the Pi runtime gets one provider named after the app ID, so a model appears as `<app id>/<model id>`. Request authentication is resolved per request: PiShip refreshes the credential before expiry and passes the secret only to Pi's request path.

## Model catalog

The effective catalog is an intersection that can only narrow:

1. The distribution's `models.allowed` and `models.catalog` metadata.
2. The credential entitlement, when the broker returns `models`.
3. The live gateway listing from `GET {baseUrl}/models`, when `liveCatalog: true`.
4. The user's optional `models.allowed` preference, set with `config set models.allowed a,b`. It can only remove models.

A model outside the distribution allowlist, or a Pi model in managed mode, is refused with `MODEL_DENIED`. An allowed model that is unentitled, not listed by the gateway, or excluded by user preference is `MODEL_UNAVAILABLE`, with the reason. PiShip never substitutes another model. If no allowed model is available, launch fails with `MODEL_UNAVAILABLE`.

The distribution allowlist is the ceiling: every other list only removes models from it. With `models.allowed: [A, B]`, a credential entitled to `B, C`, and a gateway listing `B, C, D`, the only available model is `B`; `A` is `MODEL_UNAVAILABLE` (not entitled), and `C` and `D` are `MODEL_DENIED`. A gateway listing never authorizes a model, and an enforced model does not override a narrower entitlement: if the enforced model is not entitled, launch fails with `MODEL_UNAVAILABLE`.

A piship/v1alpha6 virtual model (`models.catalog.<id>.virtual`) is the exception to the gateway listing: the gateway never lists it, so it is available when at least one of its declared `routes` is allowed, entitled, and listed, and is otherwise `MODEL_UNAVAILABLE` ("none of its routes is available"). The user's narrowing applies to the virtual model itself, and the routes of a virtual model the user keeps stay available to it. A request it routes is decided again as `model.dispatch` for the physical model, and a target outside `routes` is refused with `MODEL_DENIED` ([security](security.md#tools-shell-and-plan-mode)).

### Entitlement freshness

The entitlement is the `models` list the broker or adapter returned with the credential, stored in the credential metadata. It is read again only when the credential is acquired or renewed:

- at every `login`, which always replaces the runtime credential;
- when a credential with `expires_at` is renewed before it expires;
- after the gateway denies a model (HTTP 403, `MODEL_DENIED`) on a request: `DistributionAccess.refreshEntitlement()` renews the credential once through the refresh path. It does this at most once per credential generation, so a denial of the renewed credential is taken as the organization's answer and re-issues nothing. A failed renewal keeps the current credential and is reported; the next denial tries again.

A credential without `expires_at` is otherwise never renewed, so between these events its entitlement stays as issued: a model the organization adds is not offered, and a model it withdraws is still offered until the gateway denies it. The new entitlement applies from the next launch; within a session the gateway enforces its own decision. However wide a re-read entitlement is, it only narrows the distribution allowlist.

The model is chosen from `--model <id>`, then the configuration layers: an enforced value always wins; otherwise a user preference applies if the key is user-overridable; otherwise the distribution default (`models.default`) applies. When `config.enforced.model` is set, it is the only selectable model: `--model`, a preference, and in-session `/model` cannot choose another. `models` lists the catalog with availability and reasons; `config explain` shows each value and its source.

## Gateway status

`GET {baseUrl}/models` (the live catalog at launch, and `doctor`) shows that the gateway is reachable, that it accepts the runtime credential, and which models it lists for it. It does not reach a model provider behind the gateway: a gateway such as LiteLLM answers it from its own configuration, so a provider that is down, refuses the gateway's own provider key, or rate limits it shows only when a request is sent (in a session, or with `--smoke-model`). `doctor` says `model providers not contacted` for this reason. An answer is classified as:

| Status | Code |
| --- | --- |
| 401 | `CREDENTIAL_REVOKED` |
| 403 | `MODEL_DENIED` |
| 401 or 403 whose error message starts with `litellm.`, unless its type is one of LiteLLM's own refusals (`auth_error`, `token_not_found_in_db`, `expired_key`, `key_model_access_denied`) | `GATEWAY_UNREACHABLE`, not retryable: LiteLLM relays its model provider's refusal (a provider key or permission of the gateway's), which says nothing about the runtime credential or its entitlement |
| 404 | `MODEL_UNAVAILABLE` |
| 429 | `GATEWAY_RATE_LIMITED`, retryable; `Retry-After` (seconds or HTTP date) is shown as `Retry after: <n> s`. Without it, LiteLLM's `llm_provider-retry-after` (the provider's value it relays) is used, at most one hour |
| 5xx, network failure, timeout (15 s, including the body) | `GATEWAY_UNREACHABLE`, retryable |
| Other 4xx, malformed list | `GATEWAY_PROTOCOL_ERROR` |

During a session, Pi performs the request. PiShip recognizes an authentication rejection (401, unauthorized, invalid API key) on Pi's error message, marks the credential rejected, and renews it before the next request. The rejected request is not replayed. Other in-session gateway errors are reported by Pi in the conversation; after a model denial (403), PiShip also re-reads the credential entitlement once, as described in [entitlement freshness](#entitlement-freshness). A 401 or 403 that LiteLLM relays from its model provider (Pi's message carries the status and the gateway's error object, whose message starts with `litellm.`) is neither: the credential is not marked and the entitlement is not re-read. `--smoke-model` reports a failed acceptance request with the code the table above gives for the status and error body in Pi's message (a 503 is `GATEWAY_UNREACHABLE`, a gateway 401 `CREDENTIAL_REVOKED`) with its retry flag (Pi's message carries no headers, so no retry time). A request without a status is classified by structured information only, never by the provider's text:

| Failure | Code |
| --- | --- |
| Aborted by the caller (Pi's stop reason `aborted`, which Pi sets only when the caller's signal aborted the request) | `REQUEST_CANCELLED`, not retryable |
| Managed endpoint, no answer: a refused or reset connection, a DNS failure, or the request deadline | `GATEWAY_UNREACHABLE`, retryable; `detail.transport` and the end of the message name the system error code (`ECONNREFUSED`, `ENOTFOUND`), `timeout`, or `network error` |
| A stream that failed after it started, or a Pi-native provider's request that got no answer | `GATEWAY_PROTOCOL_ERROR` |

Pi's message keeps only the SDK's text for a request that got no answer ("Connection error.", "Request timed out."), so for a managed endpoint PiShip passes its own `fetch` through Pi's public request option and records what it saw: the system error code of the failed connection, or that the request was aborted although the caller had not aborted it (the client's deadline). It forwards each request to the global `fetch` unchanged. A Pi-native provider's request is not observed, because some of Pi's adapters refuse a custom `fetch`. `REQUEST_CANCELLED` is an additive error code (#85): a cancellation is not a gateway failure, and no earlier code described it.

## Failure policy

| Situation | Result |
| --- | --- |
| Runtime variable missing or empty | `CONFIG_UNAVAILABLE`; fail closed |
| Not signed in | `IDENTITY_REQUIRED` |
| Broker returns 5xx or 429 | `CREDENTIAL_ACQUIRE_FAILED`, retryable |
| Broker unreachable or timed out | `CREDENTIAL_ACQUIRE_FAILED`, retryable |
| Broker denies the request (403) | `CREDENTIAL_DENIED`, not retryable |
| Caller cancels the acquire | `CREDENTIAL_ACQUIRE_FAILED`, not retryable |
| No stored `local-secret` | `CREDENTIAL_REQUIRED` |
| Credential expired and cannot be renewed | `CREDENTIAL_EXPIRED` |
| Gateway rejects the credential | One automatic renewal; if renewal fails, `CREDENTIAL_REVOKED` with the failure's `retryable` and `retryAfterMs`, except that specific codes such as `IDENTITY_EXPIRED`, `NETWORK_DENIED`, `TLS_POLICY_VIOLATION`, and `CREDENTIAL_DENIED` are kept |
| Selected model misses an enabled capability's `requirements`, or its metadata is unknown | `MODEL_INCOMPATIBLE`; no substitution |
| Gateway outage | `GATEWAY_UNREACHABLE` at launch with `liveCatalog: true` and in `doctor`; otherwise Pi reports the failed request |
| Model outside the allowlist | `MODEL_DENIED` |
| A routed request to a model outside the declared `routes`, or one `model.dispatch` denies | `MODEL_DENIED` |
| Model unentitled, unlisted, or narrowed out | `MODEL_UNAVAILABLE` |
| Undeclared host under `privateOnly` | `NETWORK_DENIED` |
| Non-loopback plain HTTP endpoint | Admitted when the host is private or internal, unless `inference.httpTransport: https` (piship/v1alpha6) forces HTTPS-only, which gives `NETWORK_DENIED`; then only the gateway's own origin is admitted over plain HTTP, and the credential and prompts travel unencrypted ([manifest](manifest.md#plain-http-to-internal-endpoints-v1alpha6)) |
| Plain HTTP to a public host | Refused by `validate`; a `${NAME}` that resolves to one fails the launch with `CONFIG_INVALID` |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | `TLS_POLICY_VIOLATION` |
| Platform secret store unavailable | `SECRET_STORE_UNAVAILABLE` |

Managed mode never falls back to a personal or public provider. Errors carry a code, a redacted message, a retryable flag, and a user action where one applies.

The token-free context that approved extensions can read is described in [identity](identity.md#extension-context).
