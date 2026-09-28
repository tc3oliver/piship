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

For `openai-compatible`, the Pi runtime gets one provider named after the app ID, so a model appears as `<app id>/<model id>`. Request authentication is resolved per request: PiShip refreshes the credential before expiry and passes the secret only to Pi's request path.

## Model catalog

The effective catalog is an intersection that can only narrow:

1. The distribution's `models.allowed` and `models.catalog` metadata.
2. The credential entitlement, when the broker returns `models`.
3. The live gateway listing from `GET {baseUrl}/models`, when `liveCatalog: true`.
4. The user's optional `models.allowed` preference, set with `config set models.allowed a,b`. It can only remove models.

A model outside the distribution allowlist, or a Pi model in managed mode, is refused with `MODEL_DENIED`. An allowed model that is unentitled, not listed by the gateway, or excluded by user preference is `MODEL_UNAVAILABLE`, with the reason. PiShip never substitutes another model. If no allowed model is available, launch fails with `MODEL_UNAVAILABLE`.

The model is chosen from `--model <id>`, then the configuration layers: an enforced value always wins; otherwise a user preference applies if the key is user-overridable; otherwise the distribution default (`models.default`) applies. When `config.enforced.model` is set, it is the only selectable model: `--model`, a preference, and in-session `/model` cannot choose another. `models` lists the catalog with availability and reasons; `config explain` shows each value and its source.

## Gateway status

`GET {baseUrl}/models` (the live catalog at launch, and `doctor`) is classified as:

| Status | Code |
| --- | --- |
| 401 | `CREDENTIAL_REVOKED` |
| 403 | `MODEL_DENIED` |
| 404 | `MODEL_UNAVAILABLE` |
| 429 | `GATEWAY_RATE_LIMITED`, retryable; `Retry-After` (seconds or HTTP date) is shown as `Retry after: <n> s` |
| 5xx, network failure, timeout (15 s, including the body) | `GATEWAY_UNREACHABLE`, retryable |
| Other 4xx, malformed list | `GATEWAY_PROTOCOL_ERROR` |

During a session, Pi performs the request. PiShip recognizes an authentication rejection (401, unauthorized, invalid API key) on Pi's error message, marks the credential rejected, and renews it before the next request. The rejected request is not replayed. Other in-session gateway errors are reported by Pi in the conversation. `--smoke-model` reports a failed acceptance request as `GATEWAY_PROTOCOL_ERROR`.

## Failure policy

| Situation | Result |
| --- | --- |
| Runtime variable missing or empty | `CONFIG_UNAVAILABLE`; fail closed |
| Not signed in | `IDENTITY_REQUIRED` |
| Broker returns 5xx or 429 | `CREDENTIAL_ACQUIRE_FAILED`, retryable |
| Broker unreachable or timed out | `CREDENTIAL_ACQUIRE_FAILED`, retryable |
| No stored `local-secret` | `CREDENTIAL_REQUIRED` |
| Credential expired and cannot be renewed | `CREDENTIAL_EXPIRED` |
| Gateway rejects the credential | One automatic renewal; if renewal fails, `CREDENTIAL_REVOKED`, except that specific codes such as `IDENTITY_EXPIRED`, `NETWORK_DENIED`, and `TLS_POLICY_VIOLATION` are kept |
| Selected model misses an enabled capability's `requirements`, or its metadata is unknown | `MODEL_INCOMPATIBLE`; no substitution |
| Gateway outage | `GATEWAY_UNREACHABLE` at launch with `liveCatalog: true` and in `doctor`; otherwise Pi reports the failed request |
| Model outside the allowlist | `MODEL_DENIED` |
| Model unentitled, unlisted, or narrowed out | `MODEL_UNAVAILABLE` |
| Undeclared host under `privateOnly` | `NETWORK_DENIED` |
| Non-loopback plain HTTP endpoint | `NETWORK_DENIED` |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | `TLS_POLICY_VIOLATION` |
| Platform secret store unavailable | `SECRET_STORE_UNAVAILABLE` |

Managed mode never falls back to a personal or public provider. Errors carry a code, a redacted message, a retryable flag, and a user action where one applies.

The token-free context that approved extensions can read is described in [identity](identity.md#extension-context).
