# Identity

`@piship/identity` signs a user in to an organization identity provider. Identity is separate from credentials and inference: it proves who the user is, and a [credential provider](credentials.md) may use that session to obtain a runtime credential. PiShip integrates with an identity provider; it is not one.

## Contract

```ts
interface IdentityProvider {
  readonly kind: string;
  login(ctx: LoginContext): Promise<IdentitySession>;
  refresh?(session: IdentitySession): Promise<IdentitySession>;
  logout?(session: IdentitySession): Promise<void>;
}
```

`IdentitySession` carries `subject`, `issuer`, optional `displayName`, `email`, `expiresAt`, non-secret `claims`, and `accessToken`, `idToken`, and `refreshToken` as `SecretValue`. `LoginContext.openUrl` presents the authorization URL. An identity adapter may also declare `interactive: false` to supply a [workload identity](#workload-identity-headless-runs); `@piship/identity` exports `WorkloadIdentityProvider` and `isWorkloadIdentityProvider` for it.

## Modes

| `identity.mode` | Behavior |
| --- | --- |
| `none` | No enterprise identity. Personal only |
| `oidc` | Built-in OIDC Authorization Code + PKCE |
| `adapter` | A packaged module that default-exports a factory `(context) => IdentityProvider`, where `context` has `distributionId`, the managed `fetch`, and resolved `endpoints`. The adapter is locked and integrity-checked like other resources |

## OIDC

The built-in provider uses the maintained `openid-client` library as a native public client (`token_endpoint_auth_method: none`, no client secret):

- Discovery from `issuer`/.well-known/openid-configuration. A provider that advertises PKCE methods without `S256` is rejected.
- Authorization Code with PKCE `S256`, `state`, and `nonce`. `audience` is sent when configured.
- ID token checks: issuer, audience, authorized party, signature (`enableNonRepudiationChecks`), expiry and not-before with 30 seconds of clock tolerance, and nonce.
- A loopback redirect (RFC 8252). PiShip listens on the registered `redirectUri`, for example `http://127.0.0.1:8765/callback`, answers only that path, accepts the first callback, and closes the listener after completion, a 5-minute timeout, or cancellation. Register the exact URI with the provider.
- Refresh with the refresh token when the session expires within 60 seconds. A refreshed ID token must keep the same subject and issuer; otherwise the refresh fails with `IDENTITY_INVALID` and the stored session is kept. Refresh is serialized across processes with a lock beside `identity/session.json`, and a session another process already refreshed is reused. Refreshes are audited as `identity.refresh`.
- On `logout`, refresh and access tokens are revoked when the provider advertises a revocation endpoint.

The branded `login` prints the authorization URL and tries to open a browser; set `PISHIP_NO_BROWSER=1` to only print it. All OIDC requests use the managed fetch, so TLS, proxy, CA, and private-only rules in [security](security.md#network-and-tls) apply.

Only non-secret, display-relevant claims (`sub`, `iss`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `name`, `preferred_username`, `email`, `email_verified`, `groups`) are kept in `identity/session.json` (`piship-identity-metadata/v1`), with scalar or string-array values only. Claims returned by an identity adapter are filtered to the same allowlist. The tokens are one secret in the configured secret store, under a generation reference.

## Principal

The signed-in user is the normalized principal `(iss, sub)`: the issuer and the subject, compared as exact strings. Email, display name, username, and other claims are attributes that may change and never identify the user. `@piship/contracts` exports the key (`PrincipalKey`, `principalKey`, `samePrincipal`), a string form for attribution (`principalId`: the issuer with `%` and `#` percent-encoded, `#`, then the subject), and a fixed-length digest for per-principal directory names (`principalDigest`).

- A refresh, from the built-in provider or an identity adapter, must return the same principal; anything else is `IDENTITY_INVALID`, whatever the provider returned.
- The runtime credential, its entitlement, and the model selection belong to the principal. Signing in as another principal clears them first; see [user switching](security.md#user-switching).
- `identity/principal.json` records the principal that owns the state. `logout` keeps it, so a different user signing in after a logout is still recognized as a change of user.

## Workload identity (headless runs)

A managed distribution can run without a person: in CI, scheduled automation, a headless RPC service, or a managed worker. The identity is then a workload identity, supplied by an identity adapter that declares itself non-interactive. There is no manifest change: it is `identity.mode: adapter`.

```js
// resources/adapters/workload-identity.mjs, declared as
//   identity: { mode: adapter, adapter: ./adapters/workload-identity.mjs }
import { readFileSync } from "node:fs";

export default (context) => ({
  kind: "acme-workload",
  interactive: false,
  async login() {
    // Read the token the platform provides: a projected service account
    // token, a CI job token, or a token exchange through context.fetch.
    const document = JSON.parse(
      readFileSync(process.env.ACME_WORKLOAD_IDENTITY_PATH, "utf8"),
    );
    return {
      issuer: document.issuer,
      subject: document.subject,
      accessToken: document.token,
      expiresAt: document.expiresAt,
    };
  },
});
```

What a workload adapter must implement:

- `interactive: false`. Anything other than `true`, `false`, or absent is refused with `CONFIG_INVALID`; absent or `true` is the interactive path described above, unchanged.
- `login(ctx)`, which returns a session without a person: `issuer` and `subject` (the principal), the `accessToken` the broker accepts as the bearer (or whatever the credential adapter needs), and `expiresAt` when the token expires. It must never call `ctx.openUrl`: the one it receives fails the run with `IDENTITY_INVALID`. A session that is already expired fails with `IDENTITY_EXPIRED`.
- Network requests only through `context.fetch`, the managed fetch, so the distribution's TLS, proxy, CA, and private-only rules apply ([security](security.md#network-and-tls)).
- Its token source outside credential-named environment variables. In a managed distribution PiShip removes variables such as `*_TOKEN`, `*_SECRET`, `*_API_KEY`, and provider prefixes before any adapter loads, so read a token file, a platform endpoint, or a non-secret variable that names where the token is (for example `ACME_WORKLOAD_IDENTITY_PATH`).
- `refresh` and `logout` are not used for a workload identity: PiShip calls `login` again instead.

How PiShip uses it:

- Every launch, `doctor`, and `login` obtains the session from `login()`; no prior `login` and no stored session are needed. The session is held in memory for the process and never stored: no `identity/session.json` and no identity secret in the secret store. `login` works too (it replaces the runtime credential) and needs no browser.
- The session is obtained again when it expires within 60 seconds, and once when the broker rejects its token (HTTP 401). A new session inside one process must name the same principal, or the run fails with `IDENTITY_INVALID`; if the adapter keeps returning a rejected token, the run fails with `IDENTITY_EXPIRED`.
- The workload principal follows the same rules as a person ([principal](#principal), [user switching](security.md#user-switching)). The runtime credential and entitlement are bound to it, the principal binding records it, and when a later run's workload identity is another principal, the previous principal's credential is revoked where supported and deleted, its model selection cleared, and a stored identity session of another principal deleted (confirmed) before anything is used. A deletion that cannot be confirmed fails the run closed.
- `identity.login` (and `identity.refresh` for a renewed session) is audited with `workload: true`.

The runtime credential still comes from `credential.provider: http-broker`, with the workload access token as the bearer, or from a credential adapter. It is stored in the configured secret store ([headless storage](credentials.md#headless-runs)).

## Errors

| Situation | Code |
| --- | --- |
| Not signed in, sign-in cancelled or timed out, redirect port unavailable | `IDENTITY_REQUIRED` |
| Denied or rejected authorization, failed ID token or discovery check, revocation failure | `IDENTITY_INVALID` |
| Refresh rejected (`invalid_grant`), no refresh token, token outside its validity window | `IDENTITY_EXPIRED` |

Network failures keep their network codes (`GATEWAY_UNREACHABLE`, `NETWORK_DENIED`, `TLS_POLICY_VIOLATION`); an OIDC request that times out (30 s) is a retryable `GATEWAY_UNREACHABLE`. A token endpoint answer of 5xx (including an HTML error page from a proxy), `server_error`, or `temporarily_unavailable` is also a retryable `GATEWAY_UNREACHABLE`, and a 429 is a retryable `GATEWAY_RATE_LIMITED`; both carry the server's `Retry-After` when it sends one. `invalid_grant` stays `IDENTITY_EXPIRED`. When the broker rejects an expired identity access token, PiShip refreshes the identity once and retries.

## Extension context

The branded command publishes a frozen, token-free object for distribution extensions at `globalThis[Symbol.for("piship.enterprise-context/v1")]`:

```ts
{
  version: 1,
  distribution: { id, name, version, mode },
  identity: { subject, issuer, displayName?, email? } | null,
  credential: { mode, credentialId?, expiresAt? },
  inference: {
    provider,
    models: [{ id, name, policyTags }],   // allowed and available only
    defaultModel?,
    selectedModel?,                        // updated on model selection
  },
  config: { [key]: { value, source } },
}
```

It never contains access, ID, or refresh tokens or the runtime credential. It is set before Pi starts, updated when the user selects a model, and removed when the runtime is disposed. Any code running in the process can read it; it is for approved, packaged extensions, not an access-controlled channel. The [demo company extension](../examples/demo-company/resources/extensions/enterprise-context/index.ts) shows a tool that reads it.
