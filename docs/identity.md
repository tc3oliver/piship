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

`IdentitySession` carries `subject`, `issuer`, optional `displayName`, `email`, `expiresAt`, non-secret `claims`, and `accessToken`, `idToken`, and `refreshToken` as `SecretValue`. `LoginContext.openUrl` presents the authorization URL.

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
- Refresh with the refresh token when the session expires within 60 seconds. A refreshed ID token must keep the same subject and issuer. Refresh is serialized across processes with a lock beside `identity/session.json`, and a session another process already refreshed is reused. Refreshes are audited as `identity.refresh`.
- On `logout`, refresh and access tokens are revoked when the provider advertises a revocation endpoint.

The branded `login` prints the authorization URL and tries to open a browser; set `PISHIP_NO_BROWSER=1` to only print it. All OIDC requests use the managed fetch, so TLS, proxy, CA, and private-only rules in [security](security.md#network-and-tls) apply.

Only non-secret, display-relevant claims (`sub`, `iss`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `name`, `preferred_username`, `email`, `email_verified`, `groups`) are kept in `identity/session.json` (`piship-identity-metadata/v1`). The tokens are one secret in the configured secret store, under a generation reference.

## Errors

| Situation | Code |
| --- | --- |
| Not signed in, sign-in cancelled or timed out, redirect port unavailable | `IDENTITY_REQUIRED` |
| Denied or rejected authorization, failed ID token or discovery check, revocation failure | `IDENTITY_INVALID` |
| Refresh rejected (`invalid_grant`), no refresh token, token outside its validity window | `IDENTITY_EXPIRED` |

Network failures keep their network codes (`GATEWAY_UNREACHABLE`, `NETWORK_DENIED`, `TLS_POLICY_VIOLATION`). When the broker rejects an expired identity access token, PiShip refreshes the identity once and retries.

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
