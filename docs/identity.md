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

`IdentitySession` carries `subject`, `issuer`, optional `displayName`, `email`, `expiresAt`, non-secret `claims`, and `accessToken`, `idToken`, and `refreshToken` as `SecretValue`. `LoginContext.openUrl` presents the authorization URL. An identity adapter may also declare `interactive: false` to supply a [workload identity](#workload-identity-headless-runs); `WorkloadIdentityProvider` is defined in `@piship/contracts` (and reaches adapter authors through `@piship/adapter-sdk`); `@piship/identity` re-exports it unchanged and adds the `isWorkloadIdentityProvider` guard.

## Modes

| `identity.mode` | Behavior |
| --- | --- |
| `none` | No enterprise identity, so no principal: credentials and state are bound to nobody and are not compared with anyone at launch. Personal only |
| `oidc` | Built-in OIDC Authorization Code + PKCE |
| `adapter` | A packaged module that default-exports a factory `(context) => IdentityProvider`, where `context` has `distributionId`, the managed `fetch`, and resolved `endpoints`. The adapter is locked and integrity-checked like other resources. Its `login`, `refresh`, and `logout` each have a deadline and a signal that aborts at it ([deadlines](adapter-sdk.md#deadlines)) |

## OIDC

The built-in provider uses the maintained `openid-client` library as a native public client (`token_endpoint_auth_method: none`, no client secret):

- Discovery from `issuer`/.well-known/openid-configuration. A provider that advertises PKCE methods without `S256` is rejected.
- Authorization Code with PKCE `S256`, `state`, and `nonce`. `audience` is sent when configured.
- ID token checks: issuer, audience, authorized party, signature (`enableNonRepudiationChecks`), expiry and not-before with 30 seconds of clock tolerance, and nonce.
- A loopback redirect (RFC 8252). PiShip listens on the registered `redirectUri`, for example `http://127.0.0.1:8765/callback`, answers only that path, and closes the listener after completion, a 5-minute timeout, or cancellation. Only a callback that carries the `state` of the sign-in in progress completes it, and the first such callback wins. Any other request is refused and the sign-in keeps waiting, so a favicon request, a browser tab left from an earlier login, or a forged or stateless callback cannot end it; the timeout or cancellation names how many callbacks were refused and an OAuth error code one of them carried, such as `unauthorized_client`. The `state` is checked again with the code exchange. Register the exact URI with the provider.
- Refresh with the refresh token when the session expires within 60 seconds. A refreshed ID token must keep the same subject and issuer; otherwise the refresh fails with `IDENTITY_INVALID` and the stored session is kept. Refresh is serialized across processes with a lock beside `identity/session.json`, and a session another process already refreshed is reused. Refreshes are audited as `identity.refresh`.
- On `logout`, refresh and access tokens are revoked when the provider advertises a revocation endpoint.

The branded `login` prints the authorization URL and tries to open a browser; set `PISHIP_NO_BROWSER=1` to only print it. Below the URL it says where the browser must return (the redirect), how long it waits (5 minutes), and that Ctrl-C cancels; Ctrl-C ends the wait as a cancelled sign-in (`IDENTITY_REQUIRED`) and closes the listener, and a second Ctrl-C ends the process. An identity provider that does not know the client ID or the redirect URI shows its own error page and, as OAuth requires, never redirects back, so `login` cannot detect it: the hint says to press Ctrl-C and have the client registration checked when the browser shows a provider error instead of a sign-in page.

### Remote shells

The redirect is a loopback address on the machine that runs `login`, so the browser must run there, reach it, or hand the result back by hand. In a remote shell (`SSH_CONNECTION`, `SSH_CLIENT`, or `SSH_TTY` set) or with `PISHIP_NO_BROWSER=1`, `login` prints both ways below.

**Paste the address (no port forward).** `login` listens for a pasted address only in a remote shell (`SSH_CONNECTION`, `SSH_CLIENT`, or `SSH_TTY` is set) or with `PISHIP_NO_BROWSER=1`; with a local browser it reads nothing from the terminal, so a stray line typed there cannot end the sign-in. Open the printed URL in a browser on any computer and sign in. The browser then goes to `127.0.0.1:8765` and shows "can't connect"; that is expected. Copy the full address from the browser's address bar (or only its `code` value), paste it into the terminal where `login` waits, and press Enter. The pasted address must be this sign-in's redirect (the same scheme, host, port, and path) and carry this sign-in's `state`; anything else is refused with a short message and `login` keeps waiting, as it does for a stray loopback request. A bare `code` has no `state` to check and relies on PKCE. A code that expired or belongs to another sign-in ends the attempt after the failed exchange; run `login` again. The address is rebuilt from the registered redirect, so a pasted user name, password, or `#fragment` is dropped, and an address that repeats `state` or `code` is refused. Some terminals limit a pasted line (about 1000 to 4000 characters); the address-bar URL is usually shorter than that for Entra. If the paste is truncated, run `login` again or use the port forward. The loopback listener and the paste race: whichever finishes first ends the other, and the code is exchanged exactly as for a loopback callback, with the same `state`, `nonce`, and PKCE checks and the same error mapping (a pasted `error=` is reported like a callback's). Nothing is added to the manifest or the lock. Stdin that is closed or at end of input offers no paste and leaves the loopback as it is.

**Forward the port.** In another terminal on the computer with the browser, for example:

```sh
ssh -N -L 8765:127.0.0.1:8765 <remote host>
```

Then open the printed URL in that browser: the provider redirects it to `127.0.0.1:8765`, which the forward carries to the waiting `login`. The local port must be free on the browser's computer too. With a redirect that has no port (an ephemeral port), the port is known only once `login` prints the URL; start the forward then. Otherwise run `login` on the computer with the browser. All OIDC requests use the managed fetch, so TLS, proxy, CA, and private-only rules in [security](security.md#network-and-tls) apply.

Only non-secret, display-relevant claims (`sub`, `iss`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `name`, `preferred_username`, `email`, `email_verified`, `groups`) are kept in `identity/session.json` (`piship-identity-metadata/v1`), with scalar or string-array values only. Claims returned by an identity adapter are filtered to the same allowlist. The allowlist is `RETAINED_CLAIMS`, defined in `@piship/contracts` (and exported by `@piship/adapter-sdk`); `@piship/identity` re-exports it unchanged with `retainClaims`, the filter. The tokens are one secret in the configured secret store, under a generation reference.

## Principal

The signed-in user is the normalized principal `(iss, sub)`: the issuer and the subject, compared as exact strings. Email, display name, username, and other claims are attributes that may change and never identify the user. `@piship/contracts` exports the key (`PrincipalKey`, `principalKey`, `samePrincipal`), a string form for attribution (`principalId`: the issuer with `%` and `#` percent-encoded, `#`, then the subject), and a fixed-length digest for per-principal directory names (`principalDigest`).

- A refresh, from the built-in provider or an identity adapter, must return the same principal; anything else is `IDENTITY_INVALID`, whatever the provider returned.
- The runtime credential, its entitlement, and the model selection belong to the principal. Signing in as another principal clears them first; see [user switching](security.md#user-switching).
- `identity/principal.json` records the principal that owns the state. `logout` keeps it, so a different user signing in after a logout is still recognized as a change of user. An unreadable record counts as a change; so does a missing one (state from a release before v0.7), unless the stored session is the signing-in principal's, in which case the record is created and nothing is cleared.
- A running session is pinned to the principal it started with: once another user signs in elsewhere, it fails with `IDENTITY_REQUIRED` instead of using either user's credential ([user switching](security.md#user-switching)).

## Workload identity (headless runs)

A managed distribution's non-interactive surfaces (`--smoke`, `--smoke-model`, and the subcommands) can run without a person: in CI, scheduled automation, or a managed worker. There is no non-interactive prompt or RPC mode in this release, and the interactive command refuses to start without a terminal ([headless runs](enterprise-integration.md#headless-and-workload-runs)). The identity is then a workload identity, supplied by an identity adapter that declares itself non-interactive. There is no manifest change: it is `identity.mode: adapter`.

```js
// adapters/workload-identity.mjs next to piship.yaml, declared as
//   identity: { mode: adapter, adapter: ./adapters/workload-identity.mjs }
import { readFileSync } from "node:fs";

export default (context) => ({
  kind: "acme-workload",
  interactive: false,
  async login() {
    // Read the token the platform provides: a projected service account
    // token, a CI job token, or a token exchange through context.fetch. The
    // variable names only where the token is; a managed launch removes
    // credential-named variables such as *_TOKEN_* before the adapter loads.
    const token = readFileSync(process.env.ACME_WORKLOAD_IDENTITY_PATH, "utf8").trim();
    // Take the principal from the token itself, never from a side field that
    // can go stale. PiShip does not verify the token: the broker does.
    const claims = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
    );
    return {
      issuer: claims.iss,
      subject: claims.sub,
      accessToken: token,
      expiresAt: new Date(claims.exp * 1000),
    };
  },
});
```

What a workload adapter must implement:

- `interactive: false`. Anything other than `true`, `false`, or absent is refused with `CONFIG_INVALID`; absent or `true` is the interactive path described above, unchanged.
- `login(ctx)`, which returns a session without a person: `issuer` and `subject` (the principal), the `accessToken` the broker accepts as the bearer (or whatever the credential adapter needs), and `expiresAt` when the token expires. `expiresAt` is required: a session without it is refused with `IDENTITY_INVALID`. It must never call `ctx.openUrl`: the one it receives fails the run with `IDENTITY_INVALID`, even if the adapter catches the refusal and returns a session anyway. A session that is already expired fails with `IDENTITY_EXPIRED`.
- An answer within 30 seconds (`ctx.signal` is aborted then, and on a cancelled `login`). A `login` that takes longer fails the run with a retryable `GATEWAY_UNREACHABLE` ("The workload identity adapter did not answer"). Anything else it throws fails the run with `IDENTITY_INVALID` ("could not obtain a session") and without the adapter's own message, which may quote the token source; PiShip's own coded errors from `context.fetch` (such as `NETWORK_DENIED`) keep their code.
- Network requests only through `context.fetch`, the managed fetch, so the distribution's TLS, proxy, CA, and private-only rules apply ([security](security.md#network-and-tls)).
- Its token source outside credential-named environment variables. In a managed distribution PiShip removes variables such as `*_TOKEN`, `*_SECRET`, `*_API_KEY`, and provider prefixes before any adapter loads, so read a token file, a platform endpoint, or a non-secret variable that names where the token is (for example `ACME_WORKLOAD_IDENTITY_PATH`).
- `refresh` and `logout` are not used for a workload identity: PiShip calls `login` again instead, and never hands any session (a workload's or a stored person's) to the adapter's `logout`.
- A token file the adapter reads is checked by the adapter: mode 0600 and owned by the job user, not a symlink, not inside the workspace the agent can read, and bounded in size. PiShip cannot check it for you.
- A subject that identifies one workload. The subject is the isolation granularity: workloads that present the same `(iss, sub)` (for example every pod of one Kubernetes service account, or every run of one repository and branch) share one runtime credential, one entitlement, and one session history directory. Use a token whose subject names what must be kept apart.
- One state directory per workload principal. Two workloads with different principals on one state directory (the default state home of one OS user) revoke each other's credential on every activation, because each finds the other's credential bound to a different principal. Give each workload its own `PISHIP_STATE_HOME`.

How PiShip uses it:

- Every launch, `doctor`, and `login` obtains the session from `login()`; no prior `login` and no stored session are needed. The session is held in memory for the process and never stored: no `identity/session.json` and no identity secret in the secret store. `login` works too (it replaces the runtime credential) and needs no browser.
- The session is obtained again when it expires within 60 seconds, when it is five minutes old (so a token the platform rotated is picked up even if the old one is valid longer), and once when the broker rejects its token (HTTP 401). Concurrent callers in one process share one `login()` call. A new session inside one process must name the same principal, or the run fails with `IDENTITY_INVALID`; if the adapter keeps returning a rejected token, the run fails with `IDENTITY_EXPIRED`.
- The workload principal follows the same rules as a person ([principal](#principal), [user switching](security.md#user-switching)). The runtime credential and entitlement are bound to it, the principal binding records it, and when a later run's workload identity is another principal, the previous principal's credential is revoked where supported and deleted, its model selection cleared, and a stored identity session of another principal, or one that cannot be read, deleted (confirmed) before anything is used. A deletion that cannot be confirmed fails the run closed.
- `identity.login` (and `identity.refresh` for a renewed session) is audited with `workload: true`.

The runtime credential still comes from `credential.provider: http-broker`, with the workload access token as the bearer, or from a credential adapter. It is stored in the configured secret store ([headless storage](credentials.md#headless-runs)).

## Errors

| Situation | Code |
| --- | --- |
| Not signed in, sign-in cancelled or timed out | `IDENTITY_REQUIRED` |
| The registered redirect port is in use (another `login` still running, say) or cannot be bound | `CONFIG_UNAVAILABLE`, naming the port and how to find what holds it |
| Denied or rejected authorization, failed ID token or discovery check, revocation failure. A provider error that names the client registration (`unauthorized_client`, `invalid_client`, `invalid_request`, `invalid_scope`, `unsupported_response_type`) says to check the client ID, redirect URI, and scopes | `IDENTITY_INVALID` |
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
