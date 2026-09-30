# Adapter SDK

`@piship/adapter-sdk` is the supported surface for writing a company adapter: an identity adapter (`identity.mode: adapter`), a credential adapter (`credential.provider: adapter`), a custom sandbox backend (`sandbox.provider: custom`), or the audit collector behind the built-in `http` audit sink. An adapter imports nothing else from PiShip.

Status: preview. The package is built to a publishable shape but is `private: true` and not published to npm; publishing needs a separate maintainer decision ([decision 21](decisions.md)). Conformance kits that test an adapter through the SDK only, `@piship/adapter-conformance`, are described below (audit sink, credential, identity, sandbox).

The SDK is thin on purpose. It re-exports public contracts, and its helpers either return their argument unchanged or wrap one public function. It is not a framework: an adapter is still a plain module whose default export PiShip's loader calls.

## An adapter is one file

PiShip packages exactly the file the manifest names, under `resources/` in the payload, and records its digest in the lock. Two consequences:

- A relative import of a sibling file (`./helpers.mjs`) is not packaged, so the adapter fails to load from the payload. Keep the adapter in one file, or bundle it into one before locking.
- A bare import (`@piship/adapter-sdk`, `undici`) resolves only from the payload's own `node_modules`. The payload contains PiShip's packages, including the SDK, and their production dependencies, and nothing else. Import only `@piship/adapter-sdk` and `node:` built-ins, or bundle any other dependency into the file.

The payload's SDK is the one built with the PiShip version that built the distribution, so an adapter that imports it always gets the SDK matching the loader. A bundled copy of the SDK also works: the loaders re-wrap an adapter's secrets, so a second `SecretValue` class inside a bundle still redacts. Prefer the import.

## Helpers

| Helper | Default export of | What it does |
| --- | --- | --- |
| `defineIdentityAdapter(factory)` | an identity adapter | Returns `factory`, typed `(context: AdapterContext) => IdentityProvider` |
| `defineCredentialAdapter(factory)` | a credential adapter | Returns `factory`, typed `(context: AdapterContext) => CredentialProvider` |
| `defineSandboxAdapter(factory)` | a custom sandbox adapter | Returns a factory that passes the backend `factory` builds through `customBackend()`, the check the loader applies, so a malformed backend also fails in the adapter's own tests. The result is a `SandboxBackend` with `provider: custom` |
| `defineAuditSink(sink)` | nothing (see below) | Returns `sink`, typed `AuditSink` |
| `withTimeout(ms, signal?)` | | A signal that aborts when `signal` does or after `ms`, whichever is first |

`defineSandboxAdapter` builds a sandbox *backend* (`SandboxBackend`), where the service or mechanism runs each command. It is not the native OS mechanism that `@piship/sandbox` calls a `SandboxAdapter` (bubblewrap or Seatbelt), which a distribution does not supply.

A distribution cannot declare its own audit sink type: the manifest accepts `file` and `http` sinks only. `defineAuditSink` types the receiving side of the `http` sink, the collector that stores `piship-audit-batch/v1` batches ([wire contract](enterprise-integration.md#audit-collector-piship-audit-batchv1)), or a test double. A collector hands each request body to `write(batch, signal)` and answers 2xx only once it resolved; a resent batch repeats event IDs it may already have stored.

## Surface

Everything else is re-exported unchanged from `@piship/contracts` or `@piship/sandbox`:

- Context: `AdapterContext` (`distributionId`, the managed `fetch`, resolved `endpoints`), `ResolvedEndpoints`, and `CustomBackendContext` for sandbox adapters (`distributionId`, `fetch`, `endpoint`, and, when there is a credential to send, `credential`, `credentialOrigins`, and `credentialRejected`; see [the sandbox credential](#the-sandbox-credential)).
- Identity and credentials: `IdentityProvider`, `WorkloadIdentityProvider` (an identity adapter that declares `interactive: false`), `IdentitySession`, `LoginContext`, `RETAINED_CLAIMS` (the claims PiShip keeps from a session), `CredentialProvider`, `CredentialContext`, `CredentialMode`, `RuntimeCredential`, `RuntimeCredentialKind`.
- The principal: `PrincipalKey`, `principalKey(session)` (the `(issuer, subject)` of a session, or `IDENTITY_INVALID` when either is missing), and `samePrincipal(a, b)`, the comparison PiShip applies to a refreshed session.
- Secrets and redaction: `SecretValue`, `isSecretValue`, `redact`, `redactValue`, `REDACTED_TEXT`.
- Managed HTTP: the `ManagedFetch` type. Use the `fetch` in the context: it applies the distribution's proxy, CA, and private-only policy. An adapter never builds its own client.
- Errors: `PiShipError`, `isPiShipError`, `PISHIP_ERROR_CODES`, `PiShipErrorCode`, `PiShipErrorOptions`, `formatError`, and `parseRetryAfter` for a `Retry-After` header.
- Audit: `AuditSink`, `AuditBatch`, `AuditEvent`, `AuditEventType`, `AUDIT_BATCH_SCHEMA`, `AUDIT_EVENT_SCHEMA`, `AUDIT_EVENT_TYPES`.
- Sandbox backends and their capability declarations: `SandboxBackend`, `SandboxInstance`, `SandboxCapabilities`, `SandboxGuarantee`, `SANDBOX_GUARANTEES`, `HOST_FILESYSTEM_ISOLATION`, `SandboxPrepareRequest`, `SandboxProfile`, `SandboxExecRequest`, `SandboxExecIO`, `SandboxExecResult`, `SandboxCommand`, `WrappedCommand`, `AdapterAvailability`.
- `ADAPTER_KINDS`: `identity`, `credential`, `sandbox`, `audit-sink`.

A unit test pins this list, checks that every value is the public package's own (never a copy), and fails if the SDK imports anything but the public roots of `@piship/contracts` and `@piship/sandbox`.

## Writing an adapter

- Wrap every token in a `SecretValue` as soon as it arrives, and call `reveal()` only to put it in a request.
- Report failures as a `PiShipError` with the contract's code (`IDENTITY_EXPIRED`, `CREDENTIAL_DENIED`, `GATEWAY_RATE_LIMITED`, ...), `retryable`, and `retryAfterMs` from `parseRetryAfter`. Rethrow a `PiShipError` from the managed fetch unchanged: a network or TLS policy refusal keeps its own code.
- Never build a message from a transport error. Its text can quote a request header, and with it a token.
- Pass `withTimeout(ms, ctx.signal)` to every request. The caller's signal cancels; the timeout never replaces it. After an abort, `ctx.signal?.aborted` tells a cancellation (final) from a timeout or outage (retryable).
- A sandbox backend claims only what it enforces. A remote service that keeps host files out of reach claims `host-filesystem-isolation`, never the `filesystem-*` planes. It passes `io.signal` on to the service, since PiShip owns every command's timeout and cancellation, and its `dispose()` never throws ([sandbox backends](sandbox.md#custom-adapters)).

### The sandbox credential

A custom sandbox backend gets its credential through `CustomBackendContext`, from one of three sources:

| Source | Where it comes from | `credentialOrigins` | After a 401 or 403 |
| --- | --- | --- | --- |
| `sandbox.credential: runtime` | The runtime (inference) credential, when `sandbox.endpoint` is on the gateway's origin | The gateway's origin | No `credentialRejected`: the backend reports the failure |
| `sandbox.credential: stored` | The API key or token a person stored with `<command> sandbox login` | The origins it was stored for | It is marked rejected and the next launch asks for `sandbox login`; `credentialRejected()` resolves false |
| The module's `sandboxCredential` export (no `sandbox.credential`) | The adapter's own `CredentialProvider`, acquired per launch and held in memory only | The declared endpoint's origin | It is renewed once; `credentialRejected()` resolves true, and the backend may repeat the one request that created nothing |

- `credential()` returns the value for one request. Call it for each request instead of keeping the value: rotation, rejection, and a user switch take effect at once. For a stored or adapter credential it rejects with `SANDBOX_UNAVAILABLE` when the credential may no longer be used.
- Send it only to an origin in `credentialOrigins`. PiShip has already checked that the declared endpoint (and, for a stored credential, every URL it was stored for) is one of them; anything else the backend contacts gets no credential.
- On a 401 or 403 from one of those origins, call `credentialRejected()` when the context has it. Repeat a request only when it resolved true and the request created nothing (never a sandbox, a claim, or a command).
- `sandboxCredential` is a `CredentialProvider` (`acquire`, optional `refresh` and `revoke`) exported next to the default factory. It receives the signed-in identity (`null` without identity) and returns an `api_key` or `bearer` credential, with `expiresAt` when it expires; an `opaque` credential is refused. Exporting it while the manifest also declares `sandbox.credential` fails closed.

`SandboxCredentialAccess` in `@piship/contracts` is how PiShip holds the stored or adapter credential behind `credential()`; a backend never sees it, so the SDK does not export it. See [sandbox credentials](sandbox.md#credentials) for storage, binding, and clearing.

## Examples

`packages/adapter-sdk/examples/` holds one example of each kind, written against placeholder `*.example.com` services: `identity.mjs` (a device-style sign-in), `credential.mjs` (exchanges the identity for a runtime credential and revokes it with itself), `sandbox.mjs` (a remote execution service), and `audit-sink.mjs` (a collector that stores each event once). Each is a single file that imports only the SDK and `node:` built-ins, which a unit test checks. The examples are loaded through PiShip's real loaders against a local fake of those services (`tests/adapter-sdk-examples.test.ts`); that is loader evidence, not a live integration. The conformance kits below also run against the identity, credential, and sandbox examples (`tests/adapter-kits/examples.test.ts`), which pass every behavior their kit can exercise; the audit sink example is a collector, not a sink that delivers onward, so the audit kit does not apply to it. Replace the placeholder service, declare its host in `network.allowHosts` when the distribution is private-only, and copy the file into the distribution. For an adapter with a real service behind it, see the [reference container sandbox](../examples/enterprise-reference/sandbox/README.md): a sandbox adapter with a `shared` workspace and a stored credential, and the service that runs each command in a container.

## Audit sink conformance kit

`testAuditSink` in `@piship/adapter-conformance` checks an `AuditSink` against the [`piship-audit-batch/v1` contract](enterprise-integration.md#audit-collector-piship-audit-batchv1). It is for a sink that delivers batches onward to a collector, in the position of PiShip's own `http` sink: a relay, a forwarder into a SIEM, or a test double. The kit imports only `@piship/adapter-sdk`, so it tests a sink the way a company would. The package is private and unpublished: run it from a checkout of this repository, in a test file inside the workspace.

The kit builds a new sink for each check through a factory, and connects it to a fake collector the kit controls. The collector checks the batch shape, stores an event only if its `id` is new, compares a resent `id` with its first delivery in canonical form (the de-duplication guidance of the contract), and answers, fails, holds, or stores and then fails as each check needs. The factory receives:

| Field | Meaning |
| --- | --- |
| `url` | The collector. POST batches here |
| `fetch` | Reaches the collector. Use it where the real sink uses the managed `fetch` from its context |
| `credential` | A fake downstream credential, such as an ingest token. It may go in a request header, never in an event or an error |
| `required` | Whether the sink is required: losing an event is then an error |
| `maxEvents` | The most events a buffering sink may hold |

```ts
import { testAuditSink } from "@piship/adapter-conformance";
import { expect, it } from "vitest";
import { createSink } from "./my-sink.js";

it("conforms to piship-audit-batch/v1", async () => {
  const report = await testAuditSink((env) =>
    createSink({ url: env.url, fetch: env.fetch, token: env.credential }),
  );
  expect(report.results.filter((result) => result.status === "failed")).toEqual([]);
});
```

A plain sink has only `write(batch, signal)`: each write settles with the collector's answer, and PiShip's audit log holds events while the collector is down. A buffering sink also has `flush()`, `status()` (`delivered`, `pending`, `dropped`, and a redacted `lastError`), and `close(deadlineMs)`, which returns the same counts. Its `write` queues events, except the empty batch, which is the readiness probe and goes to the collector at once. A sink that has some of `flush`, `status`, and `close` but not all three fails the checks that need them.

Each result is `passed`, `failed` with a reason, or `skipped` with a reason. A reason names the event by its `time` and never repeats the fake credential. A check that does not settle within `timeoutMs` (default 10 s) fails instead of hanging; raise it on a slow machine. `closeDeadlineMs` (default 250 ms) is the deadline passed to `close()`.

| Behavior | Contract statement |
| --- | --- |
| metadata-only defaults | An event arrives already metadata-only, with `content` only for the classes the distribution opted in to. The sink stores an event without `content` without one, never copies prompt or command text from one event into another or outside `content` (a raw request body kept with each event does), and keeps opted-in `content` exactly as it arrived |
| secret redaction | The sink's own credential never appears in a stored event, a request body, or an error or `lastError` it reports |
| identity attribution | `user` is stored as sent: the identity subject, or `null`. The sink never fills it with its own principal or a token |
| session correlation | `session` is stored as sent, so every event of one session has the same value across batches, and `null` stays `null`. The sink never replaces it with a per-request correlation ID |
| event id stability | Every event reaches the collector with the `id` it was written with, on the first delivery and on a retry after the collector failed |
| delivery failure | A plain sink's write resolves only after the collector answered `2xx`; HTTP 503, a redirect (never followed), a network error, or an aborted signal makes it reject. A buffering sink's flush finishes only after the collector answered, and the sink counts a failed batch as pending (required) or dropped (optional), never as delivered, and never loses it uncounted |
| buffer behavior | Buffering sinks only; plain sinks are skipped. The queue never holds more than `maxEvents`. An event that does not fit is dropped and counted, so the oldest events are kept and delivered oldest first, and an optional sink never refuses a write for it. Every event ends up delivered, pending, or dropped, exactly once |
| fail-closed policy | The readiness probe (an empty batch) is sent to the collector and rejects while the collector is down, so a required sink fails launch with `AUDIT_UNAVAILABLE`. A required buffering sink whose buffer is full refuses the next write with a `PiShipError` whose code is `AUDIT_UNAVAILABLE`, and accepts writes again once a flush has drained it |
| shutdown flush | Buffering sinks only; plain sinks are skipped. `close()` delivers what is queued to a healthy collector and reports nothing lost. When the collector is down it reports every event it did not deliver as pending or dropped, never zero. An event written after `close()` is refused or counted as dropped, and never delivered |
| duplicate handling | After the collector stored a batch but its answer was lost, the resent batch carries the same IDs in the same order and the same content, so a collector that stores each `id` once stores every event once. The sink accepts the collector's `2xx` for a batch it had already stored |

`failed` means the sink breaks that statement; fix the sink, not the kit. Some defects fail two behaviors because one implies the other: a sink that swallows errors cannot fail closed, and a new `id` or `session` on each write makes a resent event differ from its first delivery. `skipped` means the check does not apply to this kind of sink, not that it passed. The kit's own tests (`packages/adapter-conformance/src/audit.test.ts`) run it against a reference plain sink and a reference buffering sink, which pass, and against sinks seeded with one defect each, which fail.

## Credential conformance kit

`testCredentialAdapter` from `@piship/adapter-conformance` runs a credential adapter against a fake credential broker that the kit owns, and reports each behavior of the credential contract as `passed`, `failed`, or `skipped`. The fake broker answers through the managed `fetch` in the adapter's context, so a run needs no network, no real broker, and nothing from PiShip but the SDK. The kit imports only `@piship/adapter-sdk` and `node:` built-ins.

```ts
import { testCredentialAdapter } from "@piship/adapter-conformance";
import { expect, it } from "vitest";
import { createAdapter } from "./credential-adapter.js";

it("meets the PiShip credential contract", async () => {
  // Build the adapter with a short request timeout for the kit.
  const report = await testCredentialAdapter(createAdapter({ timeoutMs: 200 }), {
    requestTimeoutMs: 200,
  });
  expect(report.results.filter((result) => result.status === "failed")).toEqual([]);
});
```

The first argument is what the adapter module default-exports, the factory `defineCredentialAdapter` returns. The kit calls it once per behavior with a fresh context and a fresh broker, so no state carries over between behaviors. The context holds placeholder endpoints under `*.conformance.invalid` (`brokerEndpoint`, `brokerRevokeEndpoint`, `baseUrl`, `issuer`); every request reaches the fake broker whatever its URL. An adapter that uses any other client than the context's `fetch` fails `acquire`.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `requestTimeoutMs` | `30000` | The adapter's own request timeout. The kit waits three times this plus 2 s for a stalled request to end before it reports a hang. With the default, the stalled-broker checks take several minutes, so build the adapter under test with a short timeout and pass the same value |
| `issue(credential)` | the `http-broker` answer | The broker's success answer to an acquire or refresh, as a `Response`. The default is `{credential_type, credential, credential_id, expires_at}`; an adapter for another service encodes the issued credential the way that service does |
| `revoked()` | 204 | The broker's success answer to a revoke |
| `idempotency` | `true` | `false` when the adapter's service does not honor idempotency keys; `idempotency` is then `skipped` |
| `endpoints`, `distributionId` | placeholders | Merged into the adapter's context |

The report is `{kind: "credential", results}`, one result per behavior in this order. `CREDENTIAL_CONTRACT` exports the same statements, and `CREDENTIAL_BEHAVIORS` the names.

| Behavior | The adapter passes when |
| --- | --- |
| `acquire` | It sends its request through the context's `fetch` and returns the credential the broker issued: kind `api_key`, `bearer`, or `opaque`, the secret as a `SecretValue`, the broker's credential ID, and `mode: "adapter"` (the built-in `http-broker` mode is also accepted, so the kit can test PiShip's own provider) |
| `refresh` | `refresh()`, or `acquire()` when there is no `refresh()` (as PiShip renews), asks the broker again and returns the newly issued credential, never the current one |
| `expiry` | `expiresAt` is the broker's expiry on acquire and on refresh, and a credential that has already expired is refused with `CREDENTIAL_EXPIRED` or `CREDENTIAL_ACQUIRE_FAILED`, never returned |
| `revoke` | `revoke()` sends a request that names the credential (its ID or secret in the URL, a header, or the body) and resolves once the broker accepted it. `skipped` for an adapter without `revoke()` |
| `401` | An acquire answered with 401 fails with `IDENTITY_EXPIRED`, not retryable, so PiShip refreshes the sign-in |
| `403` | A 403 fails with `CREDENTIAL_DENIED`, not retryable, for acquire and revoke, and is decided from the status: an answer whose body never arrives is still a denial, not a timeout |
| `429` | A 429 fails retryably with `CREDENTIAL_ACQUIRE_FAILED` (acquire) or `CREDENTIAL_REVOKED` (revoke), and `Retry-After`, in seconds or as an HTTP-date, becomes `retryAfterMs` |
| `5xx` | A 500, 502, or 503 fails retryably with the same codes, with any `Retry-After` as `retryAfterMs` |
| `timeout` | A broker that never answers ends in a retryable failure with the same codes after the adapter's own timeout, also when the caller passed a signal that never fires: the signal composes with the timeout and never replaces it (`withTimeout`) |
| `abort` | The caller's signal ends the request in flight, and the failure, with the same codes, is not retryable; a signal that was already aborted also fails without being retryable |
| `redaction` | No identity token, credential, or broker answer body appears in any error's message, stack, `sanitizedDetail`, `userAction`, `toJSON()`, `formatError` rendering, inspection, or cause chain, after a 403, 502, or 400 with a sentinel body, a success body that is not the expected answer, and a transport error whose message quotes the `Authorization` header; the returned credential never renders its secret |
| `concurrent refresh` | Two refreshes of one credential, answered at the same moment, both resolve, and neither result carries the ID or expiry of the credential issued to the other call |
| `retry behavior` | The adapter never re-sends by itself: after a timeout, a connection reset, a 502, a 503, a 429, or a 401 it has sent no more requests than one successful acquire sends. A transport failure (`ECONNREFUSED`, `ECONNRESET`) is retryable. A `NETWORK_DENIED` or `TLS_POLICY_VIOLATION` from the managed fetch is rethrown with its code and is not retryable |
| `idempotency` | `CredentialContext.idempotencyKey` is sent as `Idempotency-Key` on every acquire and refresh request; an acquire whose answer was lost after the broker issued a credential fails with the key in `sanitizedDetail.idempotencyKey`; and a caller that retries with that key receives the credential the broker already issued, not a new one ([idempotency and retries](enterprise-integration.md#idempotency-and-retries)) |

What a result means:

- `passed`: the kit exercised the behavior and the adapter met every statement in its row.
- `failed`: `reason` names the first statement the adapter broke, such as `acquire answered 403: expected CREDENTIAL_DENIED, got CREDENTIAL_ACQUIRE_FAILED` or `after a timeout: the adapter sent 2 requests where one acquire sends 1`. A call that did not end within the kit's bound reads `the call did not end within the kit's bound`. A reason names codes, statuses, and counts only, never an error message, a token, or a credential.
- `skipped`: the kit could not exercise the behavior, and `reason` says why: the adapter has no `revoke()`, or the options declared its service ignores idempotency keys. A skipped behavior is never counted as passed.

The kit judges failures with `isPiShipError`, which is the check PiShip applies when it reads an adapter's error. An adapter that bundles its own copy of the SDK throws errors of another `PiShipError` class, which fail every error check; import the SDK instead of bundling it.

## Identity conformance kit

`testIdentityAdapter` from `@piship/adapter-conformance` runs an identity adapter (`identity.mode: adapter`) against a fake identity service that the kit owns, and reports each behavior of the [identity contract](identity.md) as `passed`, `failed`, or `skipped`. It covers interactive adapters and workload adapters that declare `interactive: false` ([workload identity](identity.md#workload-identity-headless-runs)). The fake service answers through the managed `fetch` in the adapter's context, so a run needs no network, no identity provider, and nothing from PiShip but the SDK. The kit imports only `@piship/adapter-sdk` and `node:` built-ins. Like the other kits, it is private and unpublished: run it from a checkout of this repository, in a test file inside the workspace.

```ts
import { testIdentityAdapter } from "@piship/adapter-conformance";
import { expect, it } from "vitest";
import { createAdapter } from "./identity-adapter.js";

it("meets the PiShip identity contract", async () => {
  // Build the adapter with a short request timeout for the kit.
  const report = await testIdentityAdapter(createAdapter({ timeoutMs: 200 }), {
    requestTimeoutMs: 200,
    issuer: "https://sign-in.example.com", // the issuer the adapter reports
    respond: myServiceAnswer, // how the service says each answer; see below
  });
  expect(report.results.filter((result) => result.status === "failed")).toEqual([]);
});
```

The first argument is what the adapter module default-exports, the factory `defineIdentityAdapter` returns. The kit calls it once per behavior with a fresh context and a fresh service, so no state carries over between behaviors. The context holds placeholder endpoints under `*.conformance.invalid`; every request reaches the fake service whatever its URL. The kit tells an interactive adapter from a workload adapter by `interactive: false` on the provider.

The kit can only see what goes through the context's `fetch`. An adapter that opens its own connections (its own HTTP client, a socket, a child process) or reads its token from a file or the environment without a request is not testable this way: its `login` sends nothing, and `login` fails with `login sent no request through the context's managed fetch`. PiShip requires the managed `fetch` anyway, so it applies the distribution's TLS, proxy, CA, and private-only rules. A workload adapter that reads a platform token and exchanges it through `context.fetch` is testable: build it in the test with a fake platform token.

### The fake service and the `respond` hook

The kit decides what the service says to each request; `respond(request, answer)` encodes it in the adapter's protocol and returns a `Response`. `request` has the `operation` being called (`login`, `refresh`, or `logout`), its `step` within that call (from 0), `url`, `method`, `headers`, and `body`. `answer` is one of:

| `answer.kind` | Meaning |
| --- | --- |
| `session` | A successful login or refresh, or an intermediate step of one (a device authorization, a poll). `answer.identity` is what the service issues: `subject`, `issuer`, `name`, `email`, `accessToken`, `idToken`, `refreshToken`, `expiresAt` and `expiresIn`, `claims` (allowlisted claims plus some that are not, which the adapter must drop), and `verificationUrl` and `deviceCode` for a device-style login. One call reuses one identity across its steps |
| `logged-out` | The service accepted a logout |
| `already-revoked` | A logout of a session the service had already revoked or no longer knows |
| `invalid-grant` | The service refuses the grant (a refresh token, or a workload's token) because it expired or was revoked |

Without `respond`, the service answers every login and refresh request with one JSON body holding all the `session` fields above (`deviceCode`, `verificationUrl`, `subject`, `issuer`, `name`, `email`, `accessToken`, `idToken`, `refreshToken`, `expiresIn`, `expiresAt`, `claims`), a logout with 204, an already revoked session's logout with 401 `{"error":"invalid_token"}`, and an invalid grant with 400 `{"error":"invalid_grant"}`. That fits a device-style service like the SDK example, which reads the start and poll answers from the same fields. Outages, 401s, and answers with sentinel bodies are protocol-independent; the kit sends those itself.

All values are fake and carry a per-run marker; none is a real token.

### Token validation and the harness

PiShip does no JWT cryptography ([decision 15](decisions.md)): an adapter that accepts tokens from its service validates them itself, and a generic kit cannot mint a token with a wrong issuer, a wrong audience, or a bad signature for an arbitrary adapter. The behaviors `invalid issuer`, `invalid audience`, `invalid signature`, `token validity window`, and `revoked token` therefore run only with `options.harness`, token-minting hooks the adapter author writes against the keys and issuer the adapter trusts in the test. Without a harness each is `skipped` with a reason that starts `needs harness`, never `passed`.

```ts
interface IdentityTokenHarness {
  mint(request: {
    kind: "valid" | "wrong-issuer" | "wrong-audience" | "bad-signature"
        | "expired" | "not-yet-valid" | "revoked";
    issuer: string;      // the issuer the session names
    subject: string;     // the subject the session names
    expiresAt: Date;     // when the service says the session ends
    operation: "login" | "refresh" | "logout";
    request: IdentityServiceRequest; // the request being answered, e.g. for its nonce
  }): { idToken?: string; accessToken?: string } | undefined;
  respond?(request: IdentityServiceRequest): Response | undefined;
}
```

- `mint` returns the tokens that replace the kit's fake ones in the session the service issues (either or both), or `undefined` for a kind it cannot mint, which skips that behavior with the reason `the harness cannot mint a token ...`. It may be async. `valid` is a token the adapter must accept for exactly that principal and expiry; each other kind differs from `valid` in that one respect: another issuer, another audience, a signature the trusted keys do not verify, an `exp` in the past, an `nbf` in the future, or a token the issuer has revoked.
- With a harness, every session the service issues carries `mint({kind: "valid"})` tokens, so an adapter that validates tokens accepts the kit's sessions in every other behavior. A harness that cannot mint `valid` fails the token behaviors.
- `respond` answers the requests the harness serves itself, such as discovery, the issuer's keys (JWKS), or token introspection for `revoked`, before the kit's service sees them; `undefined` passes the request on.

Each token behavior first checks that a session with a `valid` token is accepted. An adapter, or a harness setup, that refuses every token fails with `a session with a valid minted token was refused`, because its refusals would prove nothing. The kit's own tests (`packages/adapter-conformance/src/identity.test.ts`) show a harness that signs Ed25519 ID tokens with `node:crypto` and answers introspection.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `requestTimeoutMs` | `30000` | The adapter's own request timeout. The kit waits three times this plus 2 s for a stalled request to end before it reports a hang. With the default, the stalled-service checks take minutes, so build the adapter under test with a short timeout and pass the same value |
| `issuer` | `endpoints.issuer`, `https://issuer.conformance.invalid` | The issuer the service asserts and the adapter must report |
| `respond(request, answer)` | the JSON body above | The service's answer in the adapter's protocol |
| `harness` | none | Token-minting hooks; without them the token behaviors are skipped |
| `endpoints`, `distributionId` | placeholders | Merged into the adapter's context |

### Behaviors

The report is `{kind: "identity", results}`, one result per behavior in this order. `IDENTITY_CONTRACT` exports the same statements, `IDENTITY_BEHAVIORS` the names, and `IDENTITY_ALLOWED_CLAIMS` the claim allowlist.

| Behavior | The adapter passes when |
| --- | --- |
| `login` | It declares a `kind` and `interactive` is absent, `true`, or `false`. `login()` sends its requests through the context's `fetch` and returns a session whose `subject` and `issuer` are the principal the service asserted. An interactive adapter passes a URL to `openUrl`; a workload adapter never calls it (PiShip hands a workload an `openUrl` that fails the run). The kit's `openUrl` only records the call |
| `refresh` | `refresh()` asks the service again and returns a session for the same principal `(iss, sub)`, with the access token and the rotated refresh token the service issued, never the current ones. A refreshed session that names another subject or issuer fails here: PiShip refuses it with `IDENTITY_INVALID`. `skipped` for an adapter without `refresh()` and for a workload adapter, which PiShip logs in again instead |
| `expiry` | `expiresAt` is the service's expiry, within 5 s, on login and on refresh. A session the service issued already expired is returned with that past expiry or refused with `IDENTITY_EXPIRED`, never given a later one |
| `logout` | `logout()` sends a request that names the session's refresh or access token and resolves once the service accepted it, and resolves, without throwing, for a session the service had already revoked. `skipped` for an adapter without `logout()` and for a workload adapter, whose session PiShip holds in memory only |
| `claim normalization` | `claims`, on login and on refresh, hold only the [allowlisted claims](identity.md#oidc) (`sub`, `iss`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `name`, `preferred_username`, `email`, `email_verified`, `groups`) with scalar or string-array values, and no token appears in `claims`, `subject`, `issuer`, `displayName`, or `email`. PiShip filters claims again; the kit holds the adapter to the allowlist so a token never reaches a claim in the first place |
| `revoked session` | A refresh the service refuses as `invalid_grant` or with HTTP 401, and a refresh of a session without a refresh token, fail with `IDENTITY_EXPIRED` (the user signs in again), never `IDENTITY_INVALID` or an uncoded error. For a workload adapter, a login refused the same way fails with `IDENTITY_EXPIRED`. `skipped` for an interactive adapter without `refresh()` |
| `secret redaction` | The session's `accessToken`, `idToken`, and `refreshToken` are `SecretValue`s (a plain string fails, even though PiShip's loader wraps one) that never render their value. No token or service answer body appears in any error's message, stack, `sanitizedDetail`, `userAction`, `toJSON()`, `formatError` rendering, inspection, or cause chain, after a 400 whose body quotes the refresh token, a 401 and a 502 with a sentinel body, a success body that is not the expected answer, and a transport error whose message quotes the access token, on login, refresh, and logout; with a harness, also after refusing a token with a bad signature |
| `service outage` | On login and on refresh: a 503 with `Retry-After`, a 502 HTML page, a refused connection, and a service that never answers fail with a retryable `GATEWAY_UNREACHABLE`; a 429 with a retryable `GATEWAY_RATE_LIMITED`; `Retry-After` becomes `retryAfterMs`. Never `IDENTITY_INVALID`, which tells the user to contact an administrator ([errors](identity.md#errors)). A `NETWORK_DENIED` refusal from the managed fetch keeps its code and is not retryable |
| `invalid issuer` | With a harness: a login, and a refresh, whose token names another issuer fails with `IDENTITY_INVALID` |
| `invalid audience` | With a harness: the same for a token issued for another audience |
| `invalid signature` | With a harness: the same for a token whose signature the trusted keys do not verify |
| `token validity window` | With a harness: a login and a refresh whose token has expired, or is not yet valid, fail with `IDENTITY_EXPIRED` or `IDENTITY_INVALID`. Either kind the harness can mint is enough |
| `revoked token` | With a harness: a login and a refresh whose token the issuer has revoked fail with `IDENTITY_EXPIRED` or `IDENTITY_INVALID` |

What a result means:

- `passed`: the kit exercised the behavior and the adapter met every statement in its row.
- `failed`: `reason` names the first statement the adapter broke, such as `refresh after a 503 with Retry-After: expected GATEWAY_UNREACHABLE, got IDENTITY_INVALID` or `the refreshed session names another subject; PiShip refuses a refresh that changes the principal (iss, sub)`. A call that did not end within the kit's bound reads `the call did not end within the kit's bound`. A reason names codes, statuses, and claim names only, never an error message, a token, or an answer body.
- `skipped`: the kit could not exercise the behavior, and `reason` says why: the adapter has no `refresh()` or `logout()`, a workload adapter does not use it, there is no harness (`needs harness: ...`), or the harness cannot mint that kind of token. A skipped behavior is never counted as passed, and a skipped token behavior means token validation is untested, not that it is safe.

The kit's own tests run it against a reference device-style adapter and a reference workload adapter, which pass, with and without a harness, and against variants seeded with one defect each, which fail exactly one behavior: a subject swapped on refresh, a refresh token returned in `claims`, a token leaked in an error's cause, an outage reported as `IDENTITY_INVALID`, `invalid_grant` reported as an uncoded error, a browser opened by a workload adapter, an ignored expiry, a logout that throws for a revoked session, and, with a harness, an adapter that accepts a wrong issuer, a wrong audience, a bad signature, an expired token, or a revoked one.

## Sandbox conformance kit

`testSandboxAdapter` from `@piship/adapter-conformance` runs a sandbox backend the way PiShip does, through `available`, `capabilities`, `prepare`, `exec`, and `dispose`, and reports each behavior of the [sandbox contract](sandbox.md#the-contract) as `passed`, `failed`, or `skipped`. It checks claims by running commands inside the backend, not by reading the declaration: a file the kit plants on this host must stay unreadable, a loopback listener the kit runs must stay unreachable with the network denied, a variable the kit plants in the launcher's environment must not arrive, and a timed-out or cancelled command must not write the marker it would write a second later. For a backend that declares a `shared` or `synchronized` workspace it runs PiShip's [workspace check](sandbox.md#the-workspace-check) and git control probe. The kit imports only `@piship/adapter-sdk` and `node:` built-ins.

```ts
import { testSandboxAdapter } from "@piship/adapter-conformance";
import { expect, it } from "vitest";
import acmeSandbox from "./acme-sandbox.mjs";
import { countSessions, replacePod } from "./acme-test-service.js";

it("meets the PiShip sandbox contract", async () => {
  const report = await testSandboxAdapter(acmeSandbox, {
    // A test instance of the company's sandbox service.
    context: { endpoint: "http://127.0.0.1:8080" },
    // Hooks the kit cannot provide: they enable cleanup and the epoch check.
    sandboxes: () => countSessions(),
    replaceEnvironment: (instance) => replacePod(instance.epoch?.()),
  });
  expect(report.results.filter((result) => result.status === "failed")).toEqual([]);
}, 300_000);
```

The first argument is what the adapter module default-exports, the factory `defineSandboxAdapter` returns. A backend object also works, but then the kit cannot give it a context of its own, and the checks that simulate an unreachable service reach the real one. The kit calls the factory once per check with a context it controls: `endpoint` and `distributionId` from the options, a `fetch` that wraps the one in the options (default: the global `fetch`), and a `credential()` that returns a fake sentinel value, so the kit can see where the credential goes. That context has no `credentialOrigins` or `credentialRejected`, and the kit does not load a `sandboxCredential` export, so a backend's rejection handling and a module's own credential are tested in the adapter's own tests. Every command the kit sends is POSIX `sh` and needs `cat`, `mkdir`, `mv`, `printf`, `sleep`, and `env` in the sandbox; the network check also needs `nc` or `bash`. A call that does not end within `callTimeoutMs` fails its check instead of hanging it.

A backend runs for real, so the kit runs against a test instance of the company's sandbox service, in a test file inside a checkout of this repository (the package is private and unpublished). A shared-workspace backend must see the directory the kit uses as its workspace: pass `workspace`, an empty directory the service mounts, or let the kit create a temporary one.

Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `context` | none | `endpoint`, `fetch`, and `distributionId` for the adapter's context |
| `workspace` | a new temporary directory | An empty directory the sandbox sees as its workspace. The kit writes a `.git` directory and its own scratch directory there and removes both afterwards; a directory that is not empty is refused |
| `sandboxes()` | none | Hook: how many sandboxes (sessions, pods, VMs) the service holds now. Enables `cleanup` |
| `replaceEnvironment(instance)` | none | Hook: move the instance to a new environment behind its back, as a service does when it replaces an expired pod. Enables the epoch part of `workspace re-check` |
| `networkTarget` | a loopback listener the kit runs | `{host, port}` of a TCP listener the sandbox would reach if its network were allowed. A remote sandbox cannot reach this host's loopback, so a remote backend passes one to get a network result |
| `settleMs` | `5000`, PiShip's | How long the backend has to settle after `io.signal` aborted |
| `callTimeoutMs` | `30000` | The longest one backend call may take |
| `sharedWindowMs` | `10000`, PiShip's | The window a declared `shared` workspace gets per direction; a `synchronized` one gets its `propagationMs` |
| `only` | all | Run only these behaviors while iterating on one; the others are `skipped` as not selected |

The report is `{kind: "sandbox", results}`, one result per behavior in this order. `SANDBOX_CONTRACT` exports the same statements, and `SANDBOX_BEHAVIORS` the names.

| Behavior | The backend passes when |
| --- | --- |
| `availability` | `available()` resolves `{available: true}` in the kit's context, and with its service unreachable (the context's `fetch` refuses the connection) it resolves `{available: false, reason}` with a non-empty reason, or still `true` when it needs no service. It never throws |
| `capabilities` | `capabilities()` is well formed and the same on a second call: `local` or `remote`, known guarantees named once, network modes `deny` and `allow` only, `network-deny` claimed exactly when `deny` is listed, `environment-filter`, `localProcesses` only for a local backend, and a valid workspace declaration (a known mode, `propagationMs` from 1 to 60000 on `synchronized` only, a workspace-relative `sentinelDir` without `..` or `\` and never on `snapshot`). A local backend claims both `filesystem-*` planes and never `host-filesystem-isolation` or `workspace-confinement`; a remote `snapshot` backend claims `host-filesystem-isolation`; a remote `shared` or `synchronized` one claims `workspace-confinement` and `git-control-protection` and never `host-filesystem-isolation` |
| `prepare` | `prepare(profile)` resolves an instance with `exec()` and `dispose()` (and `wrap()` when it declares `localProcesses`), and every call creates its own sandbox: after one instance is disposed, another still runs commands |
| `execute` | A command runs at the workspace path it was given, sees an environment value exactly as given (spaces, quotes, `$`, a backslash, and non-ASCII kept), its stdout arrives on `onStdout` and its stderr on `onStderr`, and exit 7 and exit 0 are reported as such |
| `environment filtering` | A command receives exactly the request's environment: two variables the kit plants in the launcher's own environment (one named like a credential) never arrive, and an allowlisted variable the launcher also has arrives with the approved value, not the launcher's |
| `secret leakage` | The context's credential never appears in `available()`, `capabilities()`, `epoch()`, a command's environment or output, an error from `exec()`, `dispose()`, `available()`, or `prepare()` (also after a transport error that quotes the credential and a 401 whose body and header echo it; causes are checked too), or a line the backend logs. With `endpoint` set, it is sent to that origin only |
| `filesystem claims` | Each claimed filesystem guarantee holds for a command inside the sandbox: `host-filesystem-isolation` and `workspace-confinement` keep a file planted on this host outside the workspace unreadable and unwritable; `filesystem-read-deny` keeps a `readDeny` path unreadable; `filesystem-write-allowlist` allows a write in the workspace and refuses one outside `writeAllow`; a local backend's `git-control-protection` keeps `.git/config` and `.git/hooks` read-only. `skipped` for a backend that claims none |
| `network claims` | With the profile's network denied, a command cannot connect to the kit's listener (or `networkTarget`); with it allowed, the same command connects, which shows the attempt would have noticed a connection. `skipped` when the backend does not claim `network-deny`, enforces only `deny`, has neither `nc` nor `bash`, or cannot reach the listener even with the network allowed; a refused connection alone never passes |
| `timeout` | When the kit aborts `io.signal` for a command that is running (after its first output, or after a fixed time for a backend that returns output only at the end), `exec()` settles within `settleMs`, the command and the processes it started stop, so the marker a background child would write a second later never appears, and the instance runs the next command |
| `cancellation` | An abort that arrives while the backend is still setting the command up, and one that arrives before the command printed anything, both stop the command. A backend that does not settle within `settleMs` is retired as PiShip would retire it: the kit disposes the instance, and `dispose()` must then stop the command. `skipped` when the command had to be retired and the kit cannot see inside the disposed sandbox (a remote workspace that is not shared) |
| `cleanup` | `dispose()` removes what `prepare()` created: `sandboxes()` reports no more sandboxes after `dispose()` than before `prepare()`. `skipped` without the `sandboxes` hook |
| `dispose` | `dispose()` of an instance with a command still running resolves without throwing, the command ends within `settleMs` (and, where the kit can see the workspace, never writes its marker), a second `dispose()` resolves, and `exec()` afterwards never reports a command as run |
| `fail-closed behavior` | The backend never reports a result it did not observe: a command that cannot run in the sandbox is not reported with exit 0, and PiShip's own sandbox check is run like any other command, never answered by the backend itself (the kit sends it with the marker variable set, and the answer must show the value). A backend that answered the check without running it would let PiShip report guarantees nobody verified as enforced |
| `workspace consistency` | A declared `shared` or `synchronized` workspace passes PiShip's two-way sentinel on a fresh instance: the sandbox sees a file the host wrote, and the host sees a file the sandbox wrote, both at once for `shared` (a delay means `synchronized`, not `shared`) and within `propagationMs` for `synchronized`. The check command must complete |
| `git control protection` | With a `shared` or `synchronized` workspace, appending zero bytes to `.git/config` and creating a file in `.git/hooks` and `.git/info` all fail from inside the sandbox, the check command completes (a check that cannot run fails, as PiShip fails closed), and nothing on the host changed. Renames are not tried: they would be destructive, and PiShip leaves them attested |
| `workspace re-check` | The workspace stays consistent across a session. On the kit's own clock, a command inside PiShip's 30-minute validity window is not checked again, and one after it is checked and passes. `epoch()`, when present, returns a non-empty, non-secret string or `undefined` and stays the same while the environment does. With `replaceEnvironment`, `epoch()` must change after the replacement (an instance without `epoch()` fails, since PiShip would never check the new environment) and the sentinel must pass in the new environment |

The `timeout`, `cancellation`, and `dispose` commands write a marker a second after they start. The kit counts from the command's first line of output, which each of them prints as it starts (the one command the cancellation check aborts while it runs is silent), or from the abort or the `dispose()` call when nothing has arrived, and looks for the marker 1.8 s from there. A backend under load that starts a command late is therefore still watched until its marker would appear. The command aborted before it started gets one second more when it has printed nothing by then (2.8 s from the abort), since a backend that ignored the abort can start it after the first window; if its first line arrives in that time, the count restarts from the line. A backend that starts it later than that is not caught.

The three workspace behaviors are `skipped` for a local backend, whose workspace is `shared` by construction, and for a backend that declares `snapshot`, with a reason that begins `declares snapshot`: a snapshot is never a complete coding-agent workspace, so there is nothing to verify and nothing to pass. `workspace re-check` is also `skipped` when the first sentinel did not pass; `workspace consistency` carries that failure.

What a result means:

- `passed`: the kit exercised the behavior and the backend met every statement in its row.
- `failed`: `reason` names the first statement the backend broke, such as `a command in the sandbox read a file on this host outside the workspace` or `the host did not see a file the sandbox wrote within 10000 ms`. A reason carries no credential, planted value, or command output; an error is named by its code or class and a short redacted message.
- `skipped`: the kit could not exercise the behavior, and `reason` says why and, where a hook would help, which one. A skipped behavior is never counted as passed.

While `environment filtering` runs, the kit sets `PISHIP_CONFORMANCE_HOST_TOKEN`, `PISHIP_CONFORMANCE_HOST_ONLY`, and `PISHIP_CONFORMANCE_APPROVED` in `process.env`; while `secret leakage` runs, it watches `console` and `process.stdout` and `stderr` and passes each line on with the fake credential removed. Both are restored afterwards, also when several kit runs share a process. The kit's own tests (`packages/adapter-conformance/src/sandbox.test.ts`) run it against reference backends that really run each command under Seatbelt (macOS) or bubblewrap (Linux): a local one, a remote snapshot, a remote shared workspace, a remote synchronized one with a timer-driven copier, and one that returns output only when a command ends. They pass, and a reference seeded with one defect per behavior fails that behavior and no other. Where neither mechanism can run (Windows, or a Linux host where bubblewrap cannot create user namespaces, as on Ubuntu 24.04 with AppArmor's restriction on), those tests are skipped and the run prints why; with `PISHIP_REQUIRE_ISOLATOR=1` they fail instead, so a runner that cannot isolate never reports a green run with no sandbox tests.

## Kit self-tests

Each kit's own tests (`packages/adapter-conformance/src/*.test.ts`) pass reference adapters and, for every behavior, fail an adapter seeded with a defect that breaks that behavior and no other. A test in each file fails when a behavior has no such seed. The kits share their helpers (how a check fails, how a call is bounded, how an error is searched for a secret) through a module the package does not export, and the package may import only `@piship/adapter-sdk`, which `npm run check:boundaries` enforces.

`tests/adapter-kits/` runs the kits against the SDK examples (see [Examples](#examples)) and against PiShip's own implementations, reached through their packages' public exports. The tests that run a sandbox backend need an OS isolator (Seatbelt or bubblewrap): `sandbox.test.ts` and these tests skip themselves without one, print the reason on the console and in the test's name, and fail instead when `PISHIP_REQUIRE_ISOLATOR=1` is set.

| Implementation | Kit | Result |
| --- | --- | --- |
| `http-broker` (`HttpBrokerCredentialProvider`) | credential | Every behavior passes |
| The `http` audit sink's delivery (`HttpSinkWriter`) | audit | Passes; `buffer behavior` and `shutdown flush` are skipped, because the queue belongs to PiShip's audit log, not to the sink |
| The native backend (`NativeBackend`, Seatbelt or bubblewrap) | sandbox | Passes; `cleanup` is skipped (no service holds its sandboxes) and the workspace checks are skipped (a local backend) |
| A custom backend passed through `customBackend()`, as PiShip's loader passes it (the SDK example against a fake execution service) | sandbox | Passes; `network claims` is skipped (it enforces only `deny`) and the workspace checks are skipped (`snapshot`) |
| The reference container sandbox adapter, against its service and real Docker containers (`examples/enterprise-reference/tests/sandbox.test.ts`, with the reference tests) | sandbox | Every behavior passes, none is skipped, including the workspace checks of a `shared` workspace |
| The `e2b-compatible` backend, against a fake E2B service that runs each command under Seatbelt or bubblewrap | sandbox | Fails `secret leakage`, and fails `timeout` against a service whose `SendSignal` stops only the command's own process; both are points where the kit is stricter than PiShip (below) |

The built-in OIDC provider is not run: its login waits for the browser to reach a loopback redirect, and the identity kit's `openUrl` only records the URL. The `kubernetes-agent-sandbox` backend is not run either: there is no fake of its runtime API that runs commands. Setting `PISHIP_KIT_REPORT` to a file path writes every report the tests produce to that file as JSON.

### Where a kit is stricter than PiShip

A kit holds an adapter to the contract as a company should write it; in a few places that is more than PiShip itself enforces. A failure on one of these points means the adapter relies on PiShip's leniency:

- **A `shared` workspace with a delayed direction.** The kit fails `workspace consistency`: a delay is `synchronized`, not `shared`. PiShip verifies the workspace as `synchronized`, reports the lower effective mode with a notice, and still counts it complete ([workspace](sandbox.md#workspace)).
- **A local backend that claims `host-filesystem-isolation` or `workspace-confinement`.** The kit fails `capabilities`. PiShip drops the claim, which cannot apply to commands that run on this host, and never shows it.
- **`network-deny` claimed without listing `deny` in `network`.** The kit fails `capabilities` whatever the policy. PiShip refuses the backend only when the policy denies the network.
- **A transport error from `prepare()` passed on unchanged.** The kit fails `secret leakage` when the error object quotes the credential, as the `e2b-compatible` backend's does. PiShip reports a failed preparation only through `redact()`, which removes the runtime credential (a revealed `SecretValue`) and bearer tokens; a company adapter's own credential is not known to it, so an adapter must not rely on that.
- **Background processes after a timeout.** The kit's `timeout` requires every process the command started to stop. The `e2b-compatible` backend stops a timed-out command with envd's `SendSignal`, which reaches the command's own process; a background process it started runs until the sandbox is deleted ([what PiShip controls](sandbox.md#what-piship-controls)). Against a service that signals the whole process group the backend passes. The tests' fake service runs a command in this host's process space when its `SendSignal` stops only the process, so the outcome is the same under Seatbelt and bubblewrap (bubblewrap's own process space would end every process of the sandbox together with its first).
