# Adapter SDK

`@piship/adapter-sdk` is the supported surface for writing a company adapter: an identity adapter (`identity.mode: adapter`), a credential adapter (`credential.provider: adapter`), a custom sandbox backend (`sandbox.provider: custom`), or the audit collector behind the built-in `http` audit sink. An adapter imports nothing else from PiShip.

Status: preview. The package is built to a publishable shape but is `private: true` and not published to npm; publishing needs a separate maintainer decision ([decision 21](decisions.md)). Conformance kits that test an adapter through the SDK only, `@piship/adapter-conformance`, are scaffolded and do not have kits yet.

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

- Context: `AdapterContext` (`distributionId`, the managed `fetch`, resolved `endpoints`), `ResolvedEndpoints`, and `CustomBackendContext` for sandbox adapters (`distributionId`, `fetch`, `endpoint`, and `credential` only under `sandbox.credential: runtime`).
- Identity and credentials: `IdentityProvider`, `IdentitySession`, `LoginContext`, `CredentialProvider`, `CredentialContext`, `CredentialMode`, `RuntimeCredential`, `RuntimeCredentialKind`.
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

## Examples

`packages/adapter-sdk/examples/` holds one example of each kind, written against placeholder `*.example.com` services: `identity.mjs` (a device-style sign-in), `credential.mjs` (exchanges the identity for a runtime credential and revokes it with itself), `sandbox.mjs` (a remote execution service), and `audit-sink.mjs` (a collector that stores each event once). Each is a single file that imports only the SDK and `node:` built-ins, which a unit test checks. The examples are loaded through PiShip's real loaders against a local fake of those services (`tests/adapter-sdk-examples.test.ts`); that is loader evidence, not a live integration. Replace the placeholder service, declare its host in `network.allowHosts` when the distribution is private-only, and copy the file into the distribution.
