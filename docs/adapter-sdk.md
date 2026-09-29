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
