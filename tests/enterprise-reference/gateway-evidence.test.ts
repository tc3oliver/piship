import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { PiShipError, SecretValue } from "@piship/contracts";
import {
  type CatalogEntry,
  classifyGatewayStatus,
  OpenAICompatibleInferenceProvider,
} from "@piship/inference";
import { isCredentialRejection, isModelDenial } from "@piship/pi";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  type Installed,
  installDistribution,
} from "../../examples/enterprise-reference/tests/support/distribution.js";
import type { Stack } from "../../examples/enterprise-reference/tests/support/stack.js";
import {
  errorType,
  type HttpResult,
  keyHash,
  poll,
  type ReferenceStack,
  request,
  startReferenceStack,
} from "./stack.js";

// Section 14.1: gateway authentication and authorization, the model catalog
// filtered by key, streaming, and the propagation of upstream 401, 403, 429
// and 5xx answers, all through the real LiteLLM and into PiShip's own
// error handling: the inference client's status mapping, the launch-time
// renewal of a rejected credential, and the in-session reading of Pi's error
// messages, driven through the installed AcmeCode reference distribution.
// Budgets, rate limits, parallel requests and the key's model list are in
// the other files here and are not repeated.
//
// LiteLLM does not document these error bodies, so the assertions below pin
// what LiteLLM v1.103.0 (the pinned image) answered with the reference config
// (examples/enterprise-litellm, no retry or cooldown settings of its own);
// the README beside compose.yaml has the table. In short:
// - Every refused virtual key is 401 with `code: "401"` and no retry-after;
//   the `type` tells them apart: `auth_error` (none, malformed, blocked),
//   `token_not_found_in_db` (unknown or deleted), `expired_key`.
// - An upstream 401 comes back as 401 `authentication_error` at once, and
//   puts the deployment in a 5 s cooldown: every key's next request for that
//   model is 429 `all_deployments_in_cooldown` with `retry-after: 5`.
// - An upstream 403, 429 or 5xx is tried three times (about 4 to 5 s) and
//   comes back with its status: 403 `permission_error`, 429
//   `throttling_error` (the upstream retry-after only as
//   `llm_provider-retry-after`), 5xx `internal_server_error`. No cooldown.
// - A stream the upstream cuts is 200, the chunks so far, then a
//   `data: {"error": ..., "code": "500"}` event and no `[DONE]`; not retried.
// PiShip reads an upstream 401 as its own credential rejected and an
// upstream 403 as a model denial; the tests pin that as found.

const LITELLM_VERSION = "1.103.0";
const REPLY = "Reference mock reply from gpt-4.1.";
// Its own ports, so it can run beside a stack on any other set. 55432, the
// planned PostgreSQL port, is often taken by a local database.
const PORTS = {
  KEYCLOAK_PORT: 58080,
  LITELLM_PORT: 54000,
  MOCK_UPSTREAM_PORT: 58090,
  POSTGRES_PORT: 55433,
  BROKER_PORT: 58070,
};

const CATALOG: CatalogEntry[] = [
  "acme/coder",
  "acme/general",
  "acme/extra",
].map((id) => ({
  id,
  name: id,
  contextWindow: 64_000,
  maxOutputTokens: 4096,
  input: ["text"],
  reasoning: false,
  tools: true,
  streaming: true,
  policyTags: [],
}));

let stack: ReferenceStack;
let acme: Installed | undefined;
// Set by a test that sends an upstream 401, with a key to poll with: every
// test sharing this stack waits for the 5 s cooldown to end, even when the
// test that caused it failed before its own wait.
let cooling: string | undefined;
const fileStarted = performance.now();

/** The reference distribution's view of this stack. */
function distributionStack(reference: ReferenceStack): Stack {
  const issuer = `http://127.0.0.1:${reference.ports.KEYCLOAK_PORT}/realms/piship-reference`;
  const brokerUrl = `${reference.broker}/v1/credential`;
  const revokeUrl = `${reference.broker}/v1/revoke`;
  const gatewayUrl = `${reference.gateway}/v1`;
  return {
    project: reference.project,
    ports: reference.ports,
    issuer,
    brokerUrl,
    revokeUrl,
    gatewayUrl,
    variables: {
      ACMECODE_OIDC_ISSUER: issuer,
      ACMECODE_CREDENTIAL_BROKER_URL: brokerUrl,
      ACMECODE_CREDENTIAL_REVOKE_URL: revokeUrl,
      ACMECODE_LLM_GATEWAY_URL: gatewayUrl,
    },
    password: (user) => reference.password(user),
    masterKey() {
      throw new Error("the admin calls go through ReferenceStack.admin");
    },
    stop: () => reference.stop(),
  };
}

beforeAll(async () => {
  stack = startReferenceStack({ name: "gateway", ports: PORTS });
  console.info(
    `reference stack ${stack.project} up in ${stack.startupSeconds} s`,
  );
  const installing = performance.now();
  acme = await installDistribution(distributionStack(stack), {
    name: "gateway",
  });
  const login = await acme.login("alice");
  if (login.status !== 0)
    throw new Error(`acmecode login failed:\n${login.stderr}`);
  console.info(
    `AcmeCode built, installed and signed in in ${Math.round((performance.now() - installing) / 100) / 10} s`,
  );
}, 600_000);

afterAll(async () => {
  try {
    // A platform secret store outlives the temporary directory: sign out.
    if (acme) await acme.run(["logout"]);
  } finally {
    acme?.remove();
    stack?.stop();
    console.info(
      `gateway-evidence.test.ts took ${Math.round((performance.now() - fileStarted) / 1000)} s`,
    );
  }
}, 120_000);

afterEach(async () => {
  // A failed test may leave queued mock faults or a cooled-down deployment.
  await clearFaults();
  if (cooling !== undefined) await untilServed(cooling);
}, 60_000);

const installed = () => {
  if (!acme) throw new Error("the distribution is not installed");
  return acme;
};

/** A chat completion with arbitrary content, streamed or not. */
function chat(
  key: string | undefined,
  content: string,
  { model = "acme/coder", stream = false } = {},
): Promise<HttpResult> {
  return request(`${stack.gateway}/v1/chat/completions`, {
    ...(key === undefined ? {} : { bearer: key }),
    body: {
      model,
      messages: [{ role: "user", content }],
      ...(stream
        ? { stream: true, stream_options: { include_usage: true } }
        : {}),
    },
  });
}

interface UpstreamRecord {
  model: string;
  stream: boolean;
  status: number;
  cut?: number;
}

/** What reached the mock upstream while `action` ran. */
async function upstreamDuring<T>(
  action: () => Promise<T>,
): Promise<{ value: T; upstream: UpstreamRecord[] }> {
  const before = (await stack.upstreamRequests()).length;
  const value = await action();
  const after = (await stack.upstreamRequests()) as UpstreamRecord[];
  // The log keeps the last 100: no case here comes near that.
  return { value, upstream: after.slice(before) };
}

async function queueFaults(fault: {
  status?: number;
  cut?: number;
  count: number;
}) {
  const queued = await request(`${stack.mock}/__mock/faults`, { body: fault });
  expect(queued.status).toBe(200);
}

const clearFaults = () =>
  request(`${stack.mock}/__mock/faults`, { method: "DELETE" });

/** Wait until the model's deployment serves requests again after a cooldown. */
function untilServed(key: string, model = "acme/coder") {
  cooling = undefined;
  return poll(
    `${model} to leave its cooldown`,
    async () => {
      const answer = await chat(key, "ping", { model });
      return answer.status === 200 ? answer : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 500 },
  );
}

function errorBody(result: HttpResult) {
  return (
    result.body as {
      error: { message: string; type: string; param: unknown; code: string };
    }
  ).error;
}

/** PiShip's inference client against the live gateway, as `liveCatalog: true` uses it. */
function inferenceClient(
  key: string | undefined,
  allowed: readonly string[] = ["acme/coder", "acme/general"],
) {
  return new OpenAICompatibleInferenceProvider({
    providerId: "acmecode-reference",
    baseUrl: `${stack.gateway}/v1`,
    api: "openai-completions",
    catalog: CATALOG,
    allowed,
    liveCatalog: true,
    fetch: (url, init) => fetch(url, init),
    secret: () => (key === undefined ? null : new SecretValue(key)),
  });
}

async function probeFailure(key: string | undefined): Promise<PiShipError> {
  const failure = await inferenceClient(key)
    .probe()
    .then(
      () => undefined,
      (error: unknown) => error,
    );
  if (!(failure instanceof PiShipError))
    throw new Error(`the probe did not fail with a PiShipError: ${failure}`);
  return failure;
}

/** The AcmeCode credential metadata: never a secret. */
function credentialMetadata(): { credential_id: string; rejected_at?: string } {
  const path = join(
    installed().stateRoot,
    "credentials-metadata",
    "inference.json",
  );
  if (!existsSync(path)) throw new Error("no credential metadata");
  return JSON.parse(readFileSync(path, "utf8"));
}

/** The key AcmeCode holds now, for admin calls by its hash. */
async function heldKey(): Promise<{ key: string; hash: string }> {
  const held = await installed().secrets();
  if (!held) throw new Error("AcmeCode holds no credential");
  return { key: held.credential, hash: keyHash(held.credential) };
}

interface SmokeResult {
  status: number | null;
  stderr: string;
  seconds: number;
  modelRequest?: {
    model: string;
    text: string;
    stopReason: string | null;
    error?: string;
  };
  access?: { credential: { credentialId: string }; notices: string[] };
}

/** `acmecode --smoke-model`: one real prompt through Pi, the gateway and the mock. */
async function smokeModel(args: string[] = []): Promise<SmokeResult> {
  const started = performance.now();
  const done = await installed().run([...args, "--smoke-model"]);
  const seconds = Math.round((performance.now() - started) / 100) / 10;
  const line = done.stdout.trim().split("\n").at(-1) ?? "";
  const parsed = line.startsWith("{") ? JSON.parse(line) : {};
  return {
    status: done.status,
    stderr: done.stderr,
    seconds,
    modelRequest: parsed.modelRequest,
    access: parsed.access,
  };
}

/** Pi's assistant message as PiShip's in-session hook sees it. */
const assistantMessage = (result: SmokeResult) => ({
  role: "assistant",
  stopReason: result.modelRequest?.stopReason,
  errorMessage: result.modelRequest?.error,
});

describe(`gateway evidence against LiteLLM v${LITELLM_VERSION} (live reference stack)`, () => {
  describe("authentication", () => {
    it("refuses a missing, malformed, deleted, expired and blocked key with 401, each with its own error type", async () => {
      const refusals: Record<string, HttpResult> = {};
      refusals.missing = await chat(undefined, "hello");
      refusals.malformed = await chat("not-a-litellm-key", "hello");
      refusals.unknown = await chat(`sk-${"0".repeat(22)}`, "hello");

      const deleted = await stack.acquire("bob");
      expect(
        (await stack.admin("/key/delete", { keys: [deleted.hash] })).status,
      ).toBe(200);
      refusals.deleted = await chat(deleted.key, "hello");

      // An administrator shortens the key's life at the gateway; PiShip's
      // metadata still holds the broker's longer expires_at.
      const expired = await stack.acquire("bob");
      expect(
        (
          await stack.admin("/key/update", {
            key: expired.hash,
            duration: "1s",
          })
        ).status,
      ).toBe(200);
      refusals.expired = (
        await poll("the key to expire", async () => {
          const answer = await chat(expired.key, "hello");
          return answer.status === 401 ? answer : undefined;
        })
      ).value;

      const blocked = await stack.acquire("bob");
      expect(
        (await stack.admin("/key/block", { key: blocked.hash })).status,
      ).toBe(200);
      refusals.blocked = await chat(blocked.key, "hello");

      const observed = Object.fromEntries(
        Object.entries(refusals).map(([name, answer]) => [
          name,
          {
            status: answer.status,
            type: errorType(answer),
            code: errorBody(answer).code,
          },
        ]),
      );
      expect(observed).toEqual({
        missing: { status: 401, type: "auth_error", code: "401" },
        malformed: { status: 401, type: "auth_error", code: "401" },
        unknown: { status: 401, type: "token_not_found_in_db", code: "401" },
        deleted: { status: 401, type: "token_not_found_in_db", code: "401" },
        expired: { status: 401, type: "expired_key", code: "401" },
        blocked: { status: 401, type: "auth_error", code: "401" },
      });
      expect(refusals.missing.scrubbed).toContain(
        "Authentication Error, No api key passed in.",
      );
      expect(refusals.malformed.scrubbed).toContain(
        "LiteLLM Virtual Key expected. Received=not-****-key, expected to start with 'sk-'.",
      );
      expect(refusals.deleted.scrubbed).toContain(
        "Authentication Error, Invalid proxy server token passed.",
      );
      expect(refusals.deleted.scrubbed).toContain(
        "Unable to find token in cache or `LiteLLM_VerificationTokenTable`",
      );
      expect(refusals.expired.scrubbed).toContain(
        "Authentication Error - Expired Key. Key Expiry time",
      );
      expect(refusals.blocked.scrubbed).toContain(
        "Authentication Error, Key is blocked. Update via `/key/unblock` if you're an admin.",
      );
      for (const answer of Object.values(refusals)) {
        expect(answer.headers["retry-after"]).toBeUndefined();
        expect(answer.headers["www-authenticate"]).toBeUndefined();
      }

      // The model list refuses them the same way, and PiShip's inference
      // client reads every one as a rejected runtime credential.
      for (const [name, key] of [
        ["missing", undefined],
        ["malformed", "not-a-litellm-key"],
        ["deleted", deleted.key],
        ["expired", expired.key],
        ["blocked", blocked.key],
      ] as const) {
        const listed = await stack.models(key ?? "");
        expect([name, listed.status]).toEqual([name, 401]);
        const failure = await probeFailure(key);
        expect([name, failure.code, failure.retryable]).toEqual([
          name,
          "CREDENTIAL_REVOKED",
          false,
        ]);
        expect(failure.userAction).toBe(
          "PiShip will re-acquire once; if it persists, run login again",
        );
      }
    });

    it("renews a credential the gateway refuses as blocked or expired when AcmeCode starts", async () => {
      for (const refusal of ["blocked", "expired"] as const) {
        const before = credentialMetadata().credential_id;
        const { key, hash } = await heldKey();
        if (refusal === "blocked")
          expect((await stack.admin("/key/block", { key: hash })).status).toBe(
            200,
          );
        else {
          expect(
            (await stack.admin("/key/update", { key: hash, duration: "1s" }))
              .status,
          ).toBe(200);
          await poll("the key to expire", async () =>
            (await stack.models(key)).status === 401 ? true : undefined,
          );
        }
        const smoke = await installed().smoke();
        expect(smoke.access.credential.credentialId).not.toBe(before);
        expect(smoke.access.notices).toContain(
          "The gateway rejected the stored credential; a new credential was acquired",
        );
        expect((await stack.models((await heldKey()).key)).status).toBe(200);
      }
    });

    it("reports CREDENTIAL_REVOKED when the renewal of a refused credential fails, and renews on the next start", async () => {
      const before = credentialMetadata().credential_id;
      const { hash } = await heldKey();
      expect((await stack.admin("/key/block", { key: hash })).status).toBe(200);
      stack.service("stop", "broker");
      let refused: Awaited<ReturnType<Installed["run"]>>;
      try {
        refused = await installed().run(["--smoke"]);
      } finally {
        stack.service("start", "broker");
      }
      expect(refused.status).toBe(1);
      console.info(`failed renewal, as the user sees it:\n${refused.stderr}`);
      // The broker's transport failure keeps the managed fetch's code in
      // parentheses: it names the gateway although the broker is down, and
      // it now adds the system error behind it (which one depends on how the
      // container runtime closes a published port). Pins current behavior,
      // expected to change when the mapping is fixed.
      expect(refused.stderr).toMatch(
        /CREDENTIAL_REVOKED: The runtime credential was rejected and could not be renewed: The credential broker is unreachable \(GATEWAY_UNREACHABLE(: [A-Z][A-Z0-9_]+)?\)\nAction: Try again later; if it keeps failing, run the branded login command/,
      );
      // The rejection is recorded, so the next start renews first.
      expect(credentialMetadata()).toMatchObject({ credential_id: before });
      expect(credentialMetadata().rejected_at).toEqual(expect.any(String));

      const smoke = await installed().smoke();
      expect(smoke.access.credential.credentialId).not.toBe(before);
      expect(credentialMetadata().rejected_at).toBeUndefined();
    });
  });

  describe("model catalog", () => {
    it("lists only the key's models, and PiShip offers the intersection of allowlist, entitlement and live list", async () => {
      const bob = await stack.acquire("bob");
      const alice = await stack.acquire("alice");
      const ids = (result: HttpResult) =>
        (result.body as { data: { id: string }[] }).data.map(
          (model) => model.id,
        );
      expect(ids(await stack.models(bob.key))).toEqual(["acme/coder"]);
      expect(ids(await stack.models(alice.key))).toEqual([
        "acme/coder",
        "acme/general",
      ]);

      // The organization narrows Alice's key at the gateway after issuing it:
      // the entitlement PiShip holds still says both.
      expect(
        (
          await stack.admin("/key/update", {
            key: alice.hash,
            models: ["acme/coder"],
          })
        ).status,
      ).toBe(200);
      expect(ids(await stack.models(alice.key))).toEqual(["acme/coder"]);

      const offered = async (
        key: string,
        allowed: readonly string[],
        entitled: readonly string[],
      ) =>
        (
          await inferenceClient(key, allowed).listModels(null, {
            ref: "gateway-evidence",
            mode: "http-broker",
            models: entitled,
          })
        ).map((model) => [
          model.id,
          model.availability.available
            ? "available"
            : model.availability.reason,
        ]);
      expect(
        await offered(
          alice.key,
          ["acme/coder", "acme/general", "acme/extra"],
          alice.models,
        ),
      ).toEqual([
        ["acme/coder", "available"],
        ["acme/general", "not currently listed by the inference gateway"],
        ["acme/extra", "not included in the runtime credential entitlement"],
      ]);
      // A gateway listing wider than the allowlist widens nothing.
      const wide = await stack.acquire("alice");
      expect(
        await offered(
          wide.key,
          ["acme/general"],
          ["acme/coder", "acme/general"],
        ),
      ).toEqual([["acme/general", "available"]]);
    });

    it("shows the narrowed live list in AcmeCode's models command", async () => {
      const { hash } = await heldKey();
      expect(
        (
          await stack.admin("/key/update", {
            key: hash,
            models: ["acme/coder"],
          })
        ).status,
      ).toBe(200);
      const models = await installed().run(["models"]);
      expect(models.status, models.stderr).toBe(0);
      expect(models.stdout).toMatch(
        /^\* acme\/coder\s+Acme Coder\s+available/m,
      );
      expect(models.stdout).toMatch(
        /^ {2}acme\/general\s+Acme General\s+unavailable \(not currently listed by the inference gateway\)/m,
      );
      const refused = await installed().run([
        "--model",
        "acme/general",
        "--smoke",
      ]);
      expect(refused.status).toBe(1);
      expect(refused.stderr).toContain("MODEL_UNAVAILABLE");
      // Give the key its models back for what follows.
      expect(
        (
          await stack.admin("/key/update", {
            key: hash,
            models: ["acme/coder", "acme/general"],
          })
        ).status,
      ).toBe(200);
    });
  });

  describe("streaming", () => {
    it("streams SSE chunks, a stop, a usage chunk and [DONE] with a broker-minted key", async () => {
      const bob = await stack.acquire("bob");
      const { value: streamed, upstream } = await upstreamDuring(() =>
        chat(bob.key, "one two three", { stream: true }),
      );
      expect(streamed.status).toBe(200);
      expect(streamed.headers["content-type"]).toContain("text/event-stream");
      expect(streamed.headers["x-litellm-version"]).toBe(LITELLM_VERSION);
      const events = String(streamed.body)
        .split("\n")
        .filter((line) => line.startsWith("data: "))
        .map((line) => line.slice(6));
      expect(events.at(-1)).toBe("[DONE]");
      const chunks = events.slice(0, -1).map((event) => JSON.parse(event));
      expect(chunks.length).toBeGreaterThan(3);
      expect(
        chunks
          .map((chunk) => chunk.choices?.[0]?.delta?.content ?? "")
          .join(""),
      ).toBe(REPLY);
      expect(
        chunks.filter((chunk) => chunk.choices?.[0]?.finish_reason === "stop"),
      ).toHaveLength(1);
      expect(chunks.at(-1).usage).toMatchObject({
        prompt_tokens: 3,
        completion_tokens: 5,
        total_tokens: 8,
      });
      expect(upstream).toEqual([
        {
          time: expect.any(String),
          model: "gpt-4.1",
          stream: true,
          status: 200,
        },
      ]);
    });

    it("ends a stream the upstream cuts mid-answer with an error event and no [DONE]", async () => {
      const bob = await stack.acquire("bob");
      const { value: cut, upstream } = await upstreamDuring(() =>
        chat(bob.key, "one two three [mock:cut=3]", { stream: true }),
      );
      // The status line went out with the first chunk, so it says 200.
      expect(cut.status).toBe(200);
      const events = String(cut.body)
        .split("\n")
        .filter((line) => line.startsWith("data: "))
        .map((line) => line.slice(6));
      expect(events).not.toContain("[DONE]");
      const chunks = events.map((event) => JSON.parse(event));
      expect(chunks.some((chunk) => chunk.choices?.[0]?.finish_reason)).toBe(
        false,
      );
      expect(chunks.at(-1)).toEqual({
        error: {
          message: expect.stringContaining(
            "litellm.APIConnectionError: APIConnectionError: OpenAIException - Response payload is not completed",
          ),
          type: null,
          param: null,
          code: "500",
        },
      });
      // No retry once the answer has started.
      expect(upstream).toHaveLength(1);
      expect(upstream[0]).toMatchObject({ stream: true, cut: 3 });
    });
  });

  describe("upstream failures through LiteLLM", () => {
    it("passes an upstream 401 on without a retry and cools the deployment down for 5 s", async () => {
      const bob = await stack.acquire("bob");
      cooling = bob.key;
      const { value: refused, upstream } = await upstreamDuring(() =>
        chat(bob.key, "hello [mock:status=401]"),
      );
      expect(refused.status).toBe(401);
      expect(errorBody(refused)).toEqual({
        message:
          "litellm.AuthenticationError: AuthenticationError: OpenAIException - Incorrect API key provided.. Received Model Group=acme/coder\nAvailable Model Group Fallbacks=None",
        type: "authentication_error",
        param: null,
        code: "401",
      });
      expect(upstream).toHaveLength(1);
      // PiShip reads the provider's 401 as its own credential being rejected.
      // Pins current behavior, expected to change when the mapping is fixed:
      // the provider's 401 is not the user's.
      expect(classifyGatewayStatus(refused.status, refused.headers)?.code).toBe(
        "CREDENTIAL_REVOKED",
      );

      // Every key's next request for that model is refused without reaching
      // the upstream; the other model is served.
      const { value: cooled, upstream: none } = await upstreamDuring(() =>
        chat(bob.key, "hello"),
      );
      expect(cooled.status).toBe(429);
      expect(errorType(cooled)).toBe("all_deployments_in_cooldown");
      expect(cooled.headers["retry-after"]).toBe("5");
      expect(cooled.scrubbed).toContain(
        "No deployments available for selected model, Try again in 5 seconds.",
      );
      expect(none).toHaveLength(0);
      const failure = classifyGatewayStatus(cooled.status, cooled.headers);
      expect([
        failure?.code,
        failure?.retryable,
        failure?.retryAfterMs,
      ]).toEqual(["GATEWAY_RATE_LIMITED", true, 5000]);
      const alice = await stack.acquire("alice");
      expect(
        (await chat(alice.key, "hello", { model: "acme/general" })).status,
      ).toBe(200);
      const { elapsedMs } = await untilServed(bob.key);
      console.info(`acme/coder served again after ${elapsedMs} ms`);
    });

    const cases = [
      {
        status: 403,
        type: "permission_error",
        message:
          "litellm.APIError: APIError: OpenAIException - Mock upstream denies this request.",
      },
      {
        status: 429,
        type: "throttling_error",
        message:
          "litellm.RateLimitError: RateLimitError: OpenAIException - Mock upstream rate limit reached.",
      },
      {
        status: 500,
        type: "internal_server_error",
        message:
          "litellm.InternalServerError: InternalServerError: OpenAIException - Mock upstream failure (500).",
      },
      {
        status: 502,
        type: "internal_server_error",
        message:
          "litellm.BadGatewayError: BadGatewayError: OpenAIException - Mock upstream failure (502).",
      },
      {
        status: 503,
        type: "internal_server_error",
        message:
          "litellm.ServiceUnavailableError: ServiceUnavailableError: OpenAIException - Mock upstream failure (503).",
      },
      {
        status: 504,
        type: "internal_server_error",
        message:
          "litellm.Timeout: Timeout Error: OpenAIException - Mock upstream failure (504).",
      },
    ];
    it.each(cases)(
      "passes an upstream $status on after two retries, without a cooldown",
      async ({ status, type, message }) => {
        const bob = await stack.acquire("bob");
        const started = performance.now();
        const { value: refused, upstream } = await upstreamDuring(() =>
          chat(bob.key, `hello [mock:status=${status}]`),
        );
        const elapsed = Math.round(performance.now() - started);
        expect(refused.status).toBe(status);
        const body = errorBody(refused);
        expect(body).toMatchObject({ type, param: null, code: String(status) });
        expect(body.message).toContain(message);
        expect(body.message).toContain("Received Model Group=acme/coder");
        // Three attempts, with LiteLLM's backoff between them.
        expect(upstream.map((record) => record.status)).toEqual([
          status,
          status,
          status,
        ]);
        expect(refused.headers["retry-after"]).toBeUndefined();
        // Pins current behavior, expected to change when the mapping is fixed:
        // the upstream's retry time is only in llm_provider-retry-after, so
        // PiShip's mapping below has no retryAfterMs for a 429.
        if (status === 429)
          expect(refused.headers["llm_provider-retry-after"]).toBe("1");
        console.info(
          `upstream ${status}: LiteLLM answered after ${elapsed} ms`,
        );

        // Pins current behavior, expected to change when the mapping is fixed:
        // an upstream 403 (permission_error) reads as MODEL_DENIED, and a 429
        // has no retry time.
        const failure = classifyGatewayStatus(refused.status, refused.headers);
        expect({
          code: failure?.code,
          retryable: failure?.retryable,
          retryAfterMs: failure?.retryAfterMs,
        }).toEqual(
          status === 403
            ? {
                code: "MODEL_DENIED",
                retryable: false,
                retryAfterMs: undefined,
              }
            : status === 429
              ? {
                  code: "GATEWAY_RATE_LIMITED",
                  retryable: true,
                  retryAfterMs: undefined,
                }
              : {
                  code: "GATEWAY_UNREACHABLE",
                  retryable: true,
                  retryAfterMs: undefined,
                },
        );
        // No cooldown: the next request is served at once.
        expect((await chat(bob.key, "hello")).status).toBe(200);
      },
    );

    it("retries a single upstream failure and answers 200", async () => {
      const bob = await stack.acquire("bob");
      await queueFaults({ status: 503, count: 1 });
      const { value: answer, upstream } = await upstreamDuring(() =>
        chat(bob.key, "hello"),
      );
      expect(answer.status).toBe(200);
      expect(answer.headers["x-litellm-attempted-retries"]).toBe("1");
      expect(answer.headers["x-litellm-max-retries"]).toBe("2");
      expect(upstream.map((record) => record.status)).toEqual([503, 200]);
    });
  });

  describe("in a session: Pi's request through the gateway, read by PiShip", () => {
    it("an upstream 401 is taken as a rejected runtime credential, which the next start replaces", async () => {
      const before = credentialMetadata().credential_id;
      const bob = await stack.acquire("bob");
      cooling = bob.key;
      await queueFaults({ status: 401, count: 1 });
      const { value: result, upstream } = await upstreamDuring(() =>
        smokeModel(),
      );
      console.info(
        `upstream 401 in a session (${result.seconds} s): ${JSON.stringify(result.modelRequest)}`,
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("GATEWAY_PROTOCOL_ERROR");
      expect(result.modelRequest?.stopReason).toBe("error");
      // Pi's message is the status and LiteLLM's error object.
      expect(result.modelRequest?.error).toMatch(
        /^401: \{"message":"litellm\.AuthenticationError: AuthenticationError: OpenAIException - Incorrect API key provided\./,
      );
      expect(result.modelRequest?.error).toContain(
        '"type":"authentication_error"',
      );
      expect(upstream.map((record) => record.status)).toEqual([401]);
      // Pins current behavior, expected to change when the mapping is fixed: an
      // upstream 401 (type authentication_error) is not the user's credential,
      // which should be neither marked rejected nor replaced.
      expect(isCredentialRejection(assistantMessage(result))).toBe(true);
      expect(credentialMetadata().rejected_at).toEqual(expect.any(String));

      await untilServed(bob.key);
      const next = await installed().smoke();
      expect(next.access.credential.credentialId).not.toBe(before);
    });

    it("an upstream 403 is taken as a model denial, which re-reads the entitlement", async () => {
      const before = credentialMetadata().credential_id;
      await queueFaults({ status: 403, count: 3 });
      const { value: result, upstream } = await upstreamDuring(() =>
        smokeModel(),
      );
      console.info(
        `upstream 403 in a session (${result.seconds} s): ${JSON.stringify(result.modelRequest)}`,
      );
      expect(result.status).toBe(1);
      expect(result.modelRequest?.stopReason).toBe("error");
      expect(result.modelRequest?.error).toMatch(
        /^403: \{"message":"litellm\.APIError: APIError: OpenAIException - Mock upstream denies this request\./,
      );
      expect(result.modelRequest?.error).toContain('"type":"permission_error"');
      expect(upstream.map((record) => record.status)).toEqual([403, 403, 403]);
      expect(isCredentialRejection(assistantMessage(result))).toBe(false);
      // Pins current behavior, expected to change when the mapping is fixed: an
      // upstream 403 (permission_error) is not the gateway's model denial
      // (key_model_access_denied), yet it re-reads the entitlement.
      expect(isModelDenial(assistantMessage(result))).toBe(true);
      // The entitlement re-read is a renewal through the refresh path: it
      // mints a new credential.
      expect(credentialMetadata().credential_id).not.toBe(before);
    });

    it("an upstream 429 that clears is retried by Pi and answered", async () => {
      await queueFaults({ status: 429, count: 3 });
      const { value: result, upstream } = await upstreamDuring(() =>
        smokeModel(),
      );
      console.info(
        `upstream 429 x3 in a session (${result.seconds} s): upstream ${JSON.stringify(upstream.map((record) => record.status))}`,
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.modelRequest).toMatchObject({
        text: REPLY,
        stopReason: "stop",
      });
      // LiteLLM's three attempts, then Pi's retry.
      expect(upstream.map((record) => record.status)).toEqual([
        429, 429, 429, 200,
      ]);
    });

    it("an upstream 503 that persists ends the request as an error, never as an answer", async () => {
      await queueFaults({ status: 503, count: 60 });
      const { value: result, upstream } = await upstreamDuring(() =>
        smokeModel(),
      );
      await clearFaults();
      console.info(
        `upstream 503 in a session (${result.seconds} s, ${upstream.length} upstream attempts): ${JSON.stringify(result.modelRequest)}`,
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("GATEWAY_PROTOCOL_ERROR");
      expect(result.modelRequest?.stopReason).toBe("error");
      expect(result.modelRequest?.text).not.toBe(REPLY);
      expect(result.modelRequest?.error).toMatch(
        /^503: \{"message":"litellm\.ServiceUnavailableError: /,
      );
      // Pi's first attempt and its three retries, each tried three times by
      // LiteLLM.
      expect(upstream.map((record) => record.status)).toEqual(
        Array(12).fill(503),
      );
      expect(isCredentialRejection(assistantMessage(result))).toBe(false);
      expect(isModelDenial(assistantMessage(result))).toBe(false);
    });

    it("a stream the upstream cuts once is retried by Pi and answered in full", async () => {
      await queueFaults({ cut: 3, count: 1 });
      const { value: result, upstream } = await upstreamDuring(() =>
        smokeModel(),
      );
      console.info(
        `cut stream once in a session (${result.seconds} s): upstream ${JSON.stringify(upstream)}`,
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.modelRequest).toMatchObject({
        text: REPLY,
        stopReason: "stop",
      });
      expect(upstream.map((record) => record.cut ?? record.status)).toEqual([
        3, 200,
      ]);
    });

    it("a stream the upstream keeps cutting ends as an error, never as a complete answer", async () => {
      await queueFaults({ cut: 3, count: 20 });
      const { value: result, upstream } = await upstreamDuring(() =>
        smokeModel(),
      );
      await clearFaults();
      console.info(
        `cut stream in a session (${result.seconds} s, ${upstream.length} upstream attempts): ${JSON.stringify(result.modelRequest)}`,
      );
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("GATEWAY_PROTOCOL_ERROR");
      expect(result.modelRequest?.stopReason).toBe("error");
      expect(result.modelRequest?.text).not.toBe(REPLY);
      // LiteLLM's error event carries no status, so Pi's message has none.
      expect(result.modelRequest?.error).toBe(
        "litellm.APIConnectionError: APIConnectionError: OpenAIException - Response payload is not completed: <TransferEncodingError: 400, message='Not enough data to satisfy transfer length header.'>",
      );
      // The partial text is kept, and marked as an error.
      expect(result.modelRequest?.text).toBe("Reference mock");
      // Pi's first attempt and its three retries; LiteLLM retries none.
      expect(upstream.map((record) => record.cut)).toEqual([3, 3, 3, 3]);
      expect(isCredentialRejection(assistantMessage(result))).toBe(false);
    });
  });
});
