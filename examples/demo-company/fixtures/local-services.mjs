#!/usr/bin/env node
// Deterministic local fixtures for the neutral demo-company distribution:
// an OIDC identity provider (Authorization Code + PKCE), an http-broker
// credential service, and an OpenAI-compatible inference gateway.
//
// This is test infrastructure for CI and local exploration only. It is not a
// real identity provider or gateway and is never evidence of a live
// integration. It auto-approves every sign-in for the fictional demo user.
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

const b64 = (value) => Buffer.from(value).toString("base64url");
const random = (bytes = 18) => randomBytes(bytes).toString("base64url");

function keyPair(kid) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    kid,
    privateKey,
    jwk: {
      ...publicKey.export({ format: "jwk" }),
      kid,
      alg: "RS256",
      use: "sig",
    },
  };
}

function signJwt(key, claims) {
  const header = b64(
    JSON.stringify({ alg: "RS256", kid: key.kid, typ: "JWT" }),
  );
  const payload = b64(JSON.stringify(claims));
  const signature = sign(
    "sha256",
    Buffer.from(`${header}.${payload}`),
    key.privateKey,
  );
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

async function body(request) {
  let data = "";
  for await (const chunk of request) data += chunk;
  return data;
}

function json(response, status, value, headers = {}) {
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(value));
}

const now = () => Math.floor(Date.now() / 1000);

/** Sorted-key JSON, so the same fields in another order are the same input. */
function canonicalJson(text) {
  try {
    return JSON.stringify(JSON.parse(text), (_key, value) =>
      value && typeof value === "object" && !Array.isArray(value)
        ? Object.fromEntries(
            Object.entries(value).sort(([a], [b]) => (a < b ? -1 : 1)),
          )
        : value,
    );
  } catch {
    return text;
  }
}

/** `Retry-After` header for a fault: seconds (number), HTTP-date (Date), or a verbatim string. */
function retryAfterHeader(value) {
  if (value === undefined) return {};
  return {
    "retry-after": value instanceof Date ? value.toUTCString() : String(value),
  };
}

/**
 * Wait for `ms`, or until the client hangs up. Resolves true when the client
 * is still connected, so a held request never outlives its connection.
 */
function pause(response, ms) {
  return new Promise((resolve) => {
    if (response.destroyed) return resolve(false);
    const finish = () => {
      clearTimeout(timer);
      response.off("close", finish);
      resolve(!response.destroyed);
    };
    const timer = setTimeout(finish, ms);
    response.once("close", finish);
  });
}

/**
 * Write a `{status, body?, headers?}` result; a missing body sends no body.
 * An undefined result means the request was dropped, so nothing is written.
 */
function respond(response, result) {
  if (result === undefined) return;
  if (result.body === undefined) {
    response.writeHead(result.status, result.headers ?? {});
    return response.end();
  }
  if (typeof result.body === "string") {
    response.writeHead(result.status, {
      "content-type": "text/html",
      "cache-control": "no-store",
      ...result.headers,
    });
    return response.end(result.body);
  }
  return json(response, result.status, result.body, result.headers);
}

// The signing key, generated once per process: an RSA key costs tens of
// milliseconds (several times that on a loaded CI runner), and a test file
// starts the services once per test. Each service still has its own issuer.
let processSigningKey;

/**
 * Start all fixture services on one loopback port.
 *
 * `knobs` can be mutated by tests to inject behaviors, and `state` can be read
 * to inspect what the services recorded. Every knob below is off by default.
 *
 * Who signs in (captured when the browser approves, so it can change between
 * logins against the same provider):
 *   subject          `sub` of the next sign-in (default "demo-user-1")
 *   email            `email` claim (default "developer@demo.example")
 *   displayName      `name` claim (default "Demo Developer")
 *   refreshSubject   `sub` a refresh grant claims instead of the session's own
 *
 * Broker idempotency (POST /broker/v1/llm-credential):
 *   brokerIdempotency        true: read the key, record it in
 *                            `state.idempotencyKeys`, replay the original
 *                            result for a repeated key with the same subject
 *                            and body, answer 409 for the same key with
 *                            different input. Only successful issues are kept.
 *   brokerIdempotencyHeader  header carrying the key (default "Idempotency-Key")
 *
 * Fault injection, the same seven knobs for each endpoint, where <e> is
 * `broker` (credential acquire), `revoke` (credential revoke) or `token`
 * (the identity provider's token endpoint):
 *   <e>Status         answer this HTTP status instead of serving, every time
 *   <e>RetryAfter     `Retry-After` on that answer: seconds (number), an
 *                     HTTP-date (Date) or a verbatim string
 *   <e>Body           body of that answer: an object is sent as JSON, a
 *                     string verbatim as text/html (a proxy error page).
 *                     Default: a small JSON error object
 *   <e>DelayMs        serve normally, but only after this delay (slow mode)
 *   <e>TimeoutMs      never answer: hold the request this long, then drop the
 *                     connection. A client that leaves earlier ends it early
 *   <e>TimeoutServes  true: with <e>TimeoutMs, do the work (issue, revoke, mint
 *                     tokens) first and withhold only the answer. False: the
 *                     request never reaches the service logic
 *   <e>Faults         one-shot queue of {status, retryAfter, body, delayMs,
 *                     timeoutMs, timeoutServes}. Each request takes the oldest
 *                     entry instead of the knobs above; {} serves normally;
 *                     an empty queue falls back to the knobs
 */
export async function startLocalServices(options = {}) {
  const clientId = options.clientId ?? "demo-company-cli";
  processSigningKey ??= keyPair("demo-signing-key");
  const signingKey = processSigningKey;
  // Same key id, other key material. Generated on first use: most services
  // never sign with it, and an RSA key costs tens of milliseconds.
  let rogue;
  const rogueKey = () => {
    rogue ??= keyPair("demo-signing-key");
    return rogue;
  };
  const knobs = {
    denyLogin: false,
    stateOverride: undefined,
    idTokenIssuer: undefined,
    idTokenAudience: undefined,
    idTokenNonce: undefined,
    signWithRogueKey: false,
    idTokenExpired: false,
    idTokenNotBefore: false,
    accessTokenTtl: 3600,
    subject: "demo-user-1",
    email: undefined,
    displayName: undefined,
    refreshSubject: undefined,
    brokerStatus: undefined,
    brokerRetryAfter: undefined,
    brokerBody: undefined,
    brokerDelayMs: 0,
    brokerTimeoutMs: 0,
    brokerTimeoutServes: false,
    brokerFaults: [],
    brokerIdempotency: false,
    brokerIdempotencyHeader: "Idempotency-Key",
    revokeStatus: undefined,
    revokeRetryAfter: undefined,
    revokeBody: undefined,
    revokeDelayMs: 0,
    revokeTimeoutMs: 0,
    revokeTimeoutServes: false,
    revokeFaults: [],
    tokenStatus: undefined,
    tokenRetryAfter: undefined,
    tokenBody: undefined,
    tokenDelayMs: 0,
    tokenTimeoutMs: 0,
    tokenTimeoutServes: false,
    tokenFaults: [],
    brokerBaseUrl: undefined,
    credentialTtl: 3600,
    entitledModels: ["acme/coder", "acme/general"],
    gatewayModels: ["acme/coder", "acme/general", "acme/review"],
    gatewayMode: "text",
    // With gatewayMode "script": one tool call per model turn, in order.
    toolScript: [],
    gatewayStatus: undefined,
    gatewayDelayMs: 0,
    acceptedKeys: [],
    ...options.knobs,
  };
  const state = {
    codes: new Map(),
    accessTokens: new Map(),
    refreshTokens: new Map(),
    credentials: new Map(),
    revokedTokens: [],
    revokedCredentials: [],
    requests: [],
    toolResults: [],
    authorizations: [],
    credentialCount: 0,
    // Every idempotency key the broker received, in order, repeats included.
    idempotencyKeys: [],
    // key -> { fingerprint, result }: what a repeated key replays.
    idempotency: new Map(),
  };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", base);
    const text = request.method === "POST" ? await body(request) : "";
    state.requests.push({
      method: request.method,
      path: url.pathname,
      authorization: request.headers.authorization ?? null,
      body: text,
    });
    try {
      await route(url, request, response, text);
    } catch (error) {
      console.error("fixture error:", error);
      json(response, 500, { error: "fixture_error" });
    }
  });
  await new Promise((resolve) =>
    server.listen(options.port ?? 0, "127.0.0.1", resolve),
  );
  const base = `http://127.0.0.1:${server.address().port}`;
  const issuer = `${base}/idp`;

  function issueTokens(session, nonce) {
    const accessToken = `demo-at-${random()}`;
    const refreshToken = `demo-rt-${random()}`;
    state.accessTokens.set(accessToken, {
      subject: session.subject,
      expires: now() + knobs.accessTokenTtl,
    });
    state.refreshTokens.set(refreshToken, session);
    const issued = now();
    const claims = {
      iss: knobs.idTokenIssuer ?? issuer,
      sub: session.subject,
      aud: knobs.idTokenAudience ?? clientId,
      exp: knobs.idTokenExpired ? issued - 600 : issued + 3600,
      iat: knobs.idTokenExpired ? issued - 1200 : issued,
      ...(knobs.idTokenNotBefore ? { nbf: issued + 3600 } : {}),
      ...(nonce === undefined ? {} : { nonce: knobs.idTokenNonce ?? nonce }),
      name: session.displayName ?? "Demo Developer",
      email: session.email ?? "developer@demo.example",
      email_verified: true,
    };
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: knobs.accessTokenTtl,
      refresh_token: refreshToken,
      id_token: signJwt(
        knobs.signWithRogueKey ? rogueKey() : signingKey,
        claims,
      ),
      scope: session.scope,
    };
  }

  function activeAccess(authorization) {
    const token = /^Bearer (.+)$/.exec(authorization ?? "")?.[1];
    const entry = token && state.accessTokens.get(token);
    return entry && entry.expires > now() ? entry : undefined;
  }

  function activeCredential(authorization) {
    const token = /^Bearer (.+)$/.exec(authorization ?? "")?.[1];
    if (token && knobs.acceptedKeys.includes(token))
      return { models: knobs.gatewayModels };
    const entry = token && state.credentials.get(token);
    return entry && !entry.revoked && entry.expires > now() ? entry : undefined;
  }

  async function sse(response, chunks) {
    response.writeHead(200, { "content-type": "text/event-stream" });
    for (const chunk of chunks) {
      if (response.destroyed) return;
      response.write(
        typeof chunk === "string"
          ? chunk
          : `data: ${JSON.stringify(chunk)}\n\n`,
      );
      if (knobs.gatewayDelayMs)
        await new Promise((resolve) =>
          setTimeout(resolve, knobs.gatewayDelayMs),
        );
    }
    if (!response.destroyed) response.end("data: [DONE]\n\n");
  }

  function completion(model, delta, finish) {
    return {
      id: "chatcmpl-demo",
      object: "chat.completion.chunk",
      created: now(),
      model,
      choices: [{ index: 0, delta, finish_reason: finish ?? null }],
    };
  }

  const FAULT_BODIES = {
    broker: { error: "broker_failure" },
    revoke: { error: "broker_failure" },
    token: { error: "server_error" },
  };

  /** The fault the next request to `kind` gets: the oldest queued one, else the knobs. */
  function nextFault(kind) {
    const queued = knobs[`${kind}Faults`];
    if (Array.isArray(queued) && queued.length > 0) return queued.shift();
    return {
      status: knobs[`${kind}Status`],
      retryAfter: knobs[`${kind}RetryAfter`],
      body: knobs[`${kind}Body`],
      delayMs: knobs[`${kind}DelayMs`],
      timeoutMs: knobs[`${kind}TimeoutMs`],
      timeoutServes: knobs[`${kind}TimeoutServes`],
    };
  }

  /**
   * Run `serve`, which returns a `{status, body?, headers?}` result, under the
   * endpoint's fault. Resolves the result to write, or undefined when the
   * request was dropped or the client left first.
   */
  async function faulted(kind, response, serve) {
    const fault = nextFault(kind);
    if (fault.delayMs && !(await pause(response, fault.delayMs)))
      return undefined;
    if (fault.timeoutMs) {
      if (fault.timeoutServes) serve();
      await pause(response, fault.timeoutMs);
      response.destroy();
      return undefined;
    }
    if (fault.status)
      return {
        status: fault.status,
        body: fault.body ?? FAULT_BODIES[kind],
        headers: retryAfterHeader(fault.retryAfter),
      };
    return serve();
  }

  function tokenGrant(text) {
    const form = new URLSearchParams(text);
    if (form.get("client_id") !== clientId)
      return { status: 401, body: { error: "invalid_client" } };
    if (form.get("grant_type") === "authorization_code") {
      const entry = state.codes.get(form.get("code") ?? "");
      state.codes.delete(form.get("code") ?? "");
      const verifier = form.get("code_verifier") ?? "";
      if (
        !entry ||
        entry.redirect !== form.get("redirect_uri") ||
        createHash("sha256").update(verifier).digest("base64url") !==
          entry.challenge
      )
        return { status: 400, body: { error: "invalid_grant" } };
      return {
        status: 200,
        body: issueTokens(
          {
            subject: entry.subject,
            scope: entry.scope,
            email: entry.email,
            displayName: entry.displayName,
          },
          entry.nonce,
        ),
      };
    }
    if (form.get("grant_type") === "refresh_token") {
      const token = form.get("refresh_token") ?? "";
      const session = state.refreshTokens.get(token);
      if (!session) return { status: 400, body: { error: "invalid_grant" } };
      state.refreshTokens.delete(token);
      return {
        status: 200,
        body: issueTokens(
          knobs.refreshSubject === undefined
            ? session
            : { ...session, subject: knobs.refreshSubject },
          undefined,
        ),
      };
    }
    return { status: 400, body: { error: "unsupported_grant_type" } };
  }

  function acquireCredential(request, text) {
    const identity = activeAccess(request.headers.authorization);
    if (!identity) return { status: 401, body: { error: "invalid_token" } };
    let key;
    let fingerprint;
    if (knobs.brokerIdempotency) {
      const header =
        request.headers[String(knobs.brokerIdempotencyHeader).toLowerCase()];
      key = (Array.isArray(header) ? header[0] : header) || undefined;
    }
    if (key !== undefined) {
      state.idempotencyKeys.push(key);
      fingerprint = createHash("sha256")
        .update(JSON.stringify([identity.subject, canonicalJson(text)]))
        .digest("hex");
      const seen = state.idempotency.get(key);
      if (seen)
        return seen.fingerprint === fingerprint
          ? { ...seen.result, headers: { "idempotent-replayed": "true" } }
          : { status: 409, body: { error: "idempotency_key_reuse" } };
    }
    state.credentialCount += 1;
    const credential = `sk-demo-${random()}`;
    const credentialId = `vk_demo_${state.credentialCount}`;
    const expires = now() + knobs.credentialTtl;
    state.credentials.set(credential, {
      id: credentialId,
      subject: identity.subject,
      expires,
      models: [...knobs.entitledModels],
      revoked: false,
    });
    const result = {
      status: 200,
      body: {
        credential_type: "api_key",
        credential,
        credential_id: credentialId,
        expires_at: new Date(expires * 1000).toISOString(),
        models: [...knobs.entitledModels],
        ...(knobs.brokerBaseUrl ? { base_url: knobs.brokerBaseUrl } : {}),
      },
    };
    if (key !== undefined) state.idempotency.set(key, { fingerprint, result });
    return result;
  }

  function revokeCredential(request) {
    const entry = activeCredential(request.headers.authorization);
    if (entry) {
      entry.revoked = true;
      state.revokedCredentials.push(entry.id);
    }
    return { status: 204 };
  }

  async function route(url, request, response, text) {
    const path = url.pathname;
    if (path === "/idp/.well-known/openid-configuration")
      return json(response, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        revocation_endpoint: `${issuer}/revoke`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["openid", "profile", "email"],
      });
    if (path === "/idp/jwks")
      return json(response, 200, { keys: [signingKey.jwk] });
    if (path === "/idp/authorize") {
      const redirect = url.searchParams.get("redirect_uri") ?? "";
      const redirectUrl = new URL(redirect);
      if (
        url.searchParams.get("client_id") !== clientId ||
        redirectUrl.hostname !== "127.0.0.1" ||
        redirectUrl.pathname !== "/callback"
      )
        return json(response, 400, { error: "invalid_request" });
      state.authorizations.push(Object.fromEntries(url.searchParams));
      const stateParam = knobs.stateOverride ?? url.searchParams.get("state");
      if (knobs.denyLogin) {
        redirectUrl.searchParams.set("error", "access_denied");
        redirectUrl.searchParams.set("state", stateParam ?? "");
      } else {
        if (
          url.searchParams.get("code_challenge_method") !== "S256" ||
          !url.searchParams.get("code_challenge") ||
          url.searchParams.get("response_type") !== "code"
        )
          return json(response, 400, {
            error: "invalid_request",
            error_description: "PKCE S256 required",
          });
        const code = `demo-code-${random()}`;
        state.codes.set(code, {
          challenge: url.searchParams.get("code_challenge"),
          nonce: url.searchParams.get("nonce") ?? undefined,
          redirect,
          scope: url.searchParams.get("scope") ?? "openid",
          // Who signed in is decided when the browser approves.
          subject: knobs.subject,
          email: knobs.email,
          displayName: knobs.displayName,
        });
        redirectUrl.searchParams.set("code", code);
        if (stateParam !== null)
          redirectUrl.searchParams.set("state", stateParam);
        redirectUrl.searchParams.set("iss", issuer);
      }
      response.writeHead(302, { location: redirectUrl.toString() });
      return response.end();
    }
    if (path === "/idp/token" && request.method === "POST")
      return respond(
        response,
        await faulted("token", response, () => tokenGrant(text)),
      );
    if (path === "/idp/revoke" && request.method === "POST") {
      const token = new URLSearchParams(text).get("token") ?? "";
      state.revokedTokens.push(token.slice(0, 8));
      state.accessTokens.delete(token);
      state.refreshTokens.delete(token);
      response.writeHead(200);
      return response.end();
    }
    if (path === "/broker/v1/llm-credential" && request.method === "POST")
      return respond(
        response,
        await faulted("broker", response, () =>
          acquireCredential(request, text),
        ),
      );
    if (path === "/broker/v1/revoke" && request.method === "POST")
      return respond(
        response,
        await faulted("revoke", response, () => revokeCredential(request)),
      );
    if (path === "/gateway/v1/models") {
      const entry = activeCredential(request.headers.authorization);
      if (!entry)
        return json(response, 401, { error: { message: "invalid api key" } });
      return json(response, 200, {
        object: "list",
        data: knobs.gatewayModels.map((id) => ({ id, object: "model" })),
      });
    }
    if (path === "/gateway/v1/chat/completions" && request.method === "POST") {
      if (knobs.gatewayStatus)
        return json(
          response,
          knobs.gatewayStatus,
          { error: { message: "gateway failure" } },
          knobs.gatewayStatus === 429 ? { "retry-after": "1" } : {},
        );
      const entry = activeCredential(request.headers.authorization);
      if (!entry)
        return json(response, 401, { error: { message: "invalid api key" } });
      const payload = JSON.parse(text);
      const model = payload.model;
      if (
        !knobs.gatewayModels.includes(model) ||
        (entry.models && !entry.models.includes(model))
      )
        return json(response, 404, {
          error: { message: `model ${model} not found` },
        });
      const messages = payload.messages ?? [];
      const toolMessages = messages.filter(
        (message) => message.role === "tool",
      );
      if (
        knobs.gatewayMode === "script" &&
        toolMessages.length < knobs.toolScript.length
      ) {
        const step = knobs.toolScript[toolMessages.length];
        const id = `call_script_${toolMessages.length + 1}`;
        return sse(response, [
          completion(model, {
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id,
                type: "function",
                function: { name: step.name, arguments: "" },
              },
            ],
          }),
          completion(model, {
            tool_calls: [
              {
                index: 0,
                function: { arguments: JSON.stringify(step.arguments ?? {}) },
              },
            ],
          }),
          completion(model, {}, "tool_calls"),
        ]);
      }
      if (knobs.gatewayMode === "script") {
        state.toolResults = toolMessages.map((message) =>
          Array.isArray(message.content)
            ? message.content.map((part) => part.text ?? "").join("")
            : String(message.content ?? ""),
        );
        const reply = `Script finished with ${toolMessages.length} tool result(s).`;
        return sse(response, [
          completion(model, { role: "assistant", content: reply }, "stop"),
        ]);
      }
      if (knobs.gatewayMode === "malformed")
        return sse(response, ["data: {not json\n\n"]);
      if (knobs.gatewayMode === "tool" && toolMessages.length === 0) {
        const available = (payload.tools ?? []).map(
          (tool) => tool.function?.name,
        );
        const name = available.includes("demo_context")
          ? "demo_context"
          : "read";
        return sse(response, [
          completion(model, {
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: "call_demo_1",
                type: "function",
                function: { name, arguments: "" },
              },
            ],
          }),
          completion(model, {
            tool_calls: [
              {
                index: 0,
                function: {
                  arguments: name === "read" ? '{"path":"piship.yaml"}' : "{}",
                },
              },
            ],
          }),
          completion(model, {}, "tool_calls"),
        ]);
      }
      const reply = toolMessages.length
        ? `Tool result received: ${String(toolMessages.at(-1)?.content ?? "").slice(0, 400)}`
        : `Hello from ${model}.`;
      const half = Math.ceil(reply.length / 2);
      return sse(response, [
        completion(model, { role: "assistant", content: reply.slice(0, half) }),
        completion(model, { content: reply.slice(half) }, "stop"),
        {
          ...completion(model, {}, null),
          choices: [],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        },
      ]);
    }
    json(response, 404, { error: "not_found" });
  }

  return {
    base,
    issuer,
    clientId,
    brokerUrl: `${base}/broker/v1/llm-credential`,
    revokeUrl: `${base}/broker/v1/revoke`,
    gatewayUrl: `${base}/gateway/v1`,
    knobs,
    state,
    env(prefix = "ACMECODE") {
      return {
        [`${prefix}_OIDC_ISSUER`]: issuer,
        [`${prefix}_OIDC_CLIENT_ID`]: clientId,
        [`${prefix}_CREDENTIAL_BROKER_URL`]: `${base}/broker/v1/llm-credential`,
        [`${prefix}_CREDENTIAL_REVOKE_URL`]: `${base}/broker/v1/revoke`,
        [`${prefix}_LLM_GATEWAY_URL`]: `${base}/gateway/v1`,
      };
    },
    /** Act as the browser: follow the authorization redirect to the loopback callback. */
    async approve(authorizationUrl) {
      const first = await fetch(authorizationUrl, { redirect: "manual" });
      const location = first.headers.get("location");
      if (!location)
        throw new Error(`authorization failed: HTTP ${first.status}`);
      const callback = await fetch(location);
      return callback.status;
    },
    close() {
      return new Promise((resolve) => {
        // Stop accepting first: a connection opened between the two calls
        // would otherwise keep close() waiting.
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const portIndex = process.argv.indexOf("--port");
  const services = await startLocalServices(
    portIndex > 0 ? { port: Number(process.argv[portIndex + 1]) } : {},
  );
  console.log(
    "# Local demo fixtures (not a real IdP or gateway). Export these, then run acmecode login:",
  );
  for (const [name, value] of Object.entries(services.env()))
    console.log(
      process.platform === "win32"
        ? `set ${name}=${value}`
        : `export ${name}=${value}`,
    );
  console.log(
    "# Sign-in is auto-approved: open the printed login URL in a browser.",
  );
}
