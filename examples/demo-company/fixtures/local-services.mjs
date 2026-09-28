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

/**
 * Start all fixture services on one loopback port.
 * `knobs` can be mutated by tests to inject negative behaviors.
 */
export async function startLocalServices(options = {}) {
  const clientId = options.clientId ?? "demo-company-cli";
  const signingKey = keyPair("demo-signing-key");
  const rogueKey = keyPair("demo-signing-key");
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
    brokerStatus: undefined,
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
      name: "Demo Developer",
      email: "developer@demo.example",
      email_verified: true,
    };
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: knobs.accessTokenTtl,
      refresh_token: refreshToken,
      id_token: signJwt(knobs.signWithRogueKey ? rogueKey : signingKey, claims),
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
        });
        redirectUrl.searchParams.set("code", code);
        if (stateParam !== null)
          redirectUrl.searchParams.set("state", stateParam);
        redirectUrl.searchParams.set("iss", issuer);
      }
      response.writeHead(302, { location: redirectUrl.toString() });
      return response.end();
    }
    if (path === "/idp/token" && request.method === "POST") {
      const form = new URLSearchParams(text);
      if (form.get("client_id") !== clientId)
        return json(response, 401, { error: "invalid_client" });
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
          return json(response, 400, { error: "invalid_grant" });
        return json(
          response,
          200,
          issueTokens(
            { subject: "demo-user-1", scope: entry.scope },
            entry.nonce,
          ),
        );
      }
      if (form.get("grant_type") === "refresh_token") {
        const token = form.get("refresh_token") ?? "";
        const session = state.refreshTokens.get(token);
        if (!session) return json(response, 400, { error: "invalid_grant" });
        state.refreshTokens.delete(token);
        return json(response, 200, issueTokens(session, undefined));
      }
      return json(response, 400, { error: "unsupported_grant_type" });
    }
    if (path === "/idp/revoke" && request.method === "POST") {
      const token = new URLSearchParams(text).get("token") ?? "";
      state.revokedTokens.push(token.slice(0, 8));
      state.accessTokens.delete(token);
      state.refreshTokens.delete(token);
      response.writeHead(200);
      return response.end();
    }
    if (path === "/broker/v1/llm-credential" && request.method === "POST") {
      if (knobs.brokerStatus)
        return json(response, knobs.brokerStatus, { error: "broker_failure" });
      const identity = activeAccess(request.headers.authorization);
      if (!identity) return json(response, 401, { error: "invalid_token" });
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
      return json(response, 200, {
        credential_type: "api_key",
        credential,
        credential_id: credentialId,
        expires_at: new Date(expires * 1000).toISOString(),
        models: knobs.entitledModels,
        ...(knobs.brokerBaseUrl ? { base_url: knobs.brokerBaseUrl } : {}),
      });
    }
    if (path === "/broker/v1/revoke" && request.method === "POST") {
      const entry = activeCredential(request.headers.authorization);
      if (entry) {
        entry.revoked = true;
        state.revokedCredentials.push(entry.id);
      }
      response.writeHead(204);
      return response.end();
    }
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
        server.closeAllConnections();
        server.close(() => resolve());
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
