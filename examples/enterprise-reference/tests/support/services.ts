import type { Stack } from "./stack.js";

// Direct calls to the stack's services, to check from outside PiShip what PiShip
// did there: which key exists at the gateway, whether a key still works,
// whether an identity token is still live. Every function returns statuses and
// non-secret fields only, because LiteLLM's error messages quote key
// fragments and a token endpoint answer carries tokens.

interface ErrorBody {
  readonly error?: { readonly type?: unknown };
}

async function json(response: Response): Promise<unknown> {
  return response.json().catch(() => ({}));
}

export interface GatewayAnswer {
  readonly status: number;
  /** LiteLLM's error `type`, such as key_model_access_denied; never its message. */
  readonly error?: string;
}

function answer(status: number, body: unknown): GatewayAnswer {
  const type = (body as ErrorBody).error?.type;
  return { status, ...(typeof type === "string" ? { error: type } : {}) };
}

/** `GET /v1/models` with a runtime credential: status and listed model IDs. */
export async function gatewayModels(
  stack: Stack,
  credential: string,
): Promise<GatewayAnswer & { readonly models: string[] }> {
  const response = await fetch(`${stack.gatewayUrl}/models`, {
    headers: { authorization: `Bearer ${credential}` },
  });
  const body = (await json(response)) as {
    data?: readonly { id?: unknown }[];
  };
  return {
    ...answer(response.status, body),
    models: (body.data ?? []).flatMap((entry) =>
      typeof entry.id === "string" ? [entry.id] : [],
    ),
  };
}

/** One non-streaming chat completion with a runtime credential. */
export async function gatewayChat(
  stack: Stack,
  credential: string,
  model: string,
): Promise<GatewayAnswer & { readonly reply?: string }> {
  const response = await fetch(`${stack.gatewayUrl}/chat/completions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${credential}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "Say hello." }],
    }),
  });
  const body = (await json(response)) as {
    choices?: readonly { message?: { content?: unknown } }[];
  };
  const reply = body.choices?.[0]?.message?.content;
  return {
    ...answer(response.status, body),
    ...(typeof reply === "string" ? { reply } : {}),
  };
}

export interface KeyRecord {
  readonly alias: string;
  readonly models: readonly string[];
  readonly userId: string | null;
  readonly teamId: string | null;
  readonly expires: string | null;
  readonly metadata: Readonly<Record<string, unknown>>;
}

/**
 * The gateway's own record of the key whose alias is the credential ID, read
 * with the admin key; `undefined` when LiteLLM has no such key (deleted,
 * expired, or never issued).
 */
export async function gatewayKey(
  stack: Stack,
  alias: string,
): Promise<KeyRecord | undefined> {
  const response = await fetch(
    `http://127.0.0.1:${stack.ports.LITELLM_PORT}/key/list?key_alias=${encodeURIComponent(alias)}&return_full_object=true`,
    { headers: { authorization: `Bearer ${stack.masterKey()}` } },
  );
  if (!response.ok)
    throw new Error(`the LiteLLM key list answered ${response.status}`);
  const body = (await json(response)) as {
    keys?: readonly Record<string, unknown>[];
  };
  const [key] = (body.keys ?? []).filter((entry) => entry.key_alias === alias);
  if (!key) return undefined;
  return {
    alias,
    models: Array.isArray(key.models) ? (key.models as string[]) : [],
    userId: typeof key.user_id === "string" ? key.user_id : null,
    teamId: typeof key.team_id === "string" ? key.team_id : null,
    expires: typeof key.expires === "string" ? key.expires : null,
    metadata: (key.metadata ?? {}) as Record<string, unknown>,
  };
}

/** Delete a key at the gateway with the admin key, as an operator would. */
export async function gatewayDeleteKey(
  stack: Stack,
  alias: string,
): Promise<void> {
  const response = await fetch(
    `http://127.0.0.1:${stack.ports.LITELLM_PORT}/key/delete`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${stack.masterKey()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ key_aliases: [alias] }),
    },
  );
  if (!response.ok)
    throw new Error(`the LiteLLM key delete answered ${response.status}`);
}

const oidc = (stack: Stack) => `${stack.issuer}/protocol/openid-connect`;

/**
 * Whether Keycloak still honors an identity access token (`userinfo`).
 * Returns the HTTP status only: 200 live, 401 revoked or expired.
 */
export async function accessTokenStatus(
  stack: Stack,
  accessToken: string,
): Promise<number> {
  const response = await fetch(`${oidc(stack)}/userinfo`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  return response.status;
}

/**
 * Whether Keycloak still honors a refresh token: tries the refresh grant and
 * returns the status and OAuth error code only. A live token is rotated by the
 * attempt, so call this on a token that is expected to be revoked.
 */
export async function refreshTokenStatus(
  stack: Stack,
  refreshToken: string,
): Promise<{ readonly status: number; readonly error?: string }> {
  const response = await fetch(`${oidc(stack)}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: "acmecode",
      refresh_token: refreshToken,
    }),
  });
  const body = (await json(response)) as { error?: unknown };
  return {
    status: response.status,
    ...(typeof body.error === "string" ? { error: body.error } : {}),
  };
}

export interface UpstreamRequest {
  readonly model: string | null;
  readonly stream: boolean;
  readonly status: number;
}

/**
 * What LiteLLM actually sent to the model upstream, oldest first: the mock
 * records the model, the stream flag, and the status of each completion.
 */
export async function upstreamRequests(
  stack: Stack,
): Promise<UpstreamRequest[]> {
  const response = await fetch(
    `http://127.0.0.1:${stack.ports.MOCK_UPSTREAM_PORT}/__mock/requests`,
  );
  if (!response.ok)
    throw new Error(`the mock upstream answered ${response.status}`);
  const body = (await json(response)) as { requests?: UpstreamRequest[] };
  return body.requests ?? [];
}
