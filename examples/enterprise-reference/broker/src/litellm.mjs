// The LiteLLM admin calls the broker makes. Only open-source LiteLLM
// endpoints are used: /user/info, /user/new, /key/generate, /key/info,
// /key/list and /key/delete. No /key/{key}/regenerate, no model_max_budget,
// no team_id.
//
// The master key is sent only as the bearer of admin calls. Response bodies
// are parsed for the fields named here and are never logged or passed on:
// LiteLLM's own error messages quote parts of keys.

/** A LiteLLM call that failed. `unknownOutcome` means the request may have been acted on. */
export class UpstreamError extends Error {
  /**
   * @param {string} operation
   * @param {{ status?: number, unknownOutcome?: boolean }} [options]
   */
  constructor(operation, { status, unknownOutcome = false } = {}) {
    super(
      `LiteLLM ${operation} failed${status === undefined ? "" : ` (HTTP ${status})`}`,
    );
    this.name = "UpstreamError";
    this.operation = operation;
    this.status = status;
    this.unknownOutcome = unknownOutcome;
  }
}

/** Marks keys this broker issued, in the key's LiteLLM metadata. */
export const ISSUER_MARK = "piship-reference-broker";

/** Role of the LiteLLM users the broker creates: can use its keys, cannot create, change or delete keys or users. */
export const USER_ROLE = "internal_user_viewer";

/**
 * @param {object} options
 * @param {string} options.baseUrl LiteLLM admin origin, e.g. http://litellm:4000
 * @param {string} options.masterKey
 * @param {typeof fetch} [options.fetch]
 * @param {number} [options.timeoutMs]
 */
export function createLiteLLMAdmin({
  baseUrl,
  masterKey,
  fetch = globalThis.fetch,
  timeoutMs = 10_000,
}) {
  const origin = baseUrl.replace(/\/+$/, "");

  /**
   * @returns {Promise<{ status: number, body: any }>}
   * Throws UpstreamError with unknownOutcome when no answer was read.
   */
  async function call(
    operation,
    method,
    path,
    { bearer = masterKey, body } = {},
  ) {
    let response;
    try {
      response = await fetch(`${origin}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${bearer}`,
          accept: "application/json",
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      // The error itself is dropped: an HTTP client error message can quote
      // a header value, and the bearer is a secret.
      throw new UpstreamError(operation, { unknownOutcome: method !== "GET" });
    }
    let parsed = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    return { status: response.status, body: parsed };
  }

  return {
    /**
     * Make sure the LiteLLM user exists with the broker's role and budget.
     * An existing user keeps its budget and spend: that is what makes several
     * keys, and every rotation, count against one budget.
     */
    async ensureUser({
      userId,
      maxBudget,
      budgetDuration,
      tpmLimit,
      rpmLimit,
      metadata,
    }) {
      const info = await call(
        "user-info",
        "GET",
        `/user/info?user_id=${encodeURIComponent(userId)}`,
      );
      if (info.status === 200 && info.body?.user_info) {
        if (info.body.user_info.user_role !== USER_ROLE)
          throw new UpstreamError("user-role", { status: 200 });
        return;
      }
      if (info.status !== 404)
        throw new UpstreamError("user-info", { status: info.status });
      const created = await call("user-new", "POST", "/user/new", {
        body: {
          user_id: userId,
          user_role: USER_ROLE,
          // /user/new issues a key by default; the broker issues its own.
          auto_create_key: false,
          max_budget: maxBudget,
          ...(budgetDuration ? { budget_duration: budgetDuration } : {}),
          ...(tpmLimit ? { tpm_limit: tpmLimit } : {}),
          ...(rpmLimit ? { rpm_limit: rpmLimit } : {}),
          metadata,
        },
      });
      // 409: another request created it first.
      if (created.status !== 200 && created.status !== 409)
        throw new UpstreamError("user-new", { status: created.status });
    },

    /** @returns {Promise<{ key: string, expires: string }>} */
    async generateKey({
      userId,
      models,
      durationSeconds,
      alias,
      metadata,
      maxParallelRequests,
    }) {
      const result = await call("key-generate", "POST", "/key/generate", {
        body: {
          user_id: userId,
          models,
          duration: `${durationSeconds}s`,
          key_alias: alias,
          metadata: { ...metadata, issued_by: ISSUER_MARK },
          ...(maxParallelRequests
            ? { max_parallel_requests: maxParallelRequests }
            : {}),
        },
      });
      const key = result.body?.key;
      const expires = result.body?.expires;
      if (result.status !== 200 || typeof key !== "string" || key.length < 8)
        throw new UpstreamError("key-generate", {
          status: result.status,
          // A 2xx without a usable key may still have created one.
          unknownOutcome: result.status >= 200 && result.status < 300,
        });
      return { key, expires: typeof expires === "string" ? expires : "" };
    },

    /**
     * Look a key up with the key itself as the bearer: only its holder can
     * do that, and the answer describes that key.
     * @returns {Promise<null | { key_alias?: string, user_id?: string, metadata?: Record<string, unknown> }>}
     *   null when LiteLLM does not accept the key (unknown, deleted, expired)
     */
    async keyInfoAsHolder(key) {
      const result = await call("key-info", "GET", "/key/info", {
        bearer: key,
      });
      if (
        result.status === 401 ||
        result.status === 403 ||
        result.status === 404
      )
        return null;
      if (result.status !== 200 || !result.body?.info)
        throw new UpstreamError("key-info", { status: result.status });
      return result.body.info;
    },

    /**
     * Delete keys by value or by alias.
     * @returns {Promise<boolean>} true when deleted, false when none was found
     */
    async deleteKeys({ keys, aliases }) {
      const result = await call("key-delete", "POST", "/key/delete", {
        body: keys ? { keys } : { key_aliases: aliases },
      });
      if (result.status === 200) return true;
      if (result.status === 404) return false;
      throw new UpstreamError("key-delete", { status: result.status });
    },

    /**
     * The user's keys, newest first, as LiteLLM lists them (hashed token,
     * alias, creation time, metadata; never the key itself).
     */
    async listUserKeys(userId) {
      const result = await call(
        "key-list",
        "GET",
        `/key/list?user_id=${encodeURIComponent(userId)}&return_full_object=true&include_team_keys=false&size=100`,
      );
      if (result.status !== 200 || !Array.isArray(result.body?.keys))
        throw new UpstreamError("key-list", { status: result.status });
      return result.body.keys
        .filter((entry) => entry && typeof entry === "object")
        .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    },
  };
}
