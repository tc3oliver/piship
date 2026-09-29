// Example credential adapter (`credential.provider: adapter`): exchanges the
// signed-in identity for a runtime credential at a company service. An
// adapter is one file that imports nothing but @piship/adapter-sdk and Node
// built-ins.
import {
  defineCredentialAdapter,
  PiShipError,
  parseRetryAfter,
  SecretValue,
  withTimeout,
} from "@piship/adapter-sdk";

// Replace with your credential service. Under a private-only network policy,
// declare its host in `network.allowHosts` so the managed fetch may reach it.
const SERVICE = "https://credentials.example.com";
const TIMEOUT_MS = 30_000;

export default defineCredentialAdapter((context) => {
  // `token` authenticates the call: the identity's access token to acquire,
  // the credential itself to revoke it. `key` is the caller's idempotency
  // key: the service returns the credential it already issued for a key it
  // has seen, so a caller may retry a timed-out acquire with it.
  async function call(method, path, token, signal, key) {
    // The key is not secret: every failure reports it, so the caller can
    // retry with the same key.
    const detail = key === undefined ? {} : { idempotencyKey: key };
    const failed = (message, retryable, extra = {}) =>
      new PiShipError(
        method === "DELETE"
          ? "CREDENTIAL_REVOKED"
          : "CREDENTIAL_ACQUIRE_FAILED",
        message,
        {
          retryable,
          component: "credential",
          sanitizedDetail: detail,
          ...extra,
        },
      );
    let response;
    try {
      response = await context.fetch(new URL(path, SERVICE), {
        method,
        headers: {
          ...(token ? { authorization: `Bearer ${token.reveal()}` } : {}),
          ...(key === undefined ? {} : { "idempotency-key": key }),
        },
        signal: withTimeout(TIMEOUT_MS, signal),
      });
    } catch (error) {
      // Network and TLS policy refusals keep their own code. Never build a
      // message from a transport error: it can quote the Authorization header.
      if (error instanceof PiShipError) throw error;
      // The caller's cancellation is final; a timeout or outage may be retried.
      if (signal?.aborted) throw failed("The request was cancelled", false);
      throw failed("The credential service is unreachable", true);
    }
    const retryAfterMs = parseRetryAfter(response.headers.get("retry-after"));
    if (response.status === 401)
      throw new PiShipError(
        "IDENTITY_EXPIRED",
        "The credential service no longer accepts the sign-in",
        { component: "credential", userAction: "Run login again" },
      );
    if (response.status === 403)
      throw new PiShipError(
        "CREDENTIAL_DENIED",
        "The credential service denied a credential for this user",
        { component: "credential" },
      );
    if (response.status === 429 || response.status >= 500)
      throw failed(
        `The credential service answered HTTP ${response.status}`,
        true,
        { retryAfterMs },
      );
    if (!response.ok)
      throw failed(
        `The credential service answered HTTP ${response.status}`,
        false,
      );
    if (method === "DELETE") return undefined;
    // A body that is not JSON must not escape as a SyntaxError: its message
    // can quote the body.
    let answer;
    try {
      answer = await response.json();
    } catch (error) {
      if (signal?.aborted) throw failed("The request was cancelled", false);
      if (error instanceof SyntaxError)
        throw failed("The credential service answer is not JSON", false);
      // The body did not arrive in time or the connection dropped.
      throw failed("The credential service answer did not arrive", true);
    }
    const expiresAt = new Date(answer?.expiresAt);
    if (
      typeof answer?.key !== "string" ||
      typeof answer.id !== "string" ||
      Number.isNaN(expiresAt.getTime())
    )
      throw failed("The credential service answer is malformed", false);
    // Never hand PiShip a credential that has already expired.
    if (expiresAt <= new Date())
      throw new PiShipError(
        "CREDENTIAL_EXPIRED",
        "The credential service issued a credential that has already expired",
        { component: "credential", sanitizedDetail: detail },
      );
    return { key: answer.key, id: answer.id, expiresAt };
  }

  return {
    mode: "adapter",
    requiresIdentity: true,
    async acquire(identity, ctx) {
      const answer = await call(
        "POST",
        "/credentials",
        identity?.accessToken,
        ctx.signal,
        ctx.idempotencyKey,
      );
      return {
        kind: "api_key",
        secret: new SecretValue(answer.key),
        credentialId: answer.id,
        expiresAt: answer.expiresAt,
      };
    },
    async revoke(credential, ctx) {
      if (credential.credentialId)
        await call(
          "DELETE",
          `/credentials/${encodeURIComponent(credential.credentialId)}`,
          credential.secret,
          ctx.signal,
        );
    },
  };
});
