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
  // the credential itself to revoke it.
  async function call(method, path, token, signal) {
    const failed = (message, retryable, extra = {}) =>
      new PiShipError(
        method === "DELETE"
          ? "CREDENTIAL_REVOKED"
          : "CREDENTIAL_ACQUIRE_FAILED",
        message,
        { retryable, component: "credential", ...extra },
      );
    let response;
    try {
      response = await context.fetch(new URL(path, SERVICE), {
        method,
        headers: token ? { authorization: `Bearer ${token.reveal()}` } : {},
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
    return method === "DELETE" ? undefined : response.json();
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
      );
      return {
        kind: "api_key",
        secret: new SecretValue(answer.key),
        credentialId: answer.id,
        expiresAt: new Date(answer.expiresAt),
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
