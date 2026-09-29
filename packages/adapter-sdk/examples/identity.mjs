// Example identity adapter (`identity.mode: adapter`) for a company sign-in
// service. An adapter is one file: PiShip packages only the file the
// manifest names, and bare imports resolve only from the payload's
// node_modules, so it imports nothing but @piship/adapter-sdk and Node
// built-ins.
import {
  defineIdentityAdapter,
  PiShipError,
  parseRetryAfter,
  SecretValue,
  withTimeout,
} from "@piship/adapter-sdk";

// Replace with your sign-in service. Under a private-only network policy,
// declare its host in `network.allowHosts` so the managed fetch may reach it.
const SERVICE = "https://sign-in.example.com";
const TIMEOUT_MS = 30_000;

export default defineIdentityAdapter((context) => {
  async function call(path, body, signal) {
    let response;
    try {
      response = await context.fetch(new URL(path, SERVICE), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: withTimeout(TIMEOUT_MS, signal),
      });
    } catch (error) {
      // Network and TLS policy refusals keep their own code. Never build a
      // message from a transport error: it can quote a header value.
      if (error instanceof PiShipError) throw error;
      throw new PiShipError(
        "GATEWAY_UNREACHABLE",
        signal?.aborted
          ? "Sign-in was cancelled"
          : "The sign-in service is unreachable",
        { retryable: !signal?.aborted, component: "identity" },
      );
    }
    if (response.status === 429 || response.status >= 500)
      throw new PiShipError(
        response.status === 429
          ? "GATEWAY_RATE_LIMITED"
          : "GATEWAY_UNREACHABLE",
        `The sign-in service answered HTTP ${response.status}`,
        {
          retryable: true,
          retryAfterMs: parseRetryAfter(response.headers.get("retry-after")),
          component: "identity",
        },
      );
    if (!response.ok)
      throw new PiShipError(
        response.status === 401 ? "IDENTITY_EXPIRED" : "IDENTITY_INVALID",
        `The sign-in service refused the request (HTTP ${response.status})`,
        { component: "identity", userAction: "Run login again" },
      );
    return response.json();
  }

  // Wrap every token at once: a SecretValue redacts itself everywhere.
  function session(answer) {
    return {
      subject: answer.subject,
      issuer: SERVICE,
      ...(answer.name ? { displayName: answer.name } : {}),
      accessToken: new SecretValue(answer.accessToken),
      ...(answer.refreshToken
        ? { refreshToken: new SecretValue(answer.refreshToken) }
        : {}),
      expiresAt: new Date(Date.now() + answer.expiresIn * 1000),
    };
  }

  return {
    kind: "example-sign-in",
    async login(ctx) {
      const started = await call("/device", {}, ctx.signal);
      await ctx.openUrl(started.verificationUrl);
      // The service answers once the person has signed in in the browser.
      return session(
        await call("/token", { deviceCode: started.deviceCode }, ctx.signal),
      );
    },
    async refresh(current) {
      if (!current.refreshToken)
        throw new PiShipError("IDENTITY_EXPIRED", "The session has ended", {
          component: "identity",
          userAction: "Run login again",
        });
      return session(
        await call("/refresh", {
          refreshToken: current.refreshToken.reveal(),
        }),
      );
    },
    async logout(current) {
      if (current.refreshToken)
        await call("/revoke", { refreshToken: current.refreshToken.reveal() });
    },
  };
});
