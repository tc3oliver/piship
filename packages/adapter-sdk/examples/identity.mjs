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
  const failure = (code, message, extra = {}) =>
    new PiShipError(code, message, { component: "identity", ...extra });

  async function call(path, body, signal) {
    const deadline = withTimeout(TIMEOUT_MS, signal);
    // Reading a body can fail as the request can; `what` names the step.
    const unreachable = (what) =>
      failure(
        "GATEWAY_UNREACHABLE",
        signal?.aborted
          ? "Sign-in was cancelled"
          : `The sign-in service ${what}`,
        { retryable: !signal?.aborted },
      );
    let response;
    try {
      response = await context.fetch(new URL(path, SERVICE), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: deadline,
      });
    } catch (error) {
      // Network and TLS policy refusals keep their own code. Never build a
      // message from a transport error: it can quote a header value.
      if (error instanceof PiShipError) throw error;
      throw unreachable("is unreachable");
    }
    if (response.status === 429 || response.status >= 500)
      throw failure(
        response.status === 429
          ? "GATEWAY_RATE_LIMITED"
          : "GATEWAY_UNREACHABLE",
        `The sign-in service answered HTTP ${response.status}`,
        {
          retryable: true,
          retryAfterMs: parseRetryAfter(response.headers.get("retry-after")),
        },
      );
    // A 204 (a revocation, for example) has no body to read.
    if (response.status === 204) return undefined;
    // Read the body once; a body that is not JSON must not escape as a
    // SyntaxError, whose message can quote it.
    let answer;
    try {
      answer = await response.json();
    } catch (error) {
      if (!(error instanceof SyntaxError))
        throw unreachable("answer did not arrive");
      answer = undefined;
    }
    if (!response.ok) {
      // 401, or an OAuth `invalid_grant`: the session or the grant has
      // expired or was revoked, so the person signs in again.
      const expired =
        response.status === 401 || answer?.error === "invalid_grant";
      throw failure(
        expired ? "IDENTITY_EXPIRED" : "IDENTITY_INVALID",
        `The sign-in service refused the request (HTTP ${response.status})`,
        { userAction: "Run login again" },
      );
    }
    if (!answer || typeof answer !== "object")
      throw failure(
        "IDENTITY_INVALID",
        "The sign-in service answered with a malformed body",
      );
    return answer;
  }

  // Wrap every token at once: a SecretValue redacts itself everywhere. The
  // principal is the subject and the issuer the service asserts.
  function session(answer) {
    if (
      typeof answer.subject !== "string" ||
      !answer.subject ||
      typeof answer.issuer !== "string" ||
      !answer.issuer ||
      typeof answer.accessToken !== "string" ||
      !Number.isFinite(answer.expiresIn)
    )
      throw failure(
        "IDENTITY_INVALID",
        "The sign-in service answered without a complete session",
      );
    return {
      subject: answer.subject,
      issuer: answer.issuer,
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
        throw failure("IDENTITY_EXPIRED", "The session has ended", {
          userAction: "Run login again",
        });
      return session(
        await call("/refresh", {
          refreshToken: current.refreshToken.reveal(),
        }),
      );
    },
    async logout(current) {
      if (!current.refreshToken) return;
      try {
        await call("/revoke", { refreshToken: current.refreshToken.reveal() });
      } catch (error) {
        // A session the service already revoked or no longer knows is
        // logged out.
        if (error?.code !== "IDENTITY_EXPIRED") throw error;
      }
    },
  };
});
