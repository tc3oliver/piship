// Sign-in attacks a hostile or careless browser can mount against PiShip's
// OIDC client without touching the identity provider: it sits between the
// authorization request PiShip prints and the callback it delivers back. Each
// attack changes one thing on that path; the identity provider itself stays
// honest, so a rejection is PiShip's own check, not the provider's.
//
// The same attacks run against the local fixture provider and, in
// tests/enterprise-reference, against a live Keycloak.

/** Follows the authorization request through the provider; returns the callback URL it redirects to. */
export type Follow = (authorizationUrl: URL) => Promise<URL>;

export interface Attack {
  readonly name: string;
  /** Changes the authorization request before the provider sees it. */
  readonly authorize?: (parameters: URLSearchParams) => void;
  /** Changes the callback before it is delivered to PiShip's loopback listener. */
  readonly callback?: (parameters: URLSearchParams) => void;
  readonly code: "IDENTITY_INVALID";
  /** What the rejection names, so it fails for the reason the attack aims at. */
  readonly message: RegExp;
}

export const ATTACKS: readonly Attack[] = [
  {
    name: "a callback whose state is not the one PiShip sent",
    callback: (parameters) => parameters.set("state", "attacker-state"),
    code: "IDENTITY_INVALID",
    message: /state/,
  },
  {
    name: "a callback with no state",
    callback: (parameters) => parameters.delete("state"),
    code: "IDENTITY_INVALID",
    message: /state/,
  },
  {
    name: "an authorization request whose nonce is not the one PiShip sent",
    authorize: (parameters) => parameters.set("nonce", "attacker-nonce"),
    code: "IDENTITY_INVALID",
    message: /nonce/,
  },
  {
    name: "an authorization request with no nonce, so the ID token carries none",
    authorize: (parameters) => parameters.delete("nonce"),
    code: "IDENTITY_INVALID",
    message: /nonce/,
  },
  {
    name: "a callback naming another issuer (mix-up)",
    callback: (parameters) => parameters.set("iss", "https://evil.example/idp"),
    code: "IDENTITY_INVALID",
    // The parameter or the word, never a substring of another word.
    message: /\biss\b|issuer/,
  },
];

export interface HostileBrowser {
  /** The `openUrl` a login takes. */
  readonly openUrl: (url: string) => void;
  /**
   * Waits for the browser to finish, the delivery of the callback included,
   * and returns what went wrong in it, if anything. A caller awaits this
   * before it trusts a rejection, so a broken harness is never read as one.
   */
  readonly finished: () => Promise<Error | undefined>;
}

/** A browser that applies `attack` (or none) and delivers the callback. */
export function browser(follow: Follow, attack?: Attack): HostileBrowser {
  let failure: Error | undefined;
  let running: Promise<void> = Promise.resolve();
  return {
    openUrl(url) {
      running = (async () => {
        const authorization = new URL(url);
        attack?.authorize?.(authorization.searchParams);
        const callback = await follow(authorization);
        attack?.callback?.(callback.searchParams);
        // PiShip's listener answers the first request it gets.
        await fetch(callback);
      })().catch((error: unknown) => {
        failure = error as Error;
      });
    },
    finished: async () => {
      await running;
      return failure;
    },
  };
}

/** Follows the local fixture provider, which redirects straight to the callback. */
export const followFixture: Follow = async (authorizationUrl) => {
  const answer = await fetch(authorizationUrl, { redirect: "manual" });
  const location = answer.headers.get("location");
  if (!location)
    throw new Error(`the authorization request failed (HTTP ${answer.status})`);
  return new URL(location);
};
