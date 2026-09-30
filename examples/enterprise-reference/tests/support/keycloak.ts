// The browser a test stands in for: it opens the authorization URL PiShip
// printed, submits the Keycloak login form with the fixture user's password,
// and delivers the redirect (the authorization code) to PiShip's loopback
// listener. It only follows Keycloak's own login form; nothing here reads or
// prints a token, and the password goes only into that form.

export interface AuthorizationRequest {
  readonly clientId: string | null;
  readonly redirectUri: string;
  readonly codeChallengeMethod: string | null;
  readonly scope: string | null;
  readonly responseType: string | null;
  readonly hasState: boolean;
  readonly hasNonce: boolean;
}

/** The parameters PiShip put on the authorization URL, for assertions. */
export function authorizationRequest(url: string): AuthorizationRequest {
  const { searchParams } = new URL(url);
  return {
    clientId: searchParams.get("client_id"),
    redirectUri: searchParams.get("redirect_uri") ?? "",
    codeChallengeMethod: searchParams.get("code_challenge_method"),
    scope: searchParams.get("scope"),
    responseType: searchParams.get("response_type"),
    hasState: Boolean(searchParams.get("state")),
    hasNonce: Boolean(searchParams.get("nonce")),
  };
}

/**
 * Sign `username` in on the Keycloak page at `authorizeUrl` and follow the
 * redirect to the loopback callback. Rejects with a message that never
 * contains the password, the code, or a token.
 */
export async function signInAtKeycloak(
  authorizeUrl: string,
  username: string,
  password: string,
): Promise<void> {
  const location = await authorizeAtKeycloak(authorizeUrl, username, password);
  // PiShip's listener answers the first callback and then closes.
  const delivered = await fetch(location);
  if (!delivered.ok)
    throw new Error(`the loopback callback answered ${delivered.status}`);
}

/**
 * Sign `username` in on the Keycloak page at `authorizeUrl` and return the
 * callback URL Keycloak redirects to, without delivering it. A test that
 * plays a hostile browser changes it before it reaches PiShip. The same
 * guarantee as `signInAtKeycloak` holds for the messages of a rejection.
 */
export async function authorizeAtKeycloak(
  authorizeUrl: string | URL,
  username: string,
  password: string,
): Promise<string> {
  const cookies = new Map<string, string>();
  const keepCookies = (response: Response) => {
    for (const cookie of response.headers.getSetCookie()) {
      const [pair = ""] = cookie.split(";");
      const index = pair.indexOf("=");
      cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
  };
  const cookieHeader = () =>
    [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");

  const request = authorizationRequest(String(authorizeUrl));
  const page = await fetch(authorizeUrl, { redirect: "manual" });
  keepCookies(page);
  const html = await page.text();
  if (page.status !== 200)
    throw new Error(`the authorization page answered ${page.status}`);
  const form = /<form\b[^>]*\bid="kc-form-login"[^>]*>/.exec(html)?.[0];
  const action = form && /\baction="([^"]+)"/.exec(form)?.[1];
  if (!action) throw new Error("the authorization page has no login form");

  const submitted = await fetch(action.replaceAll("&amp;", "&"), {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie: cookieHeader(),
    },
    body: new URLSearchParams({ username, password, credentialId: "" }),
  });
  const location = submitted.headers.get("location");
  if (submitted.status !== 302 || !location)
    throw new Error(`the sign-in was not accepted (${submitted.status})`);
  const callback = new URL(location);
  if (`${callback.origin}${callback.pathname}` !== request.redirectUri)
    throw new Error("the sign-in redirected away from the loopback callback");
  if (!callback.searchParams.get("code"))
    throw new Error(
      `the sign-in returned no code (${callback.searchParams.get("error")})`,
    );

  return location;
}
