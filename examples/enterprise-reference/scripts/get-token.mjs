#!/usr/bin/env node
// Signs a reference user in to Keycloak through the same flow PiShip uses,
// Authorization Code with PKCE S256 on the public `acmecode` client, and
// writes the token response to stdout for a test to capture. The password
// form is submitted directly in place of a browser, and the redirect is read
// from the Location header, so nothing listens on the loopback port.
//
//   node scripts/get-token.mjs alice                # access token only
//   node scripts/get-token.mjs bob --response       # full token response JSON
//
// The output is a live credential for the local reference realm: capture it,
// do not print or log it. Reads `.env` beside compose.yaml; variables already
// set in the environment take precedence.
import { createHash, randomBytes, randomInt } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const user = args.find((arg) => !arg.startsWith("--"));
const fullResponse = args.includes("--response");

function fail(message) {
  process.stderr.write(`get-token: ${message}\n`);
  process.exit(1);
}

if (!user || !/^[a-z]+$/.test(user))
  fail("usage: get-token.mjs <alice|bob> [--response]");

function loadEnv(path) {
  const values = {};
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return values;
  }
  for (const line of text.split("\n")) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (match) values[match[1]] = match[2];
  }
  return values;
}

const env = { ...loadEnv(join(here, "..", ".env")), ...process.env };
const password = env[`REFERENCE_${user.toUpperCase()}_PASSWORD`];
if (!password) fail(`no password for ${user}; run scripts/generate-env.mjs`);

const base = `http://127.0.0.1:${env.KEYCLOAK_PORT ?? 18080}`;
const realm = `${base}/realms/piship-reference/protocol/openid-connect`;
const clientId = "acmecode";
// The client registers the port-less http://127.0.0.1/callback, which
// Keycloak matches for any loopback port (RFC 8252 section 7.3). A random
// port proves that.
const redirectUri = `http://127.0.0.1:${randomInt(49152, 65152)}/callback`;
const random = () => randomBytes(32).toString("base64url");
const verifier = random();
const challenge = createHash("sha256").update(verifier).digest("base64url");
const state = random();

const cookies = new Map();
function keepCookies(response) {
  for (const cookie of response.headers.getSetCookie()) {
    const [pair] = cookie.split(";");
    const index = pair.indexOf("=");
    cookies.set(pair.slice(0, index), pair.slice(index + 1));
  }
}
const cookieHeader = () =>
  [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");

const authorize = new URL(`${realm}/auth`);
authorize.search = new URLSearchParams({
  client_id: clientId,
  response_type: "code",
  scope: "openid profile email offline_access",
  redirect_uri: redirectUri,
  code_challenge: challenge,
  code_challenge_method: "S256",
  state,
  nonce: random(),
}).toString();

const page = await fetch(authorize, { redirect: "manual" });
keepCookies(page);
const html = await page.text();
if (page.status !== 200) fail(`authorization endpoint answered ${page.status}`);
const form = /<form\b[^>]*\bid="kc-form-login"[^>]*>/.exec(html)?.[0];
const action = form && /\baction="([^"]+)"/.exec(form)?.[1];
if (!action) fail("no login form in the authorization page");

const login = await fetch(action.replaceAll("&amp;", "&"), {
  method: "POST",
  redirect: "manual",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    cookie: cookieHeader(),
  },
  body: new URLSearchParams({ username: user, password, credentialId: "" }),
});
const location = login.headers.get("location");
if (login.status !== 302 || !location)
  fail(`sign-in was not accepted (status ${login.status})`);
const callback = new URL(location);
if (`${callback.origin}${callback.pathname}` !== redirectUri)
  fail("sign-in redirected somewhere other than the loopback callback");
if (callback.searchParams.get("state") !== state) fail("state mismatch");
const code = callback.searchParams.get("code");
if (!code)
  fail(`no authorization code (${callback.searchParams.get("error")})`);

const token = await fetch(`${realm}/token`, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  }),
});
const body = await token.json().catch(() => ({}));
if (!token.ok || typeof body.access_token !== "string")
  fail(`token endpoint answered ${token.status} ${body.error ?? ""}`.trim());

process.stdout.write(
  fullResponse ? `${JSON.stringify(body)}\n` : `${body.access_token}\n`,
);
