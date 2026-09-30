#!/usr/bin/env node
// Happy path of the broker against the running reference stack: real
// Keycloak sign-in, real LiteLLM keys. Prints each step's status and time,
// never a token or a key. Exits non-zero on the first failed expectation.
//
//   node broker/live-check.mjs                   # reads ../.env
//   node broker/live-check.mjs --env-file <path>
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const envIndex = args.indexOf("--env-file");
const envFile =
  envIndex >= 0 ? resolve(args[envIndex + 1]) : join(here, "..", ".env");
const fileEnv = Object.fromEntries(
  readFileSync(envFile, "utf8")
    .split("\n")
    .map((line) => /^([A-Z0-9_]+)=(.*)$/.exec(line.trim()))
    .filter(Boolean)
    .map((match) => [match[1], match[2]]),
);
const env = { ...fileEnv, ...process.env };
const broker = `http://127.0.0.1:${env.BROKER_PORT ?? 18070}`;
const gateway = `http://127.0.0.1:${env.LITELLM_PORT ?? 14000}`;

const rows = [];
function check(condition, step, detail) {
  if (!condition) {
    console.table(rows);
    console.error(`FAILED: ${step}${detail ? ` (${detail})` : ""}`);
    process.exit(1);
  }
}
async function timed(step, fn) {
  const started = performance.now();
  const result = await fn();
  rows.push({
    step,
    status: result?.status ?? "",
    ms: Math.round(performance.now() - started),
  });
  return result;
}

function token(user) {
  // get-token.mjs prints the access token; it is captured, never shown.
  const result = spawnSync(
    process.execPath,
    [join(here, "..", "scripts", "get-token.mjs"), user],
    {
      env,
      encoding: "utf8",
    },
  );
  check(result.status === 0, `sign in as ${user}`, result.stderr.trim());
  return { status: 200, value: result.stdout.trim() };
}

async function acquire(accessToken, key) {
  const response = await fetch(`${broker}/v1/credential`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
      ...(key ? { "idempotency-key": key } : {}),
    },
    body: JSON.stringify({
      distribution: "acmecode-reference",
      purpose: "inference",
    }),
  });
  return { status: response.status, body: await response.json() };
}
async function revoke(credential, credentialId) {
  const response = await fetch(`${broker}/v1/revoke`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${credential}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      credential_id: credentialId,
      distribution: "acmecode-reference",
    }),
  });
  await response.body?.cancel();
  return { status: response.status };
}
async function models(credential) {
  const response = await fetch(`${gateway}/v1/models`, {
    headers: { authorization: `Bearer ${credential}` },
  });
  const body = await response.json().catch(() => ({}));
  return {
    status: response.status,
    ids: (body.data ?? []).map((model) => model.id).sort(),
  };
}
async function chat(credential, model) {
  const response = await fetch(`${gateway}/v1/chat/completions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${credential}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: "hello from the broker live check" }],
    }),
  });
  await response.body?.cancel();
  return { status: response.status };
}

const alice = (
  await timed("sign in alice (Keycloak, PKCE)", () => token("alice"))
).value;
const bob = (await timed("sign in bob (Keycloak, PKCE)", () => token("bob")))
  .value;

const key = randomUUID();
const a = await timed("acquire alice", () => acquire(alice, key));
check(a.status === 200, "acquire alice", a.status);
check(
  JSON.stringify(a.body.models) === '["acme/coder","acme/general"]',
  "alice models",
);
check(
  /^[A-Za-z0-9._:-]{1,256}$/.test(a.body.credential_id),
  "credential_id alphabet",
);
check(a.body.base_url === `${gateway}/v1`, "base_url");
check(Date.parse(a.body.expires_at) > Date.now(), "expires_at");
const aliceSub = JSON.parse(Buffer.from(alice.split(".")[1], "base64url")).sub;
check(a.body.subject === aliceSub, "subject echo");

const replay = await timed("acquire alice again, same Idempotency-Key", () =>
  acquire(alice, key),
);
check(
  replay.status === 200 && replay.body.credential_id === a.body.credential_id,
  "idempotent replay",
);

const am = await timed("alice key: GET /v1/models", () =>
  models(a.body.credential),
);
check(
  am.status === 200 &&
    JSON.stringify(am.ids) === '["acme/coder","acme/general"]',
  "alice model list",
  am.ids,
);
check(
  (
    await timed("alice key: chat acme/general", () =>
      chat(a.body.credential, "acme/general"),
    )
  ).status === 200,
  "alice general",
);

const b = await timed("acquire bob", () => acquire(bob));
check(
  b.status === 200 && JSON.stringify(b.body.models) === '["acme/coder"]',
  "bob models",
);
const bm = await timed("bob key: GET /v1/models", () =>
  models(b.body.credential),
);
check(
  bm.status === 200 && JSON.stringify(bm.ids) === '["acme/coder"]',
  "bob model list",
  bm.ids,
);
check(
  (
    await timed("bob key: chat acme/coder", () =>
      chat(b.body.credential, "acme/coder"),
    )
  ).status === 200,
  "bob coder",
);
check(
  (
    await timed("bob key: chat acme/general (refused)", () =>
      chat(b.body.credential, "acme/general"),
    )
  ).status === 403,
  "bob general refused",
);

const forged = `${alice.slice(0, -4)}AAAA`;
check(
  (
    await timed("acquire with a forged signature (refused)", () =>
      acquire(forged),
    )
  ).status === 401,
  "forged token",
);

check(
  (
    await timed("revoke alice key", () =>
      revoke(a.body.credential, a.body.credential_id),
    )
  ).status === 200,
  "revoke",
);
check(
  (
    await timed("deleted key: GET /v1/models (refused)", () =>
      models(a.body.credential),
    )
  ).status === 401,
  "deleted key rejected",
);
check(
  (
    await timed("deleted key: chat (refused)", () =>
      chat(a.body.credential, "acme/coder"),
    )
  ).status === 401,
  "deleted key chat rejected",
);
check(
  (
    await timed("revoke alice key again", () =>
      revoke(a.body.credential, a.body.credential_id),
    )
  ).status === 404,
  "second revoke",
);
check(
  (
    await timed("revoke bob key", () =>
      revoke(b.body.credential, b.body.credential_id),
    )
  ).status === 200,
  "revoke bob",
);

console.table(rows);
console.log("live check passed");
