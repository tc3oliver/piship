// node --test scripts/test/*.test.mjs (from examples/enterprise-reference):
// what scrub-logs.mjs replaces in container logs, and what it keeps.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scrub-logs.mjs", import.meta.url));

// Obvious fakes, shaped like the generated values.
const MASTER = "sk-fake0000000000000000000000000000000000";
const PASSWORD = "fake-password-0000000000000000000000";
const PROVIDER = "fake-provider-setting-0000";

function scrub(input, { env = {}, redact = [] } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "scrub-logs-test-"));
  try {
    const envFile = join(directory, ".env");
    writeFileSync(
      envFile,
      [
        "LITELLM_PORT=14000",
        `LITELLM_MASTER_KEY=${MASTER}`,
        `POSTGRES_PASSWORD=${PASSWORD}`,
        "SHORT_VALUE=abc1234",
        "",
      ].join("\n"),
    );
    const result = spawnSync(
      process.execPath,
      [
        script,
        "--env-file",
        envFile,
        ...redact.flatMap((name) => ["--redact-env", name]),
      ],
      { input, encoding: "utf8", env: { ...process.env, ...env } },
    );
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("replaces env file values by name and keeps the ports", () => {
  const out = scrub(
    `listening on 14000 key=${MASTER} db=postgresql://litellm:${PASSWORD}@postgres\n`,
  );
  assert.equal(
    out,
    "listening on 14000 key=<redacted:LITELLM_MASTER_KEY> db=postgresql://litellm:<redacted:POSTGRES_PASSWORD>@postgres\n",
  );
});

test("does not replace values shorter than 8 characters", () => {
  assert.equal(scrub("value abc1234\n"), "value abc1234\n");
});

test("replaces the named environment variables", () => {
  const out = scrub(`upstream ${PROVIDER} answered\n`, {
    env: { LIVE_PROVIDER_FAKE: PROVIDER },
    redact: ["LIVE_PROVIDER_FAKE"],
  });
  assert.equal(out, "upstream <redacted:LIVE_PROVIDER_FAKE> answered\n");
});

test("replaces key, JWT, and authorization shapes", () => {
  const out = scrub(
    "a sk-other1234 b eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl c Bearer abcdefgh1234 d Basic dXNlcjpwYXNz\n",
  );
  assert.equal(
    out,
    "a sk-<redacted> b <redacted-jwt> c Bearer <redacted> d Basic <redacted>\n",
  );
});

test("replaces OAuth code, state, and session_state values", () => {
  const out = scrub(
    "GET /callback?state=fakestate-0000&session_state=0000-fake&code=0000.fake-code.0000 HTTP/1.1\n",
  );
  assert.equal(
    out,
    "GET /callback?state=<redacted>&session_state=<redacted>&code=<redacted> HTTP/1.1\n",
  );
  // Only whole parameter names.
  assert.equal(scrub("errorcode=5 xstate=1\n"), "errorcode=5 xstate=1\n");
});
