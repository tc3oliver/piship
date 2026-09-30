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
  assert.equal(
    scrub("GET /x?errorcode=5&xstate=1\n"),
    "GET /x?errorcode=5&xstate=1\n",
  );
});

test("replaces them anywhere in a query string, and in a fragment", () => {
  assert.equal(
    scrub("GET /cb?a=1&code=fake-code-0000&b=2 HTTP/1.1\n"),
    "GET /cb?a=1&code=<redacted>&b=2 HTTP/1.1\n",
  );
  assert.equal(
    scrub(
      "redirected to http://127.0.0.1/cb#state=fake-state-0000&code=fake-code-0000\n",
    ),
    "redirected to http://127.0.0.1/cb#state=<redacted>&code=<redacted>\n",
  );
});

test("keeps the same words in ordinary log text, where they are not URL parameters", () => {
  for (const line of [
    "container exit code=137\n",
    "level=info state=running code=1 session_state=ok\n",
    "process exited: code=0 state=stopped\n",
    "what state=unknown? code=2\n",
  ])
    assert.equal(scrub(line), line);
  // Inside a URL they are parameters, whatever the value.
  assert.equal(
    scrub("GET /cb?state=running HTTP/1.1\n"),
    "GET /cb?state=<redacted> HTTP/1.1\n",
  );
});

test("replaces them in a URL that is percent-encoded inside another one", () => {
  assert.equal(
    scrub(
      "redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb%3Fstate%3Dfake-state-0000%26session_state%3D0000-fake%26code%3D0000.fake-code.0000&scope=openid\n",
    ),
    "redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb%3Fstate%3D<redacted>%26session_state%3D<redacted>%26code%3D<redacted>&scope=openid\n",
  );
  // Lower-case hex, and an encoded `=` after a plain separator.
  assert.equal(
    scrub("next=%2Fcb%3fcode%3daaaa-bbbb%26x%3D1 and /cb?code%3Dcccc-dddd\n"),
    "next=%2Fcb%3fcode%3d<redacted>%26x%3D1 and /cb?code%3D<redacted>\n",
  );
  // Only whole parameter names, encoded too.
  assert.equal(
    scrub("next=%2Fcb%3Ferrorcode%3D5%26xstate%3D1\n"),
    "next=%2Fcb%3Ferrorcode%3D5%26xstate%3D1\n",
  );
});

test("replaces a value whole, `/` and `+` included, up to the parameter's end", () => {
  // A code from an identity provider that holds `/` and `+`, logged decoded.
  assert.equal(
    scrub("GET /cb?code=4/0AbFake+code/tail.0000&scope=openid HTTP/1.1\n"),
    "GET /cb?code=<redacted>&scope=openid HTTP/1.1\n",
  );
  assert.equal(
    scrub('{"url":"http://127.0.0.1/cb?state=fake/state+0000","n":1}\n'),
    '{"url":"http://127.0.0.1/cb?state=<redacted>","n":1}\n',
  );
  assert.equal(
    scrub("redirect to http://127.0.0.1/cb#code=a/b+c' and done\n"),
    "redirect to http://127.0.0.1/cb#code=<redacted>' and done\n",
  );
  // Encoded inside another URL, the value ends at the encoded `&`.
  assert.equal(
    scrub(
      "next=%2Fcb%3Fcode%3D4%2F0AbFake%2Bcode%26state%3Dfake-state-0000 x\n",
    ),
    "next=%2Fcb%3Fcode%3D<redacted>%26state%3D<redacted> x\n",
  );
});

test("recognizes an encoded fragment, a twice-encoded URL, and an HTML-escaped ampersand", () => {
  assert.equal(
    scrub("next=%2Fcb%23state%3Dfake-state-0000%26code%3Dfake-code-0000\n"),
    "next=%2Fcb%23state%3D<redacted>%26code%3D<redacted>\n",
  );
  // A URL encoded twice: `?` is %253F, `&` is %2526, `=` is %253D.
  assert.equal(
    scrub(
      "u=http%253A%252F%252Fx%252Fcb%253Fcode%253Dfake-code-0000%2526session_state%253D0000-fake&n=1\n",
    ),
    "u=http%253A%252F%252Fx%252Fcb%253Fcode%253D<redacted>%2526session_state%253D<redacted>&n=1\n",
  );
  // A URL in HTML, where `&` is written `&amp;`.
  assert.equal(
    scrub(
      '<a href="/cb?a=1&amp;code=fake-code-0000&amp;state=fake-state-0000">\n',
    ),
    '<a href="/cb?a=1&amp;code=<redacted>&amp;state=<redacted>">\n',
  );
  // Still only whole parameter names.
  for (const line of [
    "next=%2Fcb%23errorcode%3D5\n",
    "u=x%253Fxstate%253D1\n",
    '<a href="/cb?a=1&amp;errorcode=5&amp;xstate=1">\n',
    "a &amp; code=5 and 100%25 state=running\n",
  ])
    assert.equal(scrub(line), line);
});

test("keeps scanning a long line fast", () => {
  // Nothing in the patterns backtracks over a long run.
  const line = `${"%25".repeat(50_000)}code=${"a/".repeat(50_000)}\n`;
  const started = Date.now();
  scrub(line);
  scrub(`${"?code=".repeat(20_000)}\n`);
  assert.ok(Date.now() - started < 4000);
});

test("replaces token-shaped values of code, state, and session_state members of JSON", () => {
  assert.equal(
    scrub(
      '{"code":"0000.fake-code.0000-0000","state": "fake-state-0000-0000","session_state" :"0000-fake-0000-0000"}\n',
    ),
    '{"code":"<redacted>","state": "<redacted>","session_state" :"<redacted>"}\n',
  );
  // JSON that is itself a quoted string of a log line.
  assert.equal(
    scrub('{"msg":"{\\"code\\":\\"0000.fake-code.0000-0000\\",\\"n\\":1}"}\n'),
    '{"msg":"{\\"code\\":\\"<redacted>\\",\\"n\\":1}"}\n',
  );
});

test("keeps statuses and numbers in JSON members of the same names", () => {
  for (const line of [
    '{"state":"running","code":"401","session_state":"ok"}\n',
    '{"code":137,"state":null,"state_reason":"0000-fake-0000-0000-0000"}\n',
    '{"errorcode":"0000.fake-code.0000-0000","xstate":"fake-state-0000-0000"}\n',
    '{"code":"not a token, though it is longer than sixteen"}\n',
  ])
    assert.equal(scrub(line), line);
});
