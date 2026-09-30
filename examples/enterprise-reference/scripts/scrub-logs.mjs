#!/usr/bin/env node
// Filters container logs (stdin to stdout) so they can be kept as CI
// evidence. Replaced: every value of 8 characters or more in the stack's env
// file (except the ports) and in the named environment variables, by its
// name; anything shaped like a LiteLLM key (`sk-...`), a JWT, or an
// `Authorization: Bearer` or `Basic` value; and the value of an OAuth `code`,
// `state`, or `session_state` where it is a parameter of a URL (after `?`,
// `&`, `#`, or `&amp;`, also with the URL percent-encoded once or twice inside
// another one: `%3Fcode%3D...`, `%253Fcode%253D...`, and the whole value, `/`
// and `+` included) or a token-shaped string of a JSON object (`"code":"..."`,
// 16 characters or more, also when the JSON is itself a quoted string).
// Words in ordinary log text (`exit code=137`, `state=running`) and short
// JSON values (`"state":"running"`, `"code":"401"`) are kept; a form-encoded
// body logged without a URL (`code=...&state=...`) is not recognized. Other secret
// shapes pass through, so this is a filter for the reference stack's own logs,
// not a general one. The generated secrets are all 36 characters or longer.
//
//   docker compose -p <project> --env-file <path> logs --no-color \
//     | node scripts/scrub-logs.mjs --env-file <path> [--redact-env NAME ...]
import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const secrets = [];
for (let index = 0; index < args.length; index += 1) {
  const value = args[index + 1];
  if (args[index] === "--env-file" && value) {
    for (const line of readFileSync(value, "utf8").split("\n")) {
      const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
      if (match && !match[1].endsWith("_PORT"))
        secrets.push([match[1], match[2]]);
    }
    index += 1;
  } else if (args[index] === "--redact-env" && value) {
    secrets.push([value, process.env[value] ?? ""]);
    index += 1;
  } else {
    process.stderr.write(`unknown argument: ${args[index]}\n`);
    process.exit(2);
  }
}

// Longest first, so a value that contains another is replaced whole.
const values = secrets
  .filter(([, value]) => value.length >= 8)
  .sort(([, a], [, b]) => b.length - a.length);

// An OAuth parameter of a URL: `code`, `state`, or `session_state` straight
// after `?`, `&`, `#`, or `&amp;` (a URL in HTML), or after their percent-
// encoded forms (`%3F`, `%26`, `%23`) when the URL is a parameter of another
// one, once or twice encoded (`%253F`), with `=` or `%3D`. The value is
// everything up to white space, a quote, `<`, `>`, `&`, or an encoded `&`:
// a code from an identity provider can hold `/` and `+` (`4/0Ab...`). The
// same words in log text, with no URL separator before them, are not
// parameters. Every part is bounded, so the scan stays linear.
const encoded = (hex) => `%(?:25){0,2}${hex}`;
const OAUTH_URL_PARAMETER = new RegExp(
  `(?<=[?&#]|&amp;|${encoded("3[Ff]")}|${encoded("26")}|${encoded("23")})` +
    `(code|state|session_state)(=|${encoded("3[Dd]")})` +
    `(?:(?!${encoded("26")})[^\\s&"'<>])+`,
  "g",
);

// A member of a JSON object whose name is one of those and whose value is a
// string shaped like a token: 16 or more characters that a code, a state, or
// a session ID is made of. Also matches when the JSON is escaped inside a
// string (`\"code\":\"...\"`). A shorter value is a status, not a secret.
const OAUTH_JSON_MEMBER =
  /(\\?")(code|state|session_state)\1(\s*:\s*)\1[\w.~%+/=-]{16,}\1/g;

function scrub(text) {
  let out = text;
  for (const [name, value] of values)
    out = out.split(value).join(`<redacted:${name}>`);
  return out
    .replace(/sk-[A-Za-z0-9_-]{4,}/g, "sk-<redacted>")
    .replace(
      /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g,
      "<redacted-jwt>",
    )
    .replace(/(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 <redacted>")
    .replace(OAUTH_URL_PARAMETER, "$1$2<redacted>")
    .replace(OAUTH_JSON_MEMBER, "$1$2$1$3$1<redacted>$1");
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
process.stdout.write(scrub(Buffer.concat(chunks).toString("utf8")));
