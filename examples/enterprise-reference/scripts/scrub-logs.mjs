#!/usr/bin/env node
// Filters container logs (stdin to stdout) so they can be kept as CI
// evidence. Replaced: every value of 8 characters or more in the stack's env
// file (except the ports) and in the named environment variables, by its
// name; anything shaped like a LiteLLM key (`sk-...`), a JWT, or an
// `Authorization: Bearer` or `Basic` value; and the value of an OAuth `code`,
// `state`, or `session_state` parameter. Other secret shapes pass through, so
// this is a filter for the reference stack's own logs, not a general one. The
// generated secrets are all 36 characters or longer.
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
    .replace(
      /(?<![\w-])(code|state|session_state)=[\w.~%-]+/g,
      "$1=<redacted>",
    );
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
process.stdout.write(scrub(Buffer.concat(chunks).toString("utf8")));
