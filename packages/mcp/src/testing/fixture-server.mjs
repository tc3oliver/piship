#!/usr/bin/env node
// Stdio MCP fixture server (newline-delimited JSON-RPC).
//
// Flags:
//   --name <serverInfo.name>      --protocol <version to answer>
//   --record <file>               append each tools/call and cancellation as JSONL
//   --stderr <text>               write text to stderr at startup
//   --exit <code>                 exit right after startup (after --stderr)
//   --fail-first <file>:<n>       exit 1 on the first n starts (counter file)
//   --hang-initialize             never answer initialize
import {
  appendFileSync,
  existsSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { createInterface } from "node:readline";
import { createFixture } from "./fixture-core.mjs";

const args = process.argv.slice(2);
const flag = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const recordFile = flag("--record");
if (recordFile)
  appendFileSync(
    recordFile,
    `${JSON.stringify({ type: "start", pid: process.pid })}\n`,
  );
const stderrText = flag("--stderr");
if (stderrText) process.stderr.write(`${stderrText}\n`);
const failFirst = flag("--fail-first");
if (failFirst) {
  // Split at the last colon: a Windows path has a drive-letter colon.
  const cut = failFirst.lastIndexOf(":");
  const file = failFirst.slice(0, cut);
  const limit = failFirst.slice(cut + 1);
  const count = existsSync(file) ? Number(readFileSync(file, "utf8")) + 1 : 1;
  writeFileSync(file, String(count));
  if (count <= Number(limit)) process.exit(1);
}
const exitCode = flag("--exit");
if (exitCode !== undefined) {
  process.stderr.write("", () => process.exit(Number(exitCode)));
} else {
  const hang = args.includes("--hang-initialize");
  const fixture = createFixture({
    serverName: flag("--name"),
    protocolVersion: flag("--protocol"),
    envNames: () => Object.keys(process.env).sort(),
    record: recordFile
      ? (entry) => appendFileSync(recordFile, `${JSON.stringify(entry)}\n`)
      : undefined,
  });
  const lines = createInterface({ input: process.stdin });
  lines.on("line", async (line) => {
    if (line.trim() === "") return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      process.stdout.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } })}\n`,
      );
      return;
    }
    if (hang && message.method === "initialize") return;
    const response = await fixture.handle(message);
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  });
  lines.on("close", () => process.exit(0));
}
