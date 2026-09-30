// node --test mock-upstream/test/*.test.mjs (from examples/enterprise-reference):
// the mock upstream's queued tool calls. It needs no Docker: each test runs
// the server on a free loopback port.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const server = fileURLToPath(new URL("../server.mjs", import.meta.url));

let child;
let base;

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

before(async () => {
  const port = await freePort();
  child = spawn(process.execPath, [server], {
    env: {
      ...process.env,
      MOCK_UPSTREAM_LISTEN_PORT: String(port),
      MOCK_UPSTREAM_LISTEN_HOST: "127.0.0.1",
      MOCK_UPSTREAM_API_KEY: "",
    },
    stdio: "ignore",
  });
  base = `http://127.0.0.1:${port}`;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(`${base}/health`)).ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("the mock upstream did not start");
});

after(() => child?.kill());

const post = (path, body) =>
  fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

const queue = (body) => post("/__mock/faults", body);

const complete = (stream = true) =>
  post("/v1/chat/completions", {
    model: "gpt-4.1",
    stream,
    ...(stream ? { stream_options: { include_usage: true } } : {}),
    messages: [{ role: "user", content: "Run something." }],
  });

/**
 * The chunks of a streamed answer, and whether it ended with `[DONE]`: a
 * stream the mock cuts ends with the connection, so what arrived is kept.
 */
async function events(response) {
  let text = "";
  try {
    for await (const piece of response.body) text += Buffer.from(piece);
  } catch {
    // The connection was destroyed mid-stream.
  }
  const lines = text
    .split("\n")
    .filter((line) => line.startsWith("data: "))
    .map((line) => line.slice("data: ".length));
  return {
    done: lines.at(-1) === "[DONE]",
    chunks: lines
      .filter((line) => line !== "[DONE]")
      .map((line) => JSON.parse(line)),
  };
}

const requests = async () =>
  (await (await fetch(`${base}/__mock/requests`)).json()).requests;

test.afterEach(() => fetch(`${base}/__mock/faults`, { method: "DELETE" }));

test("answers the next streamed request with a queued tool call, then the plain reply", async () => {
  const arguments_ = { command: "echo hello > out.txt" };
  assert.equal(
    (await queue({ toolCall: { name: "bash", arguments: arguments_ } })).status,
    200,
  );

  const call = await events(await complete());
  assert.equal(call.done, true);
  const [first, second, last, usage] = call.chunks;
  const opened = first.choices[0].delta.tool_calls[0];
  assert.equal(opened.function.name, "bash");
  assert.match(opened.id, /^call_mock_\d+$/);
  assert.equal(first.choices[0].delta.content, null);
  // The arguments come as the second delta, one JSON document.
  assert.deepEqual(
    JSON.parse(second.choices[0].delta.tool_calls[0].function.arguments),
    arguments_,
  );
  assert.equal(last.choices[0].finish_reason, "tool_calls");
  assert.deepEqual(usage.choices, []);

  // The queue is empty: the request that carries the result gets text.
  const reply = await events(await complete());
  const text = reply.chunks
    .map((chunk) => chunk.choices[0]?.delta.content ?? "")
    .join("");
  assert.equal(text, "Reference mock reply from gpt-4.1.");
  assert.equal(reply.chunks.at(-2).choices[0].finish_reason, "stop");

  const [logged, replied] = (await requests()).slice(-2);
  assert.equal(logged.toolCall, "bash");
  assert.equal(replied.toolCall, undefined);
});

test("scripts several turns in the order the calls were queued", async () => {
  await queue({ toolCall: { name: "read", arguments: { path: "a" } } });
  await queue({ toolCall: { name: "bash" } });
  const names = [];
  for (let turn = 0; turn < 2; turn += 1) {
    const { chunks } = await events(await complete());
    const call = chunks[0].choices[0].delta.tool_calls[0];
    names.push(call.function.name);
    // A call queued without arguments sends an empty object.
    if (turn === 1)
      assert.deepEqual(
        JSON.parse(chunks[1].choices[0].delta.tool_calls[0].function.arguments),
        {},
      );
  }
  assert.deepEqual(names, ["read", "bash"]);
});

test("keeps a queued tool call for a streamed request when a plain one comes first", async () => {
  await queue({ toolCall: { name: "bash", arguments: { command: "true" } } });
  const plain = await (await complete(false)).json();
  assert.equal(plain.choices[0].finish_reason, "stop");
  assert.equal(
    plain.choices[0].message.content,
    "Reference mock reply from gpt-4.1.",
  );
  const { chunks } = await events(await complete());
  assert.equal(chunks[0].choices[0].delta.tool_calls[0].function.name, "bash");
});

test("refuses a fault that is not exactly one kind, or a tool call that is malformed", async () => {
  for (const body of [
    { toolCall: { name: "bash" }, status: 503 },
    { toolCall: { name: "bash" }, cut: 2 },
    { toolCall: { name: "not a name" } },
    { toolCall: { name: "" } },
    { toolCall: { name: "bash", arguments: ["ls"] } },
    { toolCall: { name: "bash", arguments: "ls" } },
    { toolCall: "bash" },
    { toolCall: null },
    { count: 1 },
  ])
    assert.equal((await queue(body)).status, 400, JSON.stringify(body));
  // Nothing was queued: the next streamed request is a reply.
  const { chunks } = await events(await complete());
  assert.equal(chunks[0].choices[0].delta.tool_calls, undefined);
});

test("keeps failures and cut streams working beside tool calls", async () => {
  await queue({ cut: 2 });
  await queue({ toolCall: { name: "bash" } });
  // The cut is first in the queue: it takes the first streamed request.
  const cut = await events(await complete());
  assert.equal(cut.done, false);
  assert.equal(cut.chunks.length, 2);
  const call = await events(await complete());
  assert.equal(
    call.chunks[0].choices[0].delta.tool_calls[0].function.name,
    "bash",
  );
});
