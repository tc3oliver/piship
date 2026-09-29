#!/usr/bin/env node
// Deterministic OpenAI-compatible upstream for the enterprise reference stack.
// LiteLLM routes to it in place of a real model provider, so the stack needs
// no paid API key and no Internet access.
//
// Endpoints:
//   GET  /health                   liveness, no authentication
//   GET  /v1/models                the upstream model IDs
//   POST /v1/chat/completions      streaming (SSE) and non-streaming
//   POST /__mock/faults            queue failures for the next completions
//   DELETE /__mock/faults          clear queued failures
//   GET  /__mock/requests          metadata of recent completion requests
//
// Failures are deterministic. A user message containing `[mock:status=NNN]`
// (401, 403, 429, or any 5xx) answers with that status every time it is
// sent, so LiteLLM retries see the same answer. `POST /__mock/faults` with
// `{"status": 503, "count": 1, "retryAfter": 2}` queues a failure for the
// next `count` completion requests whatever their content.
//
// A user message containing `[mock:delay=MS]` (0 to 10000) holds that
// request for MS milliseconds before it is answered, so a test can keep a
// gateway's concurrency slot occupied.
//
// This is test infrastructure. It is not a model and not evidence of a live
// provider integration. The control endpoints have no authentication: publish
// the port on loopback only.
import { createServer } from "node:http";

const PORT = Number(process.env.MOCK_UPSTREAM_LISTEN_PORT ?? 8080);
const API_KEY = process.env.MOCK_UPSTREAM_API_KEY ?? "";
const MODELS = (process.env.MOCK_UPSTREAM_MODELS ?? "gpt-4.1,gpt-4.1-mini")
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);
const CREATED = 1767225600; // 2026-01-01T00:00:00Z, fixed for determinism
const MAX_BODY = 1024 * 1024;
const MAX_LOG = 100;

const faults = [];
const requests = [];
let sequence = 0;

const ERRORS = {
  400: ["invalid_request_error", "invalid_request", "Mock bad request."],
  401: [
    "invalid_request_error",
    "invalid_api_key",
    "Incorrect API key provided.",
  ],
  403: [
    "permission_error",
    "model_not_allowed",
    "Mock upstream denies this request.",
  ],
  404: ["invalid_request_error", "model_not_found", "Mock model not found."],
  429: [
    "rate_limit_error",
    "rate_limit_exceeded",
    "Mock upstream rate limit reached.",
  ],
};

function errorBody(status) {
  const [type, code, message] = ERRORS[status] ?? [
    "server_error",
    "server_error",
    `Mock upstream failure (${status}).`,
  ];
  return { error: { message, type, param: null, code } };
}

function send(response, status, value, headers = {}) {
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(value));
}

function sendError(response, status, retryAfter) {
  const headers =
    status === 429 || retryAfter !== undefined
      ? { "retry-after": String(retryAfter ?? 1) }
      : {};
  send(response, status, errorBody(status), headers);
}

async function readJson(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

function text(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content))
    return content.map((part) => part?.text ?? "").join("");
  return "";
}

const words = (value) => value.split(/\s+/).filter(Boolean).length;

function isFailureStatus(status) {
  return (
    Number.isInteger(status) &&
    (status === 401 || status === 403 || status === 429 || status >= 500) &&
    status <= 599
  );
}

function requestedFailure(messages) {
  for (const message of messages) {
    if (message?.role !== "user") continue;
    const match = /\[mock:status=(\d{3})\]/.exec(text(message.content));
    if (match && isFailureStatus(Number(match[1]))) return Number(match[1]);
  }
  return undefined;
}

const MAX_DELAY_MS = 10_000;

function requestedDelay(messages) {
  for (const message of messages) {
    if (message?.role !== "user") continue;
    const match = /\[mock:delay=(\d{1,5})\]/.exec(text(message.content));
    if (match) return Math.min(Number(match[1]), MAX_DELAY_MS);
  }
  return 0;
}

function record(entry) {
  requests.push(entry);
  if (requests.length > MAX_LOG) requests.shift();
}

function chunk(id, model, delta, finish = null) {
  return {
    id,
    object: "chat.completion.chunk",
    created: CREATED,
    model,
    system_fingerprint: "fp_mock",
    choices: [{ index: 0, delta, logprobs: null, finish_reason: finish }],
  };
}

function complete(response, payload) {
  const model = String(payload.model ?? "");
  const messages = Array.isArray(payload.messages) ? payload.messages : [];
  const id = `chatcmpl-mock-${++sequence}`;
  const reply = `Reference mock reply from ${model}.`;
  const prompt = messages.reduce(
    (total, message) => total + words(text(message?.content)),
    0,
  );
  const usage = {
    prompt_tokens: prompt,
    completion_tokens: words(reply),
    total_tokens: prompt + words(reply),
  };

  if (payload.stream !== true) {
    return send(response, 200, {
      id,
      object: "chat.completion",
      created: CREATED,
      model,
      system_fingerprint: "fp_mock",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: reply, refusal: null },
          logprobs: null,
          finish_reason: "stop",
        },
      ],
      usage,
    });
  }

  const events = [chunk(id, model, { role: "assistant", content: "" })];
  for (const [index, word] of reply.split(" ").entries())
    events.push(chunk(id, model, { content: index ? ` ${word}` : word }));
  events.push(chunk(id, model, {}, "stop"));
  if (payload.stream_options?.include_usage === true)
    events.push({ ...chunk(id, model, {}), choices: [], usage });

  response.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  for (const event of events)
    response.write(`data: ${JSON.stringify(event)}\n\n`);
  response.end("data: [DONE]\n\n");
}

async function handle(request, response) {
  const url = new URL(request.url ?? "/", "http://mock-upstream");
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (path === "/health" && request.method === "GET")
    return send(response, 200, { status: "ok" });

  if (path === "/__mock/faults" && request.method === "POST") {
    const { status, count = 1, retryAfter } = await readJson(request);
    if (!isFailureStatus(status) || !Number.isInteger(count) || count < 1)
      return send(response, 400, {
        error: "status must be 401, 403, 429 or 5xx; count a positive integer",
      });
    for (let index = 0; index < count; index += 1)
      faults.push({ status, retryAfter });
    return send(response, 200, { queued: faults.length });
  }
  if (path === "/__mock/faults" && request.method === "DELETE") {
    faults.length = 0;
    return send(response, 200, { queued: 0 });
  }
  if (path === "/__mock/requests" && request.method === "GET")
    return send(response, 200, { requests });

  // Everything below is the OpenAI-compatible surface LiteLLM calls. The
  // upstream key is compared, never logged or echoed.
  if (API_KEY && request.headers.authorization !== `Bearer ${API_KEY}`)
    return sendError(response, 401);

  if (path === "/v1/models" && request.method === "GET")
    return send(response, 200, {
      object: "list",
      data: MODELS.map((id) => ({
        id,
        object: "model",
        created: CREATED,
        owned_by: "piship-reference-mock",
      })),
    });

  if (path === "/v1/chat/completions" && request.method === "POST") {
    const payload = await readJson(request);
    const messages = Array.isArray(payload.messages) ? payload.messages : [];
    const fault = faults.shift();
    const status = fault?.status ?? requestedFailure(messages);
    record({
      time: new Date().toISOString(),
      model: payload.model ?? null,
      stream: payload.stream === true,
      status: status ?? 200,
    });
    const delay = requestedDelay(messages);
    if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
    if (status) return sendError(response, status, fault?.retryAfter);
    return complete(response, payload);
  }

  return sendError(response, 404);
}

// As PID 1 in its container, Node has no default SIGTERM handler; without
// these, `docker compose down` waits its full 10 s before killing it.
for (const signal of ["SIGTERM", "SIGINT"])
  process.on(signal, () => process.exit(0));

createServer((request, response) => {
  handle(request, response).catch(() => {
    if (!response.headersSent) sendError(response, 400);
    else response.destroy();
  });
}).listen(PORT, "0.0.0.0", () => {
  process.stdout.write(`mock upstream listening on ${PORT}\n`);
});
