#!/usr/bin/env node
// A stand-in for a local OpenAI-compatible model server, for trying and
// testing the MyPi Local variant without a real model. It listens on
// loopback only, accepts one API key, and answers every chat completion with
// a canned, streamed reply. It is test infrastructure, not a model.
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

/**
 * Start the server. `requests` records the method, path, and authorization
 * header of every request, so a test can see what the distribution sent.
 */
export async function startModelServer({
  key = "sk-local-model-key",
  models = ["local/coder"],
  port = 0,
} = {}) {
  const requests = [];
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
      requests.push({
        method: request.method,
        path,
        authorization: request.headers.authorization,
      });
      const json = (status, value) =>
        response
          .writeHead(status, { "content-type": "application/json" })
          .end(JSON.stringify(value));
      if (request.headers.authorization !== `Bearer ${key}`)
        return json(401, { error: { message: "invalid api key" } });
      if (path === "/v1/models" && request.method === "GET")
        return json(200, {
          object: "list",
          data: models.map((id) => ({ id, object: "model" })),
        });
      if (path !== "/v1/chat/completions" || request.method !== "POST")
        return json(404, { error: { message: "not found" } });
      let model;
      try {
        model = JSON.parse(body).model;
      } catch {
        return json(400, { error: { message: "invalid JSON" } });
      }
      if (!models.includes(model))
        return json(404, { error: { message: `model ${model} not found` } });
      const chunk = (delta, finish = null) => ({
        id: "chatcmpl-local",
        object: "chat.completion.chunk",
        created: 0,
        model,
        choices: [{ index: 0, delta, finish_reason: finish }],
      });
      response.writeHead(200, { "content-type": "text/event-stream" });
      for (const event of [
        chunk({ role: "assistant", content: `Hello from ${model}.` }),
        chunk({}, "stop"),
      ])
        response.write(`data: ${JSON.stringify(event)}\n\n`);
      response.end("data: [DONE]\n\n");
    });
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/v1`;
  return {
    url,
    key,
    requests,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const port = process.argv.includes("--port")
    ? Number(process.argv[process.argv.indexOf("--port") + 1])
    : 0;
  const started = await startModelServer({ port });
  const set = process.platform === "win32" ? "set " : "export ";
  console.log("# Stand-in local model server (canned replies, not a model).");
  console.log(`${set}MYPI_MODEL_URL=${started.url}`);
  console.log(`# API key for mypi-local login: ${started.key}`);
}
