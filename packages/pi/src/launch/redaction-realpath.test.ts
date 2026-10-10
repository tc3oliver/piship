// The real output paths, not the pure function: a non-codemode tool that
// echoes a secret into its `details` must not leave it in the persisted
// session file nor in the `message_end` event the child serializes. This
// drives a live Pi session through a scriptable gateway that makes the model
// call the tool, so `message_end` runs `providerErrorRedaction` and Pi then
// persists and serializes the mutated message exactly as a real launch does.
//
// Scope, stated plainly because the child's stdout carries more than this: a
// JSON-mode child writes EVERY event verbatim (print-mode + `toJsonEvent`,
// which passes non-`message_update` events through unchanged), so a
// `tool_execution_end` line still carries the tool's unredacted
// `result.details`. Redaction runs at `message_end` only. This test therefore
// asserts the two paths redaction DOES cover — the persisted `.jsonl` and the
// `message_end` JSON — and does not claim the whole stdout is clean. That
// remaining gap is documented in docs/security.md ("Redaction").
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createAgentSession,
  DefaultResourceLoader,
  type InlineExtension,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { SecretValue } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { uninstallCrashRedaction } from "./crash-redaction.js";
import { providerErrorRedaction } from "./redaction.js";

const CREDENTIAL = "piship-fake-runtime-credential-0123456789";
new SecretValue(CREDENTIAL);

/** The secret-laden `details` the tool returns, for the assertions below. */
const toolDetails = () => ({
  request: { headers: { Authorization: `Bearer ${CREDENTIAL}` } },
  note: `token=${CREDENTIAL}`,
  fullOutputPath: "/tmp/out.txt",
});

/**
 * A gateway that scripts one model turn: call `company_batch`, then finish.
 * Pi drives OpenAI-compatible chat completions over SSE, so a tool call is a
 * streamed `tool_calls` delta and the follow-up turn sees the tool result.
 */
function scriptGateway(toolName: string) {
  const server: Server = createServer((request, response) => {
    let raw = "";
    request.on("data", (chunk) => {
      raw += chunk;
    });
    request.on("end", () => {
      const body = JSON.parse(raw || "{}") as {
        model?: string;
        messages?: { role: string }[];
      };
      const model = body.model ?? "acme/coder";
      const done = (body.messages ?? []).some((m) => m.role === "tool");
      const sse = (chunks: unknown[]) => {
        response.writeHead(200, { "content-type": "text/event-stream" });
        for (const chunk of chunks)
          response.write(`data: ${JSON.stringify(chunk)}\n\n`);
        response.end("data: [DONE]\n\n");
      };
      const part = (delta: unknown, finish?: string) => ({
        id: "chatcmpl-script",
        object: "chat.completion.chunk",
        created: 0,
        model,
        choices: [{ index: 0, delta, finish_reason: finish ?? null }],
      });
      if (!done)
        return sse([
          part({
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: "call_1",
                type: "function",
                function: { name: toolName, arguments: "" },
              },
            ],
          }),
          part({
            tool_calls: [{ index: 0, function: { arguments: "{}" } }],
          }),
          part({}, "tool_calls"),
        ]);
      return sse([part({ role: "assistant", content: "done" }, "stop")]);
    });
  });
  return new Promise<Server>((ready) =>
    server.listen(0, "127.0.0.1", () => ready(server)),
  );
}

/** An inline extension registering one non-codemode tool that leaks a secret. */
const leakingTool = (name: string): InlineExtension => ({
  name: `test-${name}`,
  factory: (pi) => {
    pi.registerTool({
      name,
      label: name,
      description: "Echoes a secret into details.",
      parameters: { type: "object", properties: {} } as never,
      async execute() {
        return {
          content: [{ type: "text", text: "ran" }],
          details: toolDetails(),
        };
      },
    } as never);
  },
});

describe("a tool result's details on the real output paths", () => {
  let temp: string;
  let sessionDir: string;
  let server: Server;

  beforeEach(async () => {
    temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-redact-path-")));
    sessionDir = join(temp, "sessions");
  });
  afterEach(async () => {
    uninstallCrashRedaction();
    server?.close();
    server?.closeAllConnections();
    rmSync(temp, { recursive: true, force: true });
  });

  /** Run one turn and return the session file text and the `message_end` JSON. */
  async function run(toolName: string) {
    server = await scriptGateway(toolName);
    const port = (server.address() as { port: number }).port;
    const runtime = await ModelRuntime.create({
      modelsPath: null,
      refreshOnCreate: false,
      allowModelNetwork: false,
      authPath: join(temp, "auth.json"),
    });
    runtime.registerProvider("acmecode", {
      name: "AcmeCode",
      baseUrl: `http://127.0.0.1:${port}/v1`,
      apiKey: "not-the-secret",
      api: "openai-completions",
      models: [
        {
          id: "acme/coder",
          name: "acme/coder",
          reasoning: false,
          input: ["text"],
          cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
          contextWindow: 64000,
          maxTokens: 4096,
        },
      ],
    });
    const settingsManager = SettingsManager.inMemory({});
    const resourceLoader = new DefaultResourceLoader({
      cwd: temp,
      agentDir: temp,
      settingsManager,
      noExtensions: true,
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
      extensionFactories: [providerErrorRedaction, leakingTool(toolName)],
    });
    await resourceLoader.reload();
    const model = runtime.getModel("acmecode", "acme/coder");
    if (!model) throw new Error("fixture model missing");
    const { session } = await createAgentSession({
      cwd: temp,
      agentDir: temp,
      modelRuntime: runtime,
      model,
      settingsManager,
      sessionManager: SessionManager.create(temp, sessionDir),
      resourceLoader,
      noTools: "builtin",
    });
    // The `message_end` line a JSON-mode child writes: print mode writes
    // `toJsonEvent(event)`, which passes a `message_end` event through
    // unchanged, so this is the real serialization of the tool result the
    // child emits at `message_end`. Only that event is collected — see the
    // scope note at the top of this file.
    const messageEnd: string[] = [];
    const unsubscribe = session.subscribe((event) => {
      if (event.type === "message_end") messageEnd.push(JSON.stringify(event));
    });
    await session.bindExtensions({});
    await session.prompt("go");
    unsubscribe();
    session.dispose();
    const files = readdirSync(sessionDir, { recursive: true, encoding: "utf8" })
      .filter((name) => name.endsWith(".jsonl"))
      .map((name) => readFileSync(join(sessionDir, name), "utf8"));
    return { file: files.join("\n"), messageEnd: messageEnd.join("\n") };
  }

  it("keeps a non-codemode tool's secret details out of the session file and the message_end event", async () => {
    const { file, messageEnd } = await run("company_batch");
    // The tool actually ran and produced its result, so this is a real path.
    expect(file).toContain("company_batch");
    expect(messageEnd).toContain('"type":"message_end"');
    // The secret is on neither path redaction covers.
    expect(file).not.toContain(CREDENTIAL);
    expect(messageEnd).not.toContain(CREDENTIAL);
    // Ordinary metadata in `details` is preserved, so the result stays useful.
    expect(file).toContain("fullOutputPath");
    expect(file).toContain("/tmp/out.txt");
    // The Authorization value is redacted, not merely absent.
    expect(file).toContain("[REDACTED");
  }, 60_000);
});
