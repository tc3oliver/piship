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
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { SecretValue } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { uninstallCrashRedaction } from "./crash-redaction.js";
import {
  providerErrorRedaction,
  redactProviderError,
  redactToolResult,
  TOOL_RESULT_MESSAGE_FIELDS,
} from "./redaction.js";

// An obvious fake: registered as a SecretValue, as PiShip registers the
// runtime credential it holds, and sent as the provider's bearer.
const CREDENTIAL = "piship-fake-runtime-credential-0123456789";
new SecretValue(CREDENTIAL);

describe("redactToolResult", () => {
  const nestedMessage = (toolName: string) => ({
    role: "toolResult",
    toolCallId: "call_1",
    toolName,
    content: [{ type: "text", text: "Script completed" }],
    isError: false,
    timestamp: 1,
    nestedCalls: {
      complete: true,
      calls: [
        {
          id: "call_1/1",
          name: "bash",
          arguments: {
            command: `curl -H "Authorization: Bearer ${CREDENTIAL}"`,
          },
          status: "error",
          error: `401 for ${CREDENTIAL}`,
        },
        {
          id: "call_1/2",
          name: "read",
          arguments: { path: "a.txt" },
          status: "ok",
        },
      ],
    },
    details: {
      calls: [
        {
          id: "call_1/1",
          name: "bash",
          args: `{"command":"curl ${CREDENTIAL}"}`,
          status: "error",
          error: `401 for ${CREDENTIAL}`,
        },
      ],
    },
  });

  it("redacts nested call arguments and errors, and a Codemode result's call previews", () => {
    const message = nestedMessage("codemode");
    const redacted = redactToolResult(message) as typeof message;
    expect(JSON.stringify(redacted)).not.toContain(CREDENTIAL);
    expect(redacted.nestedCalls.calls[0]?.error).toContain("401 for");
    expect(redacted.nestedCalls.calls[1]).toEqual(message.nestedCalls.calls[1]);
    expect(redacted.nestedCalls.complete).toBe(true);
    expect(redacted.details.calls[0]?.status).toBe("error");
    expect(redacted.content).toBe(message.content);
    // The original is left alone; Pi applies the replacement itself.
    expect(JSON.stringify(message)).toContain(CREDENTIAL);
  });

  it("leaves no part of a secret a Codemode preview cut through", () => {
    // Codemode's 200-character preview: JSON cut, ending in `...`.
    const command = `${"x".repeat(170)} ${CREDENTIAL}`;
    const json = JSON.stringify({ command });
    const cut = `${json.slice(0, 197)}...`;
    const partial = cut.slice(cut.lastIndexOf(" ") + 1, -3);
    expect(CREDENTIAL.startsWith(partial)).toBe(true);
    const message = {
      role: "toolResult",
      toolCallId: "call_2",
      toolName: "codemode",
      content: [],
      isError: false,
      timestamp: 1,
      nestedCalls: {
        complete: true,
        calls: [{ id: "call_2/1", name: "bash", arguments: { command } }],
      },
      details: {
        calls: [
          { id: "call_2/1", name: "bash", args: cut, status: "ok" },
          // No full arguments recorded (over Pi's size limit).
          { id: "call_2/2", name: "bash", args: cut, status: "ok" },
        ],
      },
    };
    const redacted = redactToolResult(message) as typeof message;
    const [rebuilt, stripped] = redacted.details.calls;
    expect(rebuilt?.args).toContain("[REDACTED");
    expect(stripped?.args.endsWith(" ...")).toBe(true);
    for (const call of redacted.details.calls)
      expect(call.args).not.toContain(partial);
  });

  it("redacts another tool's details, which are arbitrary JSON, and keeps its structure", () => {
    // A non-codemode tool that echoes a secret into `details`: the same defect
    // would persist it unredacted if only codemode's `details.calls` were
    // touched. `details` is opaque per-tool JSON, so it is redacted whole.
    const other = redactToolResult(nestedMessage("company_batch")) as {
      details: { calls: { id: string; name: string; args: string }[] };
      nestedCalls: { calls: { arguments: unknown; error: string }[] };
    };
    expect(JSON.stringify(other.details)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(other.nestedCalls)).not.toContain(CREDENTIAL);
    // Ordinary metadata survives: the shape and the non-secret fields stay.
    expect(other.details.calls[0]?.id).toBe("call_1/1");
    expect(other.details.calls[0]?.name).toBe("bash");
    expect(other.details.calls[0]?.args).toContain("[REDACTED");
    // A non-codemode `details.calls.args` is not rebuilt from full arguments
    // (that is codemode's preview); it is redacted in place, still a preview.
    expect(other.details.calls[0]?.args).not.toContain("...");
  });

  it("redacts secrets nested in objects and arrays inside any tool's details", () => {
    const message = {
      role: "toolResult",
      toolCallId: "call_9",
      toolName: "company_batch",
      content: [],
      isError: false,
      timestamp: 1,
      details: {
        request: { headers: { Authorization: `Bearer ${CREDENTIAL}` } },
        rows: [
          { ok: true },
          { note: `token=${CREDENTIAL}`, apiKey: CREDENTIAL },
        ],
        fullOutputPath: "/tmp/out.txt",
      },
    };
    const redacted = redactToolResult(message) as typeof message;
    expect(JSON.stringify(redacted.details)).not.toContain(CREDENTIAL);
    // Structure and non-secret metadata are preserved.
    expect(redacted.details.rows[0]).toEqual({ ok: true });
    expect(redacted.details.fullOutputPath).toBe("/tmp/out.txt");
    expect(redacted.details.request.headers.Authorization).toContain(
      "[REDACTED",
    );
    // The original is untouched.
    expect(JSON.stringify(message.details)).toContain(CREDENTIAL);
  });

  it("leaves a result with nothing to redact, and a message of another role, alone", () => {
    expect(
      redactToolResult({
        role: "toolResult",
        toolName: "read",
        content: [],
        isError: false,
      }),
    ).toBeUndefined();
    expect(
      redactToolResult({
        role: "toolResult",
        toolName: "read",
        content: [],
        isError: false,
        details: { lines: 3, path: "a.txt" },
      }),
    ).toBeUndefined();
    expect(redactToolResult({ role: "assistant" })).toBeUndefined();
  });

  it("classifies the nested calls and details as redacted", () => {
    expect(
      Object.entries(TOOL_RESULT_MESSAGE_FIELDS)
        .filter(([, kind]) => kind === "redacted")
        .map(([field]) => field)
        .sort(),
    ).toEqual(["details", "nestedCalls"]);
  });
});

describe("redactToolResult fallback for fields no table classifies", () => {
  // `details` and `nestedCalls` are arbitrary JSON: a future or different Pi
  // can put any key in them, and the classification tables cannot enumerate
  // those keys. The runtime fallback is `redactValue`, which recurses and runs
  // `redact()` over every string leaf and replaces a secret-named key whatever
  // it holds. These pin that the fallback SCRUBS an unknown key rather than
  // carrying it through. A token-shaped value that is NOT a registered
  // SecretValue proves the recursive `redact()` reaches unknown keys, not just
  // the registered-secret substitution. Flipping the fallback to pass-through
  // would leave CREDENTIAL/SHAPED in the output and fail every assertion here.
  const SHAPED = "sk-future-pi-field-abcdef0123456789";

  const result = (details: unknown) => ({
    role: "toolResult",
    toolCallId: "call_u",
    toolName: "company_batch",
    content: [],
    isError: false,
    timestamp: 1,
    details,
  });

  it("scrubs an unknown top-level key instead of carrying it through", () => {
    const message = result({
      futureField: `Bearer ${CREDENTIAL}`,
      anotherUnknown: SHAPED,
    });
    const redacted = redactToolResult(message) as typeof message;
    const details = redacted.details as Record<string, string>;
    expect(JSON.stringify(details)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(details)).not.toContain(SHAPED);
    // The keys survive (structure preserved); only the secret values are gone.
    expect(details.futureField).toContain("[REDACTED");
    expect(details.anotherUnknown).toBe("[REDACTED]");
    // Non-vacuous: the input really held them.
    expect(JSON.stringify(message.details)).toContain(CREDENTIAL);
    expect(JSON.stringify(message.details)).toContain(SHAPED);
  });

  it("scrubs an unknown key nested arbitrarily deep", () => {
    const message = result({
      level1: {
        level2: { level3: { deepSecret: CREDENTIAL, shaped: SHAPED } },
      },
    });
    const redacted = redactToolResult(message) as typeof message;
    expect(JSON.stringify(redacted.details)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(redacted.details)).not.toContain(SHAPED);
    const deep = (
      redacted.details as {
        level1: { level2: { level3: Record<string, string> } };
      }
    ).level1.level2.level3;
    expect(deep.deepSecret).toBe("[REDACTED]");
    expect(deep.shaped).toBe("[REDACTED]");
  });

  it("scrubs an unknown key inside an array of objects", () => {
    const message = result({
      rows: [{ ok: true }, { futureCell: CREDENTIAL }, [`Bearer ${SHAPED}`]],
    });
    const redacted = redactToolResult(message) as typeof message;
    expect(JSON.stringify(redacted.details)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(redacted.details)).not.toContain(SHAPED);
    const rows = (redacted.details as { rows: unknown[] }).rows;
    // Inert array elements are untouched; the secret-bearing ones are scrubbed.
    expect(rows[0]).toEqual({ ok: true });
    expect(rows[1]).toEqual({ futureCell: "[REDACTED]" });
    expect(rows[2]).toEqual(["[REDACTED]"]);
  });

  it("scrubs a credential riding inside an exception field's value", () => {
    // `fullOutputPath` is preserved when inert (see the nested-details test
    // above), but its VALUE still runs through `redact()`, so a registered
    // secret or a token shape embedded in the path is scrubbed, not carried. A
    // key whose NAME is a credential word is replaced whatever it holds, even
    // an otherwise-inert value.
    const message = result({
      fullOutputPath: `/tmp/${CREDENTIAL}/out.txt`,
      sizedPath: `/var/log/${SHAPED}.log`,
      apiKey: "inert-but-the-name-matches",
    });
    const redacted = redactToolResult(message) as typeof message;
    const details = redacted.details as Record<string, string>;
    expect(JSON.stringify(details)).not.toContain(CREDENTIAL);
    expect(JSON.stringify(details)).not.toContain(SHAPED);
    expect(details.fullOutputPath).toContain("/tmp/");
    expect(details.fullOutputPath).toContain("[REDACTED");
    expect(details.apiKey).toBe("[REDACTED]");
  });
});

describe("redactProviderError", () => {
  it("redacts a registered credential and bearer shapes in an assistant's error text", () => {
    const message = {
      role: "assistant",
      stopReason: "error",
      errorMessage: `500 upstream failure for Authorization: Bearer ${CREDENTIAL}`,
    };
    const redacted = redactProviderError(message) as typeof message;
    expect(redacted.errorMessage).not.toContain(CREDENTIAL);
    expect(redacted.errorMessage).toContain("500 upstream failure");
    expect(redacted.stopReason).toBe("error");
    // The original is left alone; Pi applies the replacement itself.
    expect(message.errorMessage).toContain(CREDENTIAL);
  });

  it("redacts the provider diagnostics Pi stores with the message", () => {
    const message = {
      role: "assistant",
      stopReason: "error",
      diagnostics: [
        {
          error: {
            message: `stream failed: ${CREDENTIAL}`,
            stack: `Error: stream failed: ${CREDENTIAL}\n    at x`,
          },
          details: { request: { headers: { authorization: CREDENTIAL } } },
        },
      ],
    };
    const redacted = redactProviderError(message) as typeof message;
    expect(JSON.stringify(redacted.diagnostics)).not.toContain(CREDENTIAL);
    expect(redacted.diagnostics[0]?.error.message).toBe(
      "stream failed: [REDACTED]",
    );
    expect(redacted.stopReason).toBe("error");
    expect(redactProviderError({ role: "assistant", diagnostics: [] })).toBe(
      undefined,
    );
  });

  it("redacts a secret a provider puts in a deferred handle's data", () => {
    // `DeferredHandle.data` is arbitrary provider JSON, so it is a carrier
    // like the diagnostics. The handle's structural fields and a normal `id`
    // stay: a deferred conversion Pi resumes must still work.
    const message = {
      role: "assistant",
      stopReason: "deferred",
      deferred: {
        provider: "acmecode",
        modelId: "acme/coder",
        api: "openai-completions",
        id: "batch_42/row_7",
        data: { request: { headers: { authorization: CREDENTIAL } } },
      },
    };
    const redacted = redactProviderError(message) as typeof message;
    expect(JSON.stringify(redacted.deferred)).not.toContain(CREDENTIAL);
    expect(redacted.deferred.id).toBe("batch_42/row_7");
    expect(redacted.deferred.provider).toBe("acmecode");
    expect(redacted.deferred.modelId).toBe("acme/coder");
    expect(redacted.deferred.api).toBe("openai-completions");
    expect(JSON.stringify(message.deferred)).toContain(CREDENTIAL);
  });

  it("leaves a deferred handle with nothing secret in it alone", () => {
    expect(
      redactProviderError({
        role: "assistant",
        stopReason: "deferred",
        deferred: { provider: "acmecode", id: "batch_42/row_7", data: {} },
      }),
    ).toBeUndefined();
  });

  it("leaves a message without secret text, without error text, or of another role alone", () => {
    expect(
      redactProviderError({
        role: "assistant",
        errorMessage: "500 gateway failure",
      }),
    ).toBeUndefined();
    expect(
      redactProviderError({ role: "assistant", content: [] }),
    ).toBeUndefined();
    expect(
      redactProviderError({ role: "user", errorMessage: CREDENTIAL }),
    ).toBeUndefined();
    expect(redactProviderError(undefined)).toBeUndefined();
  });
});

/** A careless gateway: every completion fails with the request's Authorization in its error. */
async function echoingGateway() {
  const seen: string[] = [];
  const server: Server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      seen.push(request.headers.authorization ?? "");
      response.writeHead(500, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          error: {
            message: `upstream failure for Authorization: ${request.headers.authorization}`,
            type: "server_error",
          },
        }),
      );
    });
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  return {
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}/v1`,
    seen,
    close: () =>
      new Promise<void>((done) => {
        server.close(() => done());
        server.closeAllConnections();
      }),
  };
}

describe("a Pi session with provider error redaction", () => {
  let temp: string;
  let gateway: Awaited<ReturnType<typeof echoingGateway>>;
  beforeEach(async () => {
    temp = realpathSync(mkdtempSync(join(tmpdir(), "piship-redaction-")));
    gateway = await echoingGateway();
  });
  afterEach(async () => {
    uninstallCrashRedaction();
    await gateway.close();
    rmSync(temp, { recursive: true, force: true });
  });

  it("puts the crash redaction first at session_start", async () => {
    const { session } = await open({ enabled: false });
    const [first] = process.listeners("uncaughtException");
    const error = new Error(`crash ${CREDENTIAL}`);
    first?.(error, "uncaughtException");
    expect(error.message).toBe("crash [REDACTED]");
    session.dispose();
  });

  async function open(retry: { enabled: boolean; maxRetries?: number }) {
    const runtime = await ModelRuntime.create({
      modelsPath: null,
      refreshOnCreate: false,
      allowModelNetwork: false,
      authPath: join(temp, "auth.json"),
    });
    runtime.registerProvider("acmecode", {
      name: "AcmeCode",
      baseUrl: gateway.url,
      apiKey: CREDENTIAL,
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
    const settingsManager = SettingsManager.inMemory({
      retry: { ...retry, baseDelayMs: 1 },
    });
    const resourceLoader = new DefaultResourceLoader({
      cwd: temp,
      agentDir: temp,
      settingsManager,
      noExtensions: true,
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
      extensionFactories: [providerErrorRedaction],
    });
    await resourceLoader.reload();
    const model = runtime.getModel("acmecode", "acme/coder");
    if (!model) throw new Error("fixture model missing");
    const sessionDir = join(temp, "sessions");
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
    await session.bindExtensions({});
    return { session, sessionDir };
  }

  const sessionFiles = (dir: string) =>
    readdirSync(dir, { recursive: true, encoding: "utf8" })
      .filter((name) => name.endsWith(".jsonl"))
      .map((name) => readFileSync(join(dir, name), "utf8"));

  it("keeps an echoed credential out of the session file and the agent state", async () => {
    const { session, sessionDir } = await open({ enabled: false });
    await session.prompt("hello");
    expect(gateway.seen).toEqual([`Bearer ${CREDENTIAL}`]);
    const last = session.messages.at(-1) as {
      stopReason?: string;
      errorMessage?: string;
    };
    expect(last.stopReason).toBe("error");
    expect(last.errorMessage).toMatch(/500/);
    expect(last.errorMessage).toContain("upstream failure");
    expect(last.errorMessage).not.toContain(CREDENTIAL);
    const files = sessionFiles(sessionDir);
    expect(files.length).toBe(1);
    expect(files[0]).toContain('"errorMessage"');
    expect(files[0]).toContain("upstream failure");
    expect(files[0]).not.toContain(CREDENTIAL);
    session.dispose();
  });

  it("still retries a redacted server error, and redacts every attempt", async () => {
    const { session, sessionDir } = await open({
      enabled: true,
      maxRetries: 1,
    });
    await session.prompt("hello");
    // One retry after the first 500: the redacted text still reads as retryable.
    expect(gateway.seen.length).toBe(2);
    const [file] = sessionFiles(sessionDir);
    expect(file).not.toContain(CREDENTIAL);
    expect(file?.match(/"errorMessage"/g)?.length).toBe(2);
    session.dispose();
  });
});
