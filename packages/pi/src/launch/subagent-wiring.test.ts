// The child's options reach the places that enforce them: the access check
// (`models.allowed`), Pi's session tools, and stdout/stderr.
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DistributionLock } from "@piship/core";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const seen = vi.hoisted(() => ({
  session: undefined as Record<string, unknown> | undefined,
  access: [] as unknown[][],
  result: undefined as Record<string, unknown> | undefined,
}));
vi.mock("@earendil-works/pi-coding-agent", async (original) => ({
  ...(await original<typeof import("@earendil-works/pi-coding-agent")>()),
  createAgentSession: async (options: Record<string, unknown>) => {
    seen.session = options;
    if (seen.result) return seen.result;
    throw new Error("stop-after-createAgentSession");
  },
}));
vi.mock("./context.js", async (original) => ({
  ...(await original<typeof import("./context.js")>()),
  prepareAccess: async (...args: unknown[]) => {
    seen.access.push(args);
    throw new Error("stop-after-prepareAccess");
  },
}));

import { runSubagentChild } from "../commands/session.js";
import { preparePiEnvironment } from "../environment.js";
import type { LaunchContext, PreparedAccess } from "./context.js";
import { startGoverned } from "./runtime.js";
import { launchOutput, type SubagentChild } from "./subagent-child.js";

let temp: string;
const saved = process.env.PISHIP_STATE_HOME;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-subagent-wiring-"));
  process.env.PISHIP_STATE_HOME = join(temp, "state");
  seen.session = undefined;
  seen.access = [];
  seen.result = undefined;
});
afterEach(() => {
  vi.restoreAllMocks();
  if (saved === undefined) delete process.env.PISHIP_STATE_HOME;
  else process.env.PISHIP_STATE_HOME = saved;
  rmSync(temp, { recursive: true, force: true });
});

function context(): LaunchContext {
  const agentDir = preparePiEnvironment("acmecode");
  const stateDir = join(temp, "state");
  mkdirSync(stateDir, { recursive: true });
  return {
    metadata: {
      app: { id: "acmecode", command: "acmecode", name: "A", version: "1" },
      deployment: { mode: "personal" },
      resources: [],
      declared: {
        instructions: [],
        skills: [],
        extensions: [],
        prompts: [],
        themes: [],
      },
    } as unknown as DistributionLock,
    distributionDir: temp,
    stateDir,
    agentDir,
    mode: "personal",
    out: () => {},
    err: () => {},
  } as unknown as LaunchContext;
}

describe("a subagent child's options reach what enforces them", () => {
  it("passes the child's model to the access check", async () => {
    const ctx = context();
    await expect(
      runSubagentChild(ctx, { prompt: "t", model: "acme/m" }),
    ).rejects.toThrow("stop-after-prepareAccess");
    expect(seen.access).toEqual([[ctx, "acme/m", false, "subagent"]]);
  });

  it("passes the child's exclusions and allowlist to Pi's session", async () => {
    const child: SubagentChild = {
      prompt: "t",
      excludeTools: ["bash"],
      tools: ["read"],
    };
    const prepared = {
      metrics: undefined,
      access: null,
      activated: null,
      removedEnvironment: [],
    } as unknown as PreparedAccess;
    await expect(
      startGoverned(
        context(),
        prepared,
        { sessionDir: "", newSession: true, child },
        null,
      ),
    ).rejects.toThrow("stop-after-createAgentSession");
    expect(seen.session).toMatchObject({
      excludeTools: ["bash"],
      tools: ["read"],
    });
  });
});

describe("a child's background session directory", () => {
  const prepared = {
    metrics: undefined,
    access: null,
    activated: null,
    removedEnvironment: [],
  } as unknown as PreparedAccess;
  const start = (dir: string) =>
    startGoverned(
      context(),
      prepared,
      {
        sessionDir: "",
        newSession: true,
        child: {
          prompt: "t",
          session: { id: "pi-code-bg-0123abcd-4567cdef", dir },
        },
      },
      null,
    );
  const directory = (mode: number) => {
    const dir = mkdtempSync(join(temp, "pi-code-bg-session-"));
    chmodSync(dir, mode);
    return dir;
  };

  it.skipIf(process.platform === "win32")(
    "is used when it is private to the user, and not when others can change it",
    async () => {
      await expect(start(directory(0o700))).rejects.toThrow(
        "stop-after-createAgentSession",
      );
      for (const mode of [0o770, 0o707, 0o755])
        await expect(start(directory(mode))).rejects.toThrow(
          "session directory cannot be used",
        );
    },
  );

  it("is refused when it is a link or not a directory", async () => {
    const real = directory(0o700);
    const link = join(temp, "pi-code-bg-session-link");
    symlinkSync(real, link);
    await expect(start(link)).rejects.toThrow(
      "session directory cannot be used",
    );
    const file = join(temp, "pi-code-bg-session-file");
    writeFileSync(file, "");
    await expect(start(file)).rejects.toThrow(
      "session directory cannot be used",
    );
  });
});

describe("a child's stdout", () => {
  it("carries only its events: PiShip's messages go to stderr", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    launchOutput(true)("notice");
    expect(log).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledWith("notice");
    launchOutput(false)("hello");
    expect(log).toHaveBeenCalledWith("hello");
  });
});

describe("resuming a session", () => {
  const sessionDir = () => {
    const dir = mkdtempSync(join(temp, "sessions-"));
    chmodSync(dir, 0o700);
    return dir;
  };
  const prepared = (requestedModel?: string) =>
    ({
      metrics: undefined,
      access: null,
      activated: {
        selectedModel: "anthropic/claude-sonnet-4-5",
        runtime: { kind: "pi-native" },
        config: { values: {}, entries: [] },
      },
      removedEnvironment: [],
      ...(requestedModel ? { requestedModel } : {}),
    }) as unknown as PreparedAccess;
  async function resume(requestedModel?: string) {
    const dir = sessionDir();
    const first = SessionManager.create(process.cwd(), dir);
    first.appendMessage({ role: "user", content: "hi", timestamp: 1 });
    first.appendMessage({
      role: "assistant",
      content: [{ type: "text", text: "hello" }],
      api: "openai-completions",
      provider: "openai",
      model: "gpt-4o",
      usage: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "stop",
      timestamp: 2,
    });
    await expect(
      startGoverned(
        context(),
        prepared(requestedModel),
        { sessionDir: dir, newSession: false, resume: first.getSessionId() },
        null,
      ),
    ).rejects.toThrow("stop-after-createAgentSession");
  }
  // Pi returns a session on its own first model when it cannot restore the
  // one the session ended on; the launch's model must replace it.
  async function resumeFallback(
    session: Record<string, unknown>,
    modelFallbackMessage?: string,
  ) {
    seen.result = { session, modelFallbackMessage };
    const notices: string[] = [];
    const ctx = { ...context(), err: (line: string) => notices.push(line) };
    const dir = sessionDir();
    const first = SessionManager.create(process.cwd(), dir);
    first.appendMessage({ role: "user", content: "hi", timestamp: 1 });
    await startGoverned(
      ctx as unknown as LaunchContext,
      prepared(),
      { sessionDir: dir, newSession: false, resume: first.getSessionId() },
      null,
    ).catch(() => {});
    return notices;
  }

  it("leaves the model to the session, so Pi restores the one it ended on", async () => {
    await resume();
    expect(seen.session).not.toHaveProperty("model");
  });

  it("starts on the model the user's preference names", async () => {
    const base = prepared() as unknown as { activated: Record<string, unknown> };
    const dir = sessionDir();
    const first = SessionManager.create(process.cwd(), dir);
    first.appendMessage({ role: "user", content: "hi", timestamp: 1 });
    base.activated.config = {
      values: { model: "anthropic/claude-sonnet-4-5" },
      entries: [{ key: "model", source: "user-preference" }],
    };
    await expect(
      startGoverned(
        context(),
        base as unknown as PreparedAccess,
        { sessionDir: dir, newSession: false, resume: first.getSessionId() },
        null,
      ),
    ).rejects.toThrow("stop-after-createAgentSession");
    expect(seen.session).toHaveProperty("model");
  });

  it("starts on the model --model names", async () => {
    await resume("anthropic/claude-sonnet-4-5");
    expect(seen.session).toHaveProperty("model");
  });

  it("switches to the launch model when Pi could not restore the session's", async () => {
    const setModel = vi.fn(async () => {});
    const notices = await resumeFallback(
      { model: { provider: "x", id: "y" }, setModel, setThinkingLevel() {} },
      "Could not restore model openai/gone. Using x/y",
    );
    expect(setModel).toHaveBeenCalledWith(
      expect.objectContaining({ id: "claude-sonnet-4-5" }),
    );
    expect(notices.join("\n")).toContain("could not be restored");
  });

  it("sets the launch model when the resumed session has none", async () => {
    const setModel = vi.fn(async () => {});
    await resumeFallback(
      { model: undefined, setModel, setThinkingLevel() {} },
      "No models available",
    );
    expect(setModel).toHaveBeenCalledOnce();
  });

  it("prints Pi's fallback message when the launch model cannot be set", async () => {
    const setModel = vi.fn(async () => {
      throw new Error("No API key");
    });
    const notices = await resumeFallback(
      { model: { provider: "x", id: "y" }, setModel, setThinkingLevel() {} },
      "Could not restore model openai/gone. Using x/y",
    );
    expect(notices.join("\n")).toContain("Could not restore model openai/gone");
  });

  it("leaves the session alone when its model was restored", async () => {
    const setModel = vi.fn(async () => {});
    await resumeFallback({
      model: { provider: "openai", id: "gpt-4o" },
      setModel,
      setThinkingLevel() {},
    });
    expect(setModel).not.toHaveBeenCalled();
  });
});
