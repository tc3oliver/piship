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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const seen = vi.hoisted(() => ({
  session: undefined as Record<string, unknown> | undefined,
  access: [] as unknown[][],
}));
vi.mock("@earendil-works/pi-coding-agent", async (original) => ({
  ...(await original<typeof import("@earendil-works/pi-coding-agent")>()),
  createAgentSession: async (options: Record<string, unknown>) => {
    seen.session = options;
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
    expect(seen.access).toEqual([[ctx, "acme/m"]]);
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
