// The launch pi-code's subagent tool uses for its children: accepted only
// under the parent's marker, by allowlist, and never as a way past a control.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync as realpath,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PiShipError } from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { preparePiEnvironment } from "../environment.js";
import { launchPiDistribution, PINNED_PI_VERSION } from "../index.js";
import { isSubagentChild, parseSubagentChild } from "./subagent-child.js";

const ENV = { PI_CODE_SUBAGENT: "1" } as NodeJS.ProcessEnv;
const BASE = ["--mode", "json", "-p", "--no-session"];
const parse = (rest: string[], env = ENV, base = BASE) =>
  parseSubagentChild([...base, ...rest], env);
// A background run has a session of its own instead of --no-session.
const BG = ["--mode", "json", "-p"];
const refused = (rest: string[], env = ENV, base = BASE): PiShipError => {
  try {
    parse(rest, env, base);
  } catch (error) {
    return error as PiShipError;
  }
  throw new Error("expected a refusal");
};

let dirs: string[] = [];
const temp = (prefix: string) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
};
afterEach(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  dirs = [];
});

describe("which arguments are a subagent child's", () => {
  it("needs the parent's marker and the leading --mode json -p", () => {
    expect(isSubagentChild(BASE, ENV)).toBe(true);
    expect(isSubagentChild(BASE, {})).toBe(false);
    expect(isSubagentChild(BASE, { PI_CODE_SUBAGENT: "0" })).toBe(false);
    expect(isSubagentChild(BASE, { PI_CODE_SUBAGENT: "true" })).toBe(false);
    expect(isSubagentChild(["-p", "hi"], ENV)).toBe(false);
    expect(isSubagentChild(["--yolo", ...BASE], ENV)).toBe(false);
    expect(isSubagentChild(["--mode", "rpc", "-p"], ENV)).toBe(false);
  });

  it("refuses to parse without the marker", () => {
    expect(refused(["Task: x"], {}).code).toBe("CONFIG_INVALID");
  });
});

describe("the options pi-code passes", () => {
  it("takes the task as the last argument", () => {
    expect(parse(["Task: list files"])).toEqual({ prompt: "Task: list files" });
  });

  it("takes the model, thinking, tools, and exclusions", () => {
    expect(
      parse([
        "--model",
        "gpt-x",
        "--thinking",
        "low",
        "--tools",
        "read,grep",
        "--exclude-tools",
        "bash",
        "--no-context-files",
        "Task: x",
      ]),
    ).toEqual({
      prompt: "Task: x",
      model: "gpt-x",
      thinking: "low",
      tools: ["read", "grep"],
      excludeTools: ["bash"],
    });
  });

  it("reads pi's :level suffix on the model, an explicit --thinking first", () => {
    expect(parse(["--model", "acme/m:high", "t"])).toMatchObject({
      model: "acme/m",
      thinking: "high",
    });
    expect(
      parse(["--model", "m:high", "--thinking", "low", "t"]),
    ).toMatchObject({ model: "m", thinking: "low" });
    // not a level: part of the id
    expect(parse(["--model", "ns:tag", "t"])).toMatchObject({
      model: "ns:tag",
    });
  });

  it("keeps a task that looks like an option as the task", () => {
    expect(parse(["--yolo"]).prompt).toBe("--yolo");
  });

  it("reads the system prompt from pi-code's own temporary file", () => {
    const dir = temp("pi-subagent-");
    const file = join(dir, "prompt-Explore.md");
    writeFileSync(file, "You are a scout.");
    expect(parse(["--system-prompt", file, "t"]).systemPrompt).toBe(
      "You are a scout.",
    );
  });

  it("reads a background session in pi-code's own temporary directory", () => {
    const dir = temp("pi-code-bg-session-");
    const id = "pi-code-bg-0123abcd-4567cdef";
    expect(
      parse(["--session-id", id, "--session-dir", dir, "t"], ENV, BG).session,
    ).toEqual({
      id,
      dir: realpath(dir),
    });
  });
});

describe("what a child cannot ask for", () => {
  it.each([
    "--yolo",
    "--new-session",
    "--api-key",
    "--provider",
    "--extension",
    "--skill",
    "--no-extensions",
    "--session",
    "--continue",
    "--fork",
    "--mode",
    "--print",
    "-p",
    "--login",
    "--offline",
    "--allow-all",
    "--dangerously-skip-permissions",
    "--append-system-prompt",
    "--settings",
    "--setting-sources",
    "--no-sandbox",
    "--no-tools",
    "login",
    "@/etc/passwd",
  ])("refuses %s by name", (flag) => {
    const error = refused([flag, "value", "Task: secret-canary"]);
    expect(error.code).toBe("CONFIG_INVALID");
    expect(error.message).toContain("not available to a subagent child");
    expect(JSON.stringify([error.message, error.userAction])).not.toContain(
      "secret-canary",
    );
  });

  it("refuses a missing task, a missing value, and a repeated option", () => {
    expect(refused([]).message).toContain("needs a task prompt");
    expect(refused(["--model", "m"]).message).toContain("needs a value");
    expect(refused(["--model"]).message).toContain("task prompt");
    expect(refused(["--model", "a", "--model", "b", "t"]).message).toContain(
      "given twice",
    );
    expect(refused(["--thinking", "extreme", "t"]).message).toContain(
      "--thinking",
    );
  });

  it("refuses a system prompt file anywhere but pi-code's temporary one", () => {
    const outside = temp("not-pi-code-");
    const file = join(outside, "prompt-x.md");
    writeFileSync(file, "x");
    for (const path of [file, "/etc/passwd", join(outside, "missing.md")])
      expect(refused(["--system-prompt", path, "t"]).message).toContain(
        "system prompt file",
      );
    // a link from the right place to the wrong one is followed, then refused
    const dir = temp("pi-subagent-");
    const link = join(dir, "prompt-link.md");
    symlinkSync("/etc/passwd", link);
    expect(refused(["--system-prompt", link, "t"]).message).toContain(
      "system prompt file",
    );
    // a directory of the right name in the wrong place
    const nested = join(outside, "pi-subagent-abc");
    mkdirSync(nested);
    writeFileSync(join(nested, "prompt-x.md"), "x");
    expect(
      refused(["--system-prompt", join(nested, "prompt-x.md"), "t"]).message,
    ).toContain("system prompt file");
  });

  it("refuses a session outside pi-code's temporary directory", () => {
    const id = "pi-code-bg-0123abcd-4567cdef";
    const outside = temp("not-pi-code-");
    const dir = temp("pi-code-bg-session-");
    const bad = (rest: string[]) => refused([...rest, "t"], ENV, BG).message;
    expect(bad(["--session-id", id, "--session-dir", outside])).toContain(
      "session directory",
    );
    expect(bad(["--session-id", id, "--session-dir", "/etc"])).toContain(
      "session directory",
    );
    expect(bad(["--session-id", "../x", "--session-dir", dir])).toContain(
      "session id",
    );
    expect(bad(["--session-id", id])).toContain("go together");
    expect(bad(["--session-dir", dir])).toContain("go together");
    expect(
      refused(["--session-id", id, "--session-dir", dir, "t"]).message,
    ).toContain("cannot both");
  });
});

// The whole launch: the options are checked before any state exists, and a
// launch without the marker is exactly what it was.
describe("the launch", () => {
  let state: string;
  const saved = {
    home: process.env.PISHIP_STATE_HOME,
    agentDir: process.env.PI_CODING_AGENT_DIR,
    marker: process.env.PI_CODE_SUBAGENT,
  };
  beforeEach(() => {
    state = temp("piship-subagent-launch-");
    process.env.PISHIP_STATE_HOME = state;
  });
  afterEach(() => {
    for (const [name, value] of [
      ["PISHIP_STATE_HOME", saved.home],
      ["PI_CODING_AGENT_DIR", saved.agentDir],
      ["PI_CODE_SUBAGENT", saved.marker],
    ] as const)
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
  });
  const metadata = {
    app: {
      id: "acmecode",
      command: "acmecode",
      name: "AcmeCode",
      version: "1",
    },
    runtime: {
      package: "@earendil-works/pi-coding-agent",
      version: PINNED_PI_VERSION,
      pishipVersion: "1.0.0",
    },
    deployment: { mode: "managed" },
  } as unknown as DistributionLock;
  const launch = (args: string[]) => {
    preparePiEnvironment("acmecode");
    return launchPiDistribution({ distributionDir: state, metadata, args });
  };
  const failure = (args: string[]) =>
    launch(args).then(
      () => undefined,
      (error: unknown) => error as PiShipError,
    );

  it("is unchanged without the marker: the same error as before", async () => {
    delete process.env.PI_CODE_SUBAGENT;
    const error = await failure([...BASE, "--model", "m", "Task: x"]);
    expect(error?.message).toMatch(
      /^Unknown branded command option: --mode json/,
    );
    expect(error?.message).toContain("no non-interactive prompt mode");
  });

  it("is unchanged under the marker when the arguments are not a child's", async () => {
    process.env.PI_CODE_SUBAGENT = "1";
    const error = await failure(["-p", "hi"]);
    expect(error?.message).toMatch(/^Unknown branded command option: -p hi/);
  });

  it("refuses an option outside the allowlist before any state exists", async () => {
    process.env.PI_CODE_SUBAGENT = "1";
    for (const flag of ["--yolo", "--api-key", "--extension"]) {
      const error = await failure([...BASE, flag, "x", "Task: canary-task"]);
      expect(error?.code).toBe("CONFIG_INVALID");
      expect(error?.message).toContain(flag);
      expect(error?.message).not.toContain("canary-task");
      expect(existsSync(join(state, "acmecode"))).toBe(false);
    }
  });
});
