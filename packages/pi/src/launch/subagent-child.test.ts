// The launch pi-code's subagent tool uses for its children: accepted only
// under the parent's marker, by allowlist, and never as a way past a control.
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync as realpath,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import {
  DEFAULT_NETWORK_POLICY,
  type PiShipError,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { preparePiEnvironment } from "../environment.js";
import { launchPiDistribution, PINNED_PI_VERSION } from "../index.js";
import {
  publishSubagentOwner,
  SUBAGENT_NONCE_ENV,
  SUBAGENT_OWNER_DIRECTORY,
} from "./subagent-owner.js";
import {
  childToolOptions,
  inTemp,
  isSubagentChild,
  parseSubagentChild,
} from "./subagent-child.js";

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

  it("never prints the value of an --flag=value refusal", () => {
    const error = refused(["--api-key=sk-secret", "t"]);
    expect(error.message).toContain("--api-key is not available");
    expect(JSON.stringify([error.message, error.userAction])).not.toContain(
      "sk-secret",
    );
    expect(refused(["--token=sk-secret-2=x", "t"]).message).not.toContain(
      "sk-secret-2",
    );
  });

  it("refuses a system prompt file that is a directory, a FIFO, or too large", () => {
    const dir = temp("pi-subagent-");
    const bad = (path: string) =>
      refused(["--system-prompt", path, "t"]).message;
    const folder = join(dir, "prompt-dir.md");
    mkdirSync(folder);
    expect(bad(folder)).toContain("system prompt file");
    if (process.platform !== "win32") {
      const fifo = join(dir, "prompt-fifo.md");
      execFileSync("mkfifo", [fifo]);
      expect(bad(fifo)).toContain("system prompt file");
    }
    const big = join(dir, "prompt-big.md");
    writeFileSync(big, Buffer.alloc(1024 * 1024 + 1, "a"));
    expect(bad(big)).toContain("system prompt file");
    const limit = join(dir, "prompt-limit.md");
    writeFileSync(limit, Buffer.alloc(1024 * 1024, "a"));
    expect(parse(["--system-prompt", limit, "t"]).systemPrompt).toHaveLength(
      1024 * 1024,
    );
  });

  it("refuses a system prompt file reached through a symlinked parent directory", () => {
    const outside = temp("not-pi-code-");
    // a symlinked directory in tmp that points outside is refused
    const target = join(outside, "pi-subagent-target");
    mkdirSync(target);
    writeFileSync(join(target, "prompt-x.md"), "x");
    const link = join(tmpdir(), `pi-subagent-link${process.pid}`);
    symlinkSync(target, link);
    dirs.push(link);
    expect(
      refused(["--system-prompt", join(link, "prompt-x.md"), "t"]).message,
    ).toContain("system prompt file");
  });

  it.skipIf(process.platform === "win32")(
    "refuses a system prompt file in a directory others can change",
    () => {
      const dir = temp("pi-subagent-");
      const file = join(dir, "prompt-a.md");
      writeFileSync(file, "x");
      for (const mode of [0o770, 0o707, 0o777]) {
        chmodSync(dir, mode);
        expect(refused(["--system-prompt", file, "t"]).message).toContain(
          "system prompt file",
        );
      }
      chmodSync(dir, 0o700);
      expect(parse(["--system-prompt", file, "t"]).systemPrompt).toBe("x");
    },
  );

  it.skipIf(process.platform === "win32")(
    "opens the system prompt file without following a link swapped in after the path was resolved",
    () => {
      const dir = temp("pi-subagent-");
      const target = join(temp("not-pi-code-"), "secret.md");
      writeFileSync(target, "secret");
      // The real path, as realpath returns it: only the last component is
      // wrong, and it is what the open must not follow.
      const link = join(realpath(dir), "prompt-link.md");
      symlinkSync(target, link);
      // The race: realpath saw a regular file, and a link took its place.
      const decoy = join(dir, "prompt-decoy.md");
      const native = realpath.native;
      const spy = vi
        .spyOn(realpath, "native")
        .mockImplementation(((path: string) =>
          path === decoy ? link : native(path)) as typeof native);
      try {
        expect(refused(["--system-prompt", decoy, "t"]).message).toContain(
          "system prompt file",
        );
        expect(spy).toHaveBeenCalledWith(decoy);
      } finally {
        spy.mockRestore();
      }
    },
  );

  it("refuses a system prompt file with other hard links", () => {
    const dir = temp("pi-subagent-");
    const file = join(dir, "prompt-a.md");
    writeFileSync(file, "x");
    linkSync(file, join(dir, "prompt-b.md"));
    expect(refused(["--system-prompt", file, "t"]).message).toContain(
      "system prompt file",
    );
  });

  it("refuses a system prompt file owned by another user", () => {
    const dir = temp("pi-subagent-");
    const file = join(dir, "prompt-a.md");
    writeFileSync(file, "x");
    const uid = vi
      .spyOn(process, "getuid")
      .mockReturnValue((process.getuid?.() ?? 0) + 1);
    try {
      expect(refused(["--system-prompt", file, "t"]).message).toContain(
        "system prompt file",
      );
    } finally {
      uid.mockRestore();
    }
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

describe("the temporary directory comparison", () => {
  const pattern = /^pi-subagent-[A-Za-z0-9]+$/;
  it("compares Windows paths without case", () => {
    const tmp = "C:\\Users\\Me\\AppData\\Local\\Temp";
    const dir = "c:\\users\\me\\appdata\\local\\temp\\pi-subagent-abc";
    expect(inTemp(dir, pattern, "win32", tmp)).toBe(true);
    expect(inTemp(`${tmp}\\pi-subagent-abc`, pattern, "win32", tmp)).toBe(true);
    expect(inTemp(`${tmp}\\x\\pi-subagent-abc`, pattern, "win32", tmp)).toBe(
      false,
    );
    expect(inTemp(`${tmp}\\other-abc`, pattern, "win32", tmp)).toBe(false);
  });

  it("stays case-sensitive elsewhere", () => {
    expect(inTemp("/TMP/pi-subagent-a", pattern, "linux", "/tmp")).toBe(false);
    expect(inTemp("/tmp/pi-subagent-a", pattern, "linux", "/tmp")).toBe(true);
    expect(inTemp("/tmp/x/pi-subagent-a", pattern, "linux", "/tmp")).toBe(
      false,
    );
  });
});

describe("the tools a child adds to the session", () => {
  it("adds its exclusions after exposure's, and its allowlist with the required tools", () => {
    const child = { prompt: "t", excludeTools: ["bash"], tools: ["read"] };
    expect(childToolOptions(child, ["web"], ["ask_user"])).toEqual({
      excludeTools: ["web", "bash"],
      tools: ["read", "ask_user"],
    });
    expect(childToolOptions(undefined, ["web"], [])).toEqual({
      excludeTools: ["web"],
    });
    expect(childToolOptions(undefined, undefined, [])).toEqual({});
    expect(childToolOptions({ prompt: "t" }, [], ["ask_user"])).toEqual({
      excludeTools: [],
    });
  });

  it("refuses an exclusion of a tool the launch needs", () => {
    const child = { prompt: "t", excludeTools: ["bash", "ask_user"] };
    expect(() => childToolOptions(child, [], ["ask_user"])).toThrow(
      /--exclude-tools cannot remove ask_user/,
    );
  });
});

// A managed launch cleans the environment after the child was recognized by
// its marker, so pi-code's hooks extension never sees the marker or the hooks
// variable there. security.md says exactly this; a change must change both.
describe("the environment a managed child's extensions see", () => {
  const ambient = () =>
    ({
      PATH: "/usr/bin",
      PI_CODE_SUBAGENT: "1",
      PI_CODE_AGENT_HOOKS: '{"Stop":[{"command":"touch /tmp/x"}]}',
    }) as NodeJS.ProcessEnv;

  it("removes the marker and the agent hooks, as it removes every PI_ variable", () => {
    const env = ambient();
    const removed = sanitizeManagedEnvironment(env, DEFAULT_NETWORK_POLICY);
    expect(removed).toEqual(["PI_CODE_AGENT_HOOKS", "PI_CODE_SUBAGENT"]);
    expect(env).toEqual({ PATH: "/usr/bin" });
  });

  it("keeps them only where the manifest declares them as variables", () => {
    const env = ambient();
    sanitizeManagedEnvironment(env, DEFAULT_NETWORK_POLICY, [
      "PI_CODE_AGENT_HOOKS",
    ]);
    expect(Object.keys(env).sort()).toEqual(["PATH", "PI_CODE_AGENT_HOOKS"]);
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
      [SUBAGENT_NONCE_ENV, undefined],
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
    const error = await failure([...BASE, "--model", "m", "Task: canary-task"]);
    expect(error?.message).toMatch(
      /^Unknown branded command option: --mode json -p \.\.\.\n/,
    );
    expect(error?.message).toContain("no non-interactive prompt mode");
    // The task is the last argument and is not repeated.
    expect(error?.message).not.toContain("canary-task");
  });

  it("is unchanged under the marker when the arguments are not a child's", async () => {
    process.env.PI_CODE_SUBAGENT = "1";
    const error = await failure(["-p", "hi"]);
    expect(error?.message).toMatch(/^Unknown branded command option: -p hi/);
  });

  /** What a running session of the distribution publishes for its children. */
  const startSession = (workspace = realpath(process.cwd())) =>
    publishSubagentOwner(join(state, "acmecode"), {
      session: "parent-1",
      workspace,
    });

  it("refuses an option outside the allowlist before any state exists", async () => {
    process.env.PI_CODE_SUBAGENT = "1";
    for (const flag of ["--yolo", "--api-key", "--extension"]) {
      startSession();
      const error = await failure([...BASE, flag, "x", "Task: canary-task"]);
      expect(error?.code).toBe("CONFIG_INVALID");
      expect(error?.message).toContain(flag);
      expect(error?.message).not.toContain("canary-task");
      // Only the parent's own record: the child wrote nothing.
      expect(readdirSync(join(state, "acmecode"))).toEqual([
        SUBAGENT_OWNER_DIRECTORY,
      ]);
      expect(process.env).not.toHaveProperty(SUBAGENT_NONCE_ENV);
    }
  });

  it("refuses the marker without a running session's nonce, before any state exists", async () => {
    process.env.PI_CODE_SUBAGENT = "1";
    for (const nonce of [undefined, "d".repeat(64)]) {
      if (nonce) process.env[SUBAGENT_NONCE_ENV] = nonce;
      const error = await failure([...BASE, "Task: canary-task"]);
      expect(error?.code).toBe("CONFIG_INVALID");
      expect(error?.message).toContain("not started by a running session");
      expect(error?.message).not.toContain("canary-task");
      expect(existsSync(join(state, "acmecode"))).toBe(false);
    }
  });

  it("refuses a child whose directory is outside its parent's workspace", async () => {
    process.env.PI_CODE_SUBAGENT = "1";
    startSession(join(state, "another-project"));
    const error = await failure([...BASE, "Task: canary-task"]);
    expect(error?.code).toBe("CONFIG_INVALID");
    expect(error?.message).toContain("outside its parent's workspace");
    expect(error?.message).not.toContain("canary-task");
  });
});
