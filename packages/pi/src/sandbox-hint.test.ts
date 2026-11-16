import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { GovernanceSession } from "./governance-session.js";
import { governedBashOperations } from "./governed-tools.js";
import { manifestChange, SandboxFailureScanner } from "./sandbox-hint.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

function profile(network: "deny" | "allow" = "deny") {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "piship-hint-")));
  dirs.push(root);
  return {
    workspace: join(root, "ws"),
    readDeny: [join(root, "home", ".docker")],
    writeAllow: [join(root, "ws"), join(root, "tmp")],
    network,
    root,
  };
}

function hintFor(
  output: string,
  mode: "managed" | "personal" = "managed",
  network: "deny" | "allow" = "deny",
) {
  const p = profile(network);
  const scanner = new SandboxFailureScanner({ profile: p, mode });
  scanner.feed(output.replaceAll("<root>", p.root));
  return scanner.hint();
}

describe("manifestChange", () => {
  it("names the owner of a managed distribution and the user of a personal one", () => {
    expect(manifestChange("managed", "sandbox.network.mode")).toBe(
      "Ask the distribution owner to change sandbox.network.mode.",
    );
    expect(manifestChange("personal", "sandbox.network.mode")).toBe(
      "Change sandbox.network.mode in your piship.yaml.",
    );
  });
});

// Native Windows has no sandbox adapter, so the hint is never produced there.
describe.skipIf(process.platform === "win32")("SandboxFailureScanner", () => {
  it("names the read-only path and the manifest key", () => {
    const hint = hintFor(
      "npm error EROFS: read-only file system, mkdir '<root>/home/.npm/_cacache'\n",
    );
    expect(hint).toContain("home/.npm/_cacache");
    expect(hint).toContain("sandbox.filesystem.write.allow");
    expect(hint).toContain("distribution owner");
  });

  it("names a protected git control path instead of suggesting a wider write allowlist", () => {
    const p = profile();
    const scanner = new SandboxFailureScanner({
      profile: {
        ...p,
        writeProtect: {
          files: [join(p.workspace, ".git", "config")],
          directories: [join(p.workspace, ".git", "worktrees")],
        },
      },
      mode: "personal",
    });
    scanner.feed(
      `fatal: could not create directory '${p.workspace}/.git/worktrees/w': Permission denied\n`,
    );
    const hint = scanner.hint();
    expect(hint).toContain("protected git control path");
    // Names who can run it; the model cannot leave the sandbox.
    expect(hint).toContain(
      "The user can run this command in their own terminal",
    );
    expect(hint).not.toContain("write.allow");
  });

  it("tells a personal user to edit their own piship.yaml", () => {
    expect(
      hintFor(
        "mkdir: cannot create directory '<root>/x': Read-only file system\n",
        "personal",
      ),
    ).toContain("in your piship.yaml");
  });

  it("names a hidden path with the read.deny key", () => {
    const hint = hintFor(
      "docker: EACCES: permission denied, open '<root>/home/.docker/config.json'\n",
    );
    expect(hint).toContain("sandbox.filesystem.read.deny");
  });

  it("names the host of a lookup that failed under network deny", () => {
    const hint = hintFor(
      "npm error code ENOTFOUND\nnpm error getaddrinfo ENOTFOUND registry.npmjs.org\n",
    );
    expect(hint).toContain("registry.npmjs.org");
    expect(hint).toContain("sandbox.network.mode");
  });

  it("stays quiet when the network is allowed or the path is writable", () => {
    expect(
      hintFor("getaddrinfo ENOTFOUND registry.npmjs.org\n", "managed", "allow"),
    ).toBeUndefined();
    expect(
      hintFor("EACCES: permission denied, open '<root>/ws/file'\n"),
    ).toBeUndefined();
    expect(hintFor("all good\n")).toBeUndefined();
  });

  it("names the network denial for a network command that printed nothing", () => {
    const silent = (command: string, network: "deny" | "allow" = "deny") =>
      new SandboxFailureScanner({
        profile: profile(network),
        mode: "personal",
        command,
      }).hint();
    for (const command of [
      "curl -s https://example.com",
      "cd app && wget -q http://example.com/x",
      "git fetch origin",
      "node fetch.js https://api.example.com",
    ])
      expect(silent(command), command).toMatch(
        /^\[PiShip sandbox: shell commands have no network access, so a command that needs the network fails here even when it was approved\. Change sandbox\.network\.mode in your piship\.yaml\./,
      );
    expect(silent("npm test")).toBeUndefined();
    expect(silent("make curlish")).toBeUndefined();
    expect(silent("curl -s https://example.com", "allow")).toBeUndefined();
  });

  it("names the denied path, not the shell, and resolves a relative path against the command's directory", () => {
    const p = profile();
    const scanner = (cwd = p.workspace) =>
      new SandboxFailureScanner({
        profile: {
          ...p,
          writeProtect: {
            files: [join(p.workspace, ".git", "config")],
            directories: [join(p.workspace, ".git", "hooks")],
          },
        },
        mode: "personal",
        cwd,
      });
    const hint = (line: string, cwd?: string) => {
      const s = scanner(cwd);
      s.feed(`${line.replaceAll("<root>", p.root)}\n`);
      return s.hint();
    };
    // What macOS Seatbelt prints for `echo x > ~/x` under /bin/bash.
    expect(hint("/bin/bash: <root>/home/x: Operation not permitted")).toContain(
      `${p.root}/home/x is outside`,
    );
    for (const line of [
      "/bin/bash: .git/config: Operation not permitted",
      "touch: .git/hooks/pre-commit: Operation not permitted",
      "error: could not write config file .git/config: Operation not permitted",
      "Error: EPERM: operation not permitted, open '.git/hooks/a'",
    ])
      expect(hint(line), line).toContain("protected git control path");
    expect(hint("cp: ../h: Operation not permitted")).toContain(
      "../h is outside the directories shell commands can write",
    );
    // The same relative path from a writable directory is not a denial.
    expect(
      hint("cp: ../h: Operation not permitted", join(p.root, "tmp", "a")),
    ).toBeUndefined();
  });

  it("names the host of a connection the sandbox refused", () => {
    expect(hintFor("connect EPERM 1.1.1.1:443 - Local (0.0.0.0:0)\n")).toMatch(
      /^\[PiShip sandbox: 1\.1\.1\.1 cannot be reached because shell commands have no network access/,
    );
    expect(
      hintFor(
        "ssh: connect to host github.com port 22: Operation not permitted\n",
      ),
    ).toContain("github.com cannot be reached");
    expect(
      hintFor("connect ENETUNREACH 10.0.0.1:80\n", "managed", "allow"),
    ).toBeUndefined();
  });

  it("finds an error split across chunks", () => {
    const p = profile();
    const scanner = new SandboxFailureScanner({ profile: p, mode: "managed" });
    scanner.feed("EROFS: read-only file sys");
    scanner.feed(`tem, mkdir '${p.root}/home/.npm'\n`);
    expect(scanner.hint()).toContain("home/.npm");
  });
});

describe.skipIf(process.platform === "win32")(
  "governed shell command in an enforced sandbox",
  () => {
    function session(exitCode: number, text: string) {
      const p = profile();
      return {
        workflowMode: null,
        currentChannel: () => undefined,
        decide: async () => ({ outcome: "allow" }),
        options: { lock: { deployment: { mode: "managed" } } },
        sandbox: {
          report: { level: "enforced" },
          profile: p,
          exec: async (
            _command: string,
            _cwd: string,
            options: { onData: (data: Buffer) => void },
          ) => {
            options.onData(Buffer.from(text.replaceAll("<root>", p.root)));
            return { exitCode };
          },
        },
      } as unknown as GovernanceSession;
    }

    async function runCommand(
      exitCode: number,
      text: string,
      source: "bash" | "user-bash" = "bash",
      command = "npm install",
    ) {
      let output = "";
      await governedBashOperations(session(exitCode, text), source).exec(
        command,
        "/",
        {
          onData: (data) => {
            output += data.toString();
          },
        },
      );
      return output;
    }

    it("appends one hint line after a failed command", async () => {
      const output = await runCommand(
        1,
        "npm error EROFS: read-only file system, mkdir '<root>/home/.npm'\n",
      );
      expect(output).toMatch(
        /\[PiShip sandbox: .*sandbox\.filesystem\.write\.allow/,
      );
      expect(output.match(/PiShip sandbox/g)).toHaveLength(1);
    });

    it("tells the model not to retry, and leaves that out for the user's own ! command", async () => {
      const model = await runCommand(
        6,
        "",
        "bash",
        "curl -s https://example.com",
      );
      expect(model).toContain("Do not retry it or work around the sandbox");
      const user = await runCommand(
        6,
        "",
        "user-bash",
        "curl -s https://example.com",
      );
      expect(user).toContain("shell commands have no network access");
      expect(user).not.toContain("Do not retry");
    });

    it("shows the user's own ! command as theirs in the prompt", async () => {
      const prompts: string[] = [];
      for (const source of ["bash", "user-bash"] as const) {
        const gov = session(0, "");
        (gov as unknown as { decide: unknown }).decide = async (
          _action: string,
          _resource: string,
          _channel: unknown,
          events: { prompt: string },
        ) => {
          prompts.push(events.prompt);
          return { outcome: "allow" };
        };
        await governedBashOperations(gov, source).exec("ls", "/", {
          onData: () => {},
        });
      }
      expect(prompts).toEqual(["bash: ls", "your own ! command: ls"]);
    });

    it("adds nothing when the command succeeded", async () => {
      const output = await runCommand(
        0,
        "warn: EROFS: read-only file system, mkdir '<root>/home/.npm'\n",
      );
      expect(output).not.toContain("PiShip sandbox");
    });
  },
);
