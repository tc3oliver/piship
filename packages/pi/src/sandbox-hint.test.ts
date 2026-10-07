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

    async function runCommand(exitCode: number, text: string) {
      let output = "";
      await governedBashOperations(session(exitCode, text), "bash").exec(
        "npm install",
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

    it("adds nothing when the command succeeded", async () => {
      const output = await runCommand(
        0,
        "warn: EROFS: read-only file system, mkdir '<root>/home/.npm'\n",
      );
      expect(output).not.toContain("PiShip sandbox");
    });
  },
);
