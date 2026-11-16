import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { DistributionLock } from "./lock-schema.js";
import {
  formatInspection,
  formatSmokeSummary,
  inspection,
  pathHint,
} from "./summary.js";

const smoke = {
  initialized: true,
  piVersion: "1.5.0",
  sessionId: "abc",
  resumed: false,
  safeTool: "read",
  agentDir: "/state/agent",
  instructions: ["/payload/AGENTS.md"],
  skills: ["review"],
  extensions: 2,
  extensionPaths: ["/payload/a.ts", "/payload/b.ts"],
  prompts: [],
  themes: [],
  access: { selectedModel: "acme/coder" },
  governance: {
    policy: "acme",
    project: { origin: "unknown" },
    sandbox: { level: "os" },
    audit: "healthy",
    resources: [{ loaded: true }, { loaded: false }],
    mcp: [{ id: "notes", state: "healthy" }],
  },
};

describe("formatSmokeSummary", () => {
  it("turns the smoke JSON into a few readable lines", () => {
    const text = formatSmokeSummary(JSON.stringify(smoke));
    expect(text).not.toContain("{");
    expect(text).not.toContain("/state/agent");
    expect(text).toContain("1.5.0, new acceptance session abc");
    expect(text).toMatch(/resources\s+instructions 1: AGENTS\.md\n/);
    expect(text).toContain("skills 1: review");
    expect(text).toContain("extensions 2: a.ts, b.ts");
    expect(text).not.toContain("prompts");
    expect(text).toMatch(/model\s+acme\/coder/);
    expect(text).toContain(
      "policy acme, project unknown, sandbox os, audit healthy, 1 resource(s) not loaded",
    );
    expect(text).toMatch(/mcp\s+notes healthy/);
  });

  it("names instructions by declared path or from the working directory", () => {
    const dist = join(tmpdir(), "dist", "mypi");
    const text = formatSmokeSummary(
      JSON.stringify({
        ...smoke,
        distributionDir: dist,
        instructions: [
          join(dist, "resources", "resources", "AGENTS.md"),
          join(process.cwd(), "AGENTS.md"),
          join(process.cwd(), "docs", "AGENTS.md"),
        ],
      }),
    );
    expect(text).toContain(
      "instructions 3: resources/AGENTS.md, AGENTS.md, docs/AGENTS.md",
    );
  });

  it("names extensions from their folder, caps long lists, and lists packages", () => {
    const text = formatSmokeSummary(
      JSON.stringify({
        ...smoke,
        skills: ["a", "b", "c", "d", "e", "f", "g"],
        extensionPaths: [
          "/dist/x/resources/resources/extensions/clock/index.ts",
          "C:\\dist\\x\\resources\\extensions\\bad.ts",
        ],
        packages: ["pi-web@1.2.0", "tools@abc1234"],
      }),
    );
    expect(text).toContain("skills 7: a, b, c, d, e, +2 more");
    expect(text).toContain("extensions 2: clock/index.ts, bad.ts");
    expect(text).toMatch(/packages\s+pi-web@1\.2\.0, tools@abc1234/);
  });

  it("says why an MCP server failed, on one line", () => {
    const text = formatSmokeSummary(
      JSON.stringify({
        ...smoke,
        governance: {
          ...smoke.governance,
          mcp: [
            { id: "notes", state: "healthy" },
            {
              id: "clock",
              state: "failed",
              reason: `spawn clock-mcp ENOENT\n  at x\n${"y".repeat(300)}`,
            },
          ],
        },
      }),
    );
    expect(text).toMatch(
      /mcp\s+notes healthy\n\s+clock failed: spawn clock-mcp ENOENT at x y+\.\.\.$/,
    );
    expect(text.split("\n").at(-1)?.length).toBeLessThan(200);
  });

  it("names the bundled search tools Pi's find and grep used", () => {
    expect(formatSmokeSummary(JSON.stringify(smoke))).not.toContain(
      "  search ",
    );
    expect(
      formatSmokeSummary(
        JSON.stringify({
          ...smoke,
          searchTools: { fd: "10.5.0", rg: "15.2.0" },
        }),
      ),
    ).toMatch(/search\s+fd 10\.5\.0, rg 15\.2\.0 bundled/);
  });

  it("returns output that is not JSON unchanged", () => {
    expect(formatSmokeSummary("not json")).toBe("not json");
  });
});

describe("formatInspection", () => {
  it("names resources by kind and lists the locked Pi packages", () => {
    const lock = {
      app: { id: "a", name: "A", version: "1.0.0", command: "a" },
      deployment: { mode: "personal" },
      runtime: { version: "1.5.0", pishipVersion: "0.13.0" },
      resources: [
        { kind: "adapters", path: "resources/mcp/clock.mjs", sha256: "x" },
        { kind: "instructions", path: "resources/AGENTS.md", sha256: "x" },
      ],
      packages: [
        { id: "pi-web", version: "1.2.0" },
        { id: "tools", commit: "abc1234def" },
      ],
    } as unknown as DistributionLock;
    const info = inspection(lock, "/state");
    expect(info.packages).toEqual(["pi-web@1.2.0", "tools@abc1234"]);
    const text = formatInspection(info);
    expect(text).toMatch(
      /resources\s+adapters 1: resources\/mcp\/clock\.mjs\n\s+instructions 1: resources\/AGENTS\.md/,
    );
    expect(text).toMatch(/packages\s+pi-web@1\.2\.0, tools@abc1234/);
  });
});

describe("pathHint", () => {
  it("says nothing when the directory is on PATH", () => {
    expect(
      pathHint(
        "/home/a/.local/bin",
        { PATH: "/usr/bin:/home/a/.local/bin/" },
        "linux",
      ),
    ).toBeUndefined();
    expect(
      pathHint(
        "C:\\Users\\a\\bin",
        { Path: "C:\\Windows;c:\\users\\a\\BIN" },
        "win32",
      ),
    ).toBeUndefined();
    // The same folder written with forward slashes.
    expect(
      pathHint(
        "C:/Users/a/bin",
        { Path: "C:\\Windows;C:\\Users\\a\\bin\\" },
        "win32",
      ),
    ).toBeUndefined();
  });

  it("escapes a Windows path for a PowerShell string and names the shell to use", () => {
    const hint = pathHint(
      "C:\\Users\\a$b\\bin",
      { Path: "C:\\Windows" },
      "win32",
    );
    expect(hint).toContain('+ ";C:\\Users\\a`$b\\bin", "User")');
    expect(hint).toContain("type powershell first in cmd.exe");
  });

  it("prints an executable line for the user's shell", () => {
    const zsh = pathHint(
      "/home/a/my bin",
      { PATH: "/usr/bin", SHELL: "/bin/zsh" },
      "darwin",
    );
    expect(zsh).toContain('  export PATH="/home/a/my bin:$PATH"');
    expect(zsh).toContain("~/.zshrc");
    expect(
      pathHint("/x/$bin", { PATH: "", SHELL: "/bin/bash" }, "linux"),
    ).toContain('export PATH="/x/\\$bin:$PATH"');
    expect(
      pathHint("/x", { PATH: "", SHELL: "/usr/bin/fish" }, "linux"),
    ).toContain('fish_add_path "/x"');
    expect(pathHint("C:\\bin", { Path: "C:\\Windows" }, "win32")).toContain(
      "[Environment]::SetEnvironmentVariable(",
    );
  });
});
