import { describe, expect, it } from "vitest";
import { formatSmokeSummary, pathHint } from "./summary.js";

const smoke = {
  initialized: true,
  piVersion: "1.0.2",
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
    expect(text).toContain("1.0.2, new acceptance session abc");
    expect(text).toContain(
      "instructions 1, skills 1, extensions 2, prompts 0, themes 0",
    );
    expect(text).toMatch(/model\s+acme\/coder/);
    expect(text).toContain(
      "policy acme, project unknown, sandbox os, audit healthy, 1 resource(s) not loaded",
    );
    expect(text).toMatch(/mcp\s+notes healthy/);
  });

  it("returns output that is not JSON unchanged", () => {
    expect(formatSmokeSummary("not json")).toBe("not json");
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
