import { describe, expect, it } from "vitest";
import { formatSmokeSummary } from "./summary.js";

const smoke = {
  initialized: true,
  piVersion: "0.87.1",
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
    expect(text).toContain("0.87.1, new acceptance session abc");
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
