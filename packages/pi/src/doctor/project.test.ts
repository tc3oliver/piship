import { describe, expect, it } from "vitest";
import type { DoctorData } from "./data.js";
import { projectGroup } from "./project.js";

function lines(extensionTrust: unknown): string[] {
  const out: string[] = [];
  const add = (status: string) => (label: string, value: string) =>
    out.push(`${status} ${label}: ${value}`);
  projectGroup(
    {
      ctx: { mode: "managed" },
      governance: {
        inspection: {
          project: { origin: "unknown", root: "/work" },
          resources: [],
          candidates: [],
          extensionTrust,
        },
      },
    } as unknown as DoctorData,
    { ok: add("ok"), warn: add("warn"), bad: add("fail"), info: add("info") },
  );
  return out.filter((line) => line.includes("project trust"));
}

describe("doctor Project group", () => {
  it("shows the managed default for a project with nothing to load as info", () => {
    expect(
      lines({
        effect: "deny",
        reason: "no Claude Code configuration was found, but ...",
        surfaces: [],
      }),
    ).toEqual([
      "info project trust for extensions: not trusted (unknown project; nothing to load here)",
    ]);
  });

  it("still warns when configuration it found is not trusted", () => {
    expect(
      lines({
        effect: "deny",
        reason: "policy denies hooks",
        surfaces: [{ path: ".claude/hooks" }],
      })[0],
    ).toMatch(/^warn project trust for extensions: not trusted for/);
  });
});

describe("doctor Project items", () => {
  function items(
    candidate: Record<string, unknown>,
    decision?: Record<string, unknown>,
  ): string[] {
    const out: string[] = [];
    const add = (status: string) => (label: string, value: string) =>
      out.push(`${status} ${label}: ${value}`);
    projectGroup(
      {
        ctx: { mode: "managed" },
        governance: {
          inspection: {
            project: { origin: "company", root: "/work" },
            resources: [],
            candidates: [candidate],
            projectDecisions: new Map(
              decision ? [[candidate.path as string, decision]] : [],
            ),
          },
        },
      } as unknown as DoctorData,
      { ok: add("ok"), warn: add("warn"), bad: add("fail"), info: add("info") },
    );
    return out.filter((line) => line.includes("/work/AGENTS.md"));
  }
  const agents = {
    dimension: "instructions",
    kind: "instructions",
    path: "/work/AGENTS.md",
    origin: "company",
    effect: "allow",
    reason: "Project trust for company projects allows instructions",
  };

  it("warns when trust admits an item that policy still asks about", () => {
    const [line] = items(agents, {
      effect: "ask",
      action: "instruction.load",
      ruleId: "builtin:default",
      reason: "No rule matched; the policy default is ask",
    });
    expect(line).toBe(
      "warn instructions: /work/AGENTS.md: asks at each launch and is left out of headless runs (No rule matched; the policy default is ask); a policy.defaults allow for instruction.load project:** loads it without a prompt",
    );
  });

  it("stays ok when policy allows it", () => {
    expect(
      items(agents, {
        effect: "allow",
        action: "instruction.load",
        ruleId: "corp.text",
      })[0],
    ).toMatch(/^ok instructions: \/work\/AGENTS.md: allow/);
  });

  it("tells a managed user who sets a project trust deny", () => {
    expect(
      items({
        ...agents,
        origin: "unknown",
        effect: "deny",
        reason: "Project trust for unknown projects denies instructions",
      })[0],
    ).toMatch(
      /^warn instructions: .*denies instructions\); your administrator sets this \(policy\.projectTrust\.unknown\.instructions in piship\.yaml\)$/,
    );
  });
});
