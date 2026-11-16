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
