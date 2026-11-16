import { describe, expect, it } from "vitest";
import type { DoctorData } from "./data.js";
import { resourcesGroup } from "./resources.js";

function lines(resources: unknown[]): string[] {
  const out: string[] = [];
  const add = (status: string) => (label: string, value: string) =>
    out.push(`${status} ${label}: ${value}`);
  resourcesGroup(
    { governance: { inspection: { resources } } } as unknown as DoctorData,
    { ok: add("ok"), warn: add("warn"), bad: add("fail"), info: add("info") },
  );
  return out;
}

describe("doctor Resources group", () => {
  it("warns about a resource that policy asks about instead of showing it as loaded", () => {
    expect(
      lines([
        {
          kind: "skills",
          class: "company",
          path: "./resources/skills",
          loaded: true,
          asks: true,
          reason: "No rule matched; the policy default is ask",
        },
        {
          kind: "instructions",
          class: "company",
          path: "./resources/AGENTS.md",
          loaded: true,
          reason: "allowed",
        },
      ]),
    ).toEqual([
      "warn company skills: ./resources/skills: asks at each launch and is left out of headless runs (No rule matched; the policy default is ask); a policy.defaults allow for skill.load company:** loads it without a prompt",
      "ok company instructions: ./resources/AGENTS.md",
    ]);
  });
});
