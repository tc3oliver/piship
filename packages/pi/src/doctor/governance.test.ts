import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DoctorData } from "./data.js";
import { governanceGroup } from "./governance.js";

vi.mock("@piship/core", async (original) => ({
  ...(await original<typeof import("@piship/core")>()),
  inspectAgentFiles: () => [
    {
      package: "pi-permission-system",
      path: "extensions/pi-permission-system/config.json",
      mode: "seed",
      state: "edited",
    },
  ],
  packageEnvironment: () => [],
}));

let agentDir: string | undefined;
afterEach(() => {
  if (agentDir) rmSync(agentDir, { recursive: true, force: true });
});

function seedLine(content: string): string | undefined {
  agentDir = mkdtempSync(join(tmpdir(), "piship-doctor-seed-"));
  mkdirSync(join(agentDir, "extensions", "pi-permission-system"), {
    recursive: true,
  });
  writeFileSync(
    join(agentDir, "extensions", "pi-permission-system", "config.json"),
    content,
  );
  const out: string[] = [];
  const add = (status: string) => (label: string, value: string) =>
    out.push(`${status} ${label}: ${value}`);
  governanceGroup(
    {
      ctx: {
        agentDir,
        distributionDir: agentDir,
        stateDir: agentDir,
        metadata: {
          manifest: { schema: "piship/v1" },
          packages: [
            {
              id: "pi-permission-system",
              source: "npm",
              class: "company",
              files: 1,
            },
          ],
        },
      },
    } as unknown as DoctorData,
    { ok: add("ok"), warn: add("warn"), bad: add("fail"), info: add("info") },
  );
  return out.find((line) => line.includes("seed file"));
}

describe("doctor Governance agent files", () => {
  it("keeps an edited seed that still parses as info", () => {
    expect(seedLine('{"defaultPolicy":{}}')).toMatch(
      /^info .*edited by the user and kept/,
    );
  });

  it("warns that an edited seed that no longer parses is ignored", () => {
    expect(seedLine("{ not json")).toMatch(
      /^warn .*no longer valid JSON, so pi-permission-system cannot read it.*delete it to restore the declared default/,
    );
  });
});
