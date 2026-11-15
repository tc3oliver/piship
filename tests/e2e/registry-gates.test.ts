import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  evaluateSignatures,
  evaluateVulnerabilities,
  npmAuditScanner,
  npmSignatureAuditor,
} from "@piship/core";
import { describe, expect, it } from "vitest";
import { registryReachable } from "../helpers/fake-npm.js";

// The only E2E tests whose subject is the npm registry: the release gates'
// real calls (`npm audit`, `npm audit signatures`, `npm view`), with no fake
// npm (tests/helpers/fake-npm.ts). Every other scenario builds its releases
// against a fake, so a network outage cannot fail them. Without the registry
// these skip, with the reason; PISHIP_REQUIRE_REGISTRY=1 (portable-e2e.yml)
// fails them instead.

const repo = fileURLToPath(new URL("../../", import.meta.url));
const required = process.env.PISHIP_REQUIRE_REGISTRY === "1";
const online = registryReachable();
const unreachable =
  "the npm registry is unreachable (PISHIP_REQUIRE_REGISTRY=1 fails instead)";

// Fails fast when CI requires the registry; otherwise skips with the reason.
function needRegistry(context: {
  skip: (condition: boolean, note: string) => void;
}) {
  if (required) expect(online, "the npm registry is required").toBe(true);
  context.skip(!online, unreachable);
}

describe("release gates against the real npm registry", () => {
  it("is reachable (mandatory with PISHIP_REQUIRE_REGISTRY=1)", (context) => {
    needRegistry(context);
  });

  it("vulnerability gate: the real npm audit returns a report the policy reads", async (context) => {
    needRegistry(context);
    const report = evaluateVulnerabilities(
      await npmAuditScanner(repo),
      { failOn: "critical", allow: [] },
      new Date(),
    );
    expect(report.scanner).toBe("npm audit --omit=dev");
  }, 300_000);

  it("signature gate: the real npm audit signatures finds no invalid signature", async (context) => {
    needRegistry(context);
    const report = evaluateSignatures(await npmSignatureAuditor(repo));
    expect(report.verdict).toBe("passed");
  }, 300_000);

  it("package resolution: the real npm view resolves a published version", (context) => {
    needRegistry(context);
    const view = spawnSync(
      "npm",
      ["view", "pi-code@1.4.2", "version", "--json"],
      { encoding: "utf8", shell: process.platform === "win32" },
    );
    expect(view.status, view.stderr).toBe(0);
    expect(JSON.parse(view.stdout)).toBe("1.4.2");
  }, 120_000);
});
