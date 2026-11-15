import { spawnSync } from "node:child_process";
import { delimiter } from "node:path";
import { describe, expect, it } from "vitest";
import {
  evaluateSignatures,
  evaluateVulnerabilities,
  npmAuditScanner,
  npmSignatureAuditor,
} from "@piship/core";
import { fakeNpmDirectory, withFakeNpm } from "./fake-npm.js";

const env = () => withFakeNpm({ ...process.env, PISHIP_REQUIRE_REGISTRY: "" });
const npm = (...args: string[]) =>
  spawnSync("npm", args, {
    encoding: "utf8",
    env: env(),
    shell: process.platform === "win32",
  });

describe("the fake npm of the E2E harness", () => {
  it("answers exactly the audit forms the release gates run", () => {
    const audit = npm("audit", "--omit=dev", "--json");
    expect(audit.status).toBe(0);
    expect(
      evaluateVulnerabilities(
        JSON.parse(audit.stdout),
        { failOn: "high", allow: [] },
        new Date(),
      ).verdict,
    ).toBe("passed");
    const signatures = npm("audit", "signatures", "--omit=dev", "--json");
    expect(
      evaluateSignatures({ ...signatures, stdout: signatures.stdout }),
    ).toMatchObject({
      verdict: "passed",
    });
  });

  it("serves the product's own scanners through PATH", async () => {
    const saved = process.env.PATH;
    process.env.PATH = [fakeNpmDirectory(), saved].join(delimiter);
    try {
      expect(await npmAuditScanner(process.cwd())).toMatchObject({
        auditReportVersion: 2,
      });
      expect((await npmSignatureAuditor(process.cwd())).status).toBe(0);
    } finally {
      process.env.PATH = saved;
    }
  });

  it("fails loudly on an audit form it does not know and passes other commands through", () => {
    const unknown = npm("audit", "fix");
    expect(unknown.status).toBe(2);
    expect(unknown.stderr).toContain("unknown audit form");
    expect(npm("--version").stdout).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("is not applied when CI requires the registry", () => {
    const real = { PATH: "/usr/bin", PISHIP_REQUIRE_REGISTRY: "1" };
    expect(withFakeNpm(real)).toBe(real);
  });
});
