import { describe, expect, it } from "vitest";
// @ts-expect-error The preflight script is plain JavaScript.
import { blockingAdvisories } from "../scripts/audit-preflight.mjs";

// The E2E preflight (scripts/audit-preflight.mjs) must reject what the
// release vulnerability gate rejects, from an `npm audit` v2 shaped report.
const advisory = (severity: string) => ({
  source: 1,
  url: "https://github.com/advisories/GHSA-xjj6-f33q-929c",
  severity,
});

describe("audit preflight", () => {
  it("names a high advisory and its package", () => {
    const audit = {
      auditReportVersion: 2,
      vulnerabilities: {
        undici: { severity: "high", via: [advisory("high")] },
        pi: { severity: "high", via: ["undici"] },
      },
    };
    expect(blockingAdvisories(audit)).toEqual([
      "GHSA-xjj6-f33q-929c (undici, high)",
    ]);
  });

  it("passes a moderate advisory and refuses an unreadable report", () => {
    const audit = {
      auditReportVersion: 2,
      vulnerabilities: {
        x: { severity: "moderate", via: [advisory("moderate")] },
      },
    };
    expect(blockingAdvisories(audit)).toEqual([]);
    const unknown = {
      auditReportVersion: 2,
      vulnerabilities: { y: { via: [advisory("strange")] } },
    };
    expect(blockingAdvisories(unknown)).toHaveLength(1);
    expect(() => blockingAdvisories({ error: {} })).toThrow(/no v2 report/);
  });
});
