// Tests that run only when CI requests them skip silently anywhere else. The
// request lives in the workflow, not in the test, so dropping it from the
// workflow would leave every run green with the test never executed. These
// checks keep the request in place.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.env.PISHIP_BUILD_INPUT as string;
const ci = readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8");

/** The steps of the CI check job, one string each. */
function steps(): string[] {
  const body = ci.slice(ci.indexOf("    steps:\n"));
  return body
    .split(/\n(?= {6}- )/)
    .filter((step) => step.startsWith("      - "));
}

describe("the CI check job", () => {
  it("runs the live platform secret store test on every runner OS", () => {
    const live = steps().filter((step) =>
      step.includes("packages/credentials/src/platform-store.test.ts"),
    );
    // One step for Keychain and Credential Manager, one for GNOME Keyring.
    const conditions = live.map(
      (step) => /^ {6}- if: (.+)$/m.exec(step)?.[1] ?? "always",
    );
    expect(conditions.sort()).toEqual([
      "runner.os != 'Linux'",
      "runner.os == 'Linux'",
    ]);
    for (const step of live)
      expect(step).toMatch(/^ {10}PISHIP_LIVE_SECRET_STORE: "1"$/m);
  });

  it("requires the OS sandbox and isolator on Linux and macOS", () => {
    const unit = steps().find((step) => step.includes("run: npm test"));
    expect(unit).toBeDefined();
    for (const variable of [
      "PISHIP_REQUIRE_SANDBOX",
      "PISHIP_REQUIRE_ISOLATOR",
    ])
      expect(unit).toMatch(
        new RegExp(
          `^ {10}${variable}: \\$\\{\\{ runner\\.os != 'Windows' && '1' \\|\\| '0' \\}\\}$`,
          "m",
        ),
      );
  });
});

describe("browser evidence tiers", () => {
  const portable = readFileSync(
    join(ROOT, ".github/workflows/portable-e2e.yml"),
    "utf8",
  );
  const qualification = readFileSync(
    join(ROOT, ".github/workflows/release-qualification.yml"),
    "utf8",
  );

  it("keeps live Chrome required by default and excludes it only in qualification", () => {
    expect(portable).toMatch(
      /skip-browser:\n(?:[^\n]*\n)*?        type: boolean\n        default: false/,
    );
    expect(portable).toContain(
      "PISHIP_SKIP_BROWSER: ${{ inputs.skip-browser && '1' || '0' }}",
    );
    expect(portable).toContain(
      "PISHIP_REQUIRE_BROWSER: ${{ inputs.skip-browser && '0' || '1' }}",
    );
    expect(portable).toContain(
      "if: runner.os == 'Linux' && matrix.shard == 1 && !inputs.skip-browser",
    );
    expect(qualification).toMatch(
      /portable-e2e:\n    uses: \.\/\.github\/workflows\/portable-e2e.yml\n    with:\n      skip-browser: true/,
    );
    expect(qualification).toContain(
      "needs: [ci, codeql, portable-e2e, reference-e2e]",
    );
  });
});

// The supply-chain evidence the v0.11 release gate rests on
// (docs/maintainers/v0.11-qualification-matrix.md): each item is a step of
// Release candidate that runs for every distribution on every target, and
// Release qualification runs Release candidate only after the other tiers.
describe("release candidate supply-chain evidence", () => {
  const candidate = readFileSync(
    join(ROOT, ".github/workflows/release-candidate.yml"),
    "utf8",
  );
  const qualification = readFileSync(
    join(ROOT, ".github/workflows/release-qualification.yml"),
    "utf8",
  );

  /** The body of one job: from its key to the next job. */
  function job(name: string): string {
    const start = candidate.indexOf(`\n  ${name}:\n`);
    const next = candidate.slice(start + 1).search(/\n {2}[a-z][\w-]*:\n/);
    return candidate.slice(start, next < 0 ? undefined : start + 1 + next);
  }

  it("builds every distribution twice on every target and compares the payloads", () => {
    expect(job("build")).toContain("build: [first, second]");
    expect(job("build")).toContain(
      "target: [linux-x64, darwin-arm64, win32-x64]",
    );
    expect(job("reproducibility")).toContain(
      "distribution: [acmecode, mypi, devcode]",
    );
    expect(job("reproducibility")).toContain("reproducibility");
  });

  it("verifies, attests, and rejects tampering for every distribution on every target", () => {
    const verify = job("verify");
    for (const step of [
      "verify-release",
      "gh attestation verify",
      "Reject a tampered archive",
      "Reject tampered release files",
      "Check the recorded release evidence",
      "scripts/check-release-evidence.mjs",
    ])
      expect(verify, step).toContain(step);
    expect(verify).toContain("distribution: [acmecode, mypi, devcode]");
    expect(verify).toContain("target: [linux-x64, darwin-arm64, win32-x64]");
    expect(job("attest")).toContain("actions/attest-build-provenance");
  });

  it("installs every distribution on every target and reports what it costs the machine", () => {
    const install = job("install");
    expect(install).toContain("distribution: [acmecode, mypi, devcode]");
    expect(install).toContain("target: [linux-x64, darwin-arm64, win32-x64]");
    expect(install).toContain("Report the installed file count");
    expect(install).toContain("--smoke");
  });

  it("runs only after the fast gate, CodeQL, and both E2E tiers", () => {
    expect(qualification).toContain(
      "needs: [ci, codeql, portable-e2e, reference-e2e]",
    );
  });
});
