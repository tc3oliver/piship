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
