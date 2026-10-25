// Tests that run only when CI requests them skip silently anywhere else. The
// request lives in the workflow, not in the test, so dropping it from the
// workflow would leave every run green with the test never executed. These
// checks keep the request in place.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.env.PISHIP_BUILD_INPUT as string;
const ci = readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8");

/** The body of one CI job: from its key to the next job. */
function ciJob(name: string): string {
  const start = ci.indexOf(`\n  ${name}:\n`);
  const next = ci.slice(start + 1).search(/\n {2}[a-z][\w-]*:\n/);
  return ci.slice(start, next < 0 ? undefined : start + 1 + next);
}

/** The steps of the CI check job, one string each. */
function steps(): string[] {
  const check = ciJob("check");
  const body = check.slice(check.indexOf("    steps: &check-steps\n"));
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
      "runner.os != 'Linux' && matrix.part != 'unit'",
      "runner.os == 'Linux'",
    ]);
    for (const step of live)
      expect(step).toMatch(/^ {10}PISHIP_LIVE_SECRET_STORE: "1"$/m);
  });

  it("requires the OS sandbox and isolator on Linux and macOS", () => {
    // The whole unit tier, and a Windows unit shard.
    const units = steps().filter((step) => step.includes("npm test"));
    expect(units).toHaveLength(2);
    for (const unit of units)
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

// Windows runs the check job's steps on three runners: two unit shards and
// one for everything else. Branch protection requires `check (windows-latest)`
// by name, and a skipped required check counts as passed, so the job of that
// name must run always and fail unless every Windows runner succeeded.
describe("the Windows CI check", () => {
  it("keeps the required check names", () => {
    expect(ciJob("check")).toContain("    name: check (${{ matrix.os }})\n");
    expect(ciJob("check")).toContain("os: [ubuntu-latest, macos-latest]");
    expect(ciJob("windows")).toMatch(
      /^ {4}name: check \(windows-latest, \$\{\{/m,
    );
    expect(ci.match(/^ {4}name: check \(windows-latest\)$/gm)).toHaveLength(1);
    expect(ciJob("check-windows")).toContain("name: check (windows-latest)\n");
  });

  it("runs every step of the check, and every unit file once, across its runners", () => {
    const windows = ciJob("windows");
    expect(windows).toContain("    steps: *check-steps\n");
    for (const leg of [
      "{ os: windows-latest, part: unit, shard: 1/2 }",
      "{ os: windows-latest, part: unit, shard: 2/2 }",
      "{ os: windows-latest, part: compatibility }",
    ])
      expect(windows).toContain(leg);
    expect(ciJob("check")).toContain("part: [all]");
    const condition = (run: string) =>
      steps()
        .filter((step) => step.includes(run))
        .map((step) => /^ {6}- if: (.+)$/m.exec(step)?.[1]);
    expect(condition("run: npm test\n")).toEqual(["matrix.part == 'all'"]);
    const shard = 'run: cmd /d /c "npm test -- --shard=${{ matrix.shard }}"';
    expect(condition(shard)).toEqual(["matrix.part == 'unit'"]);
    for (const run of [
      "run: npm run check:budgets",
      "run: npm run test:compatibility",
    ])
      expect(condition(run), run).toEqual(["matrix.part != 'unit'"]);
  });

  it("fails unless every Windows runner succeeded", () => {
    // The whole job: nothing may make it pass on a failed, skipped, or
    // cancelled runner, such as continue-on-error or a weaker condition.
    expect(ciJob("check-windows").trimEnd()).toBe(
      [
        "",
        "  check-windows:",
        "    name: check (windows-latest)",
        "    needs: [windows]",
        "    if: always()",
        "    runs-on: ubuntu-latest",
        "    steps:",
        '      - run: test "$RESULT" = success',
        "        env:",
        "          RESULT: ${{ needs.windows.result }}",
      ].join("\n"),
    );
    // A runner allowed to fail would report success to the aggregate.
    expect(ciJob("windows")).not.toContain("continue-on-error");
    expect(ciJob("check")).not.toContain("continue-on-error");
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

// Every shard of an E2E workflow builds test releases that pass the release
// vulnerability gate, so one early audit job stands in front of them all.
describe("E2E vulnerability preflight", () => {
  for (const file of ["portable-e2e", "reference-e2e"]) {
    const text = readFileSync(
      join(ROOT, `.github/workflows/${file}.yml`),
      "utf8",
    );
    it(`${file} audits once before its shards`, () => {
      expect(text).toContain("run: node scripts/audit-preflight.mjs");
      const jobs =
        file === "portable-e2e" ? ["portable"] : ["stack", "reference"];
      for (const name of jobs)
        expect(text).toMatch(
          new RegExp(`\\n  ${name}:\\n    needs: preflight\\n`),
        );
      expect(text).toMatch(/\n  report:\n    needs: \[preflight, /);
    });
  }
});
