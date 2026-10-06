// What an extracted release says of its own supply-chain evidence, checked on
// the runner that verifies it (Release candidate, `verify`), so a green job
// shows the evidence is present on every target and not only that the build
// passed. `verify-release` proves the release is complete and consistent; this
// adds what it does not print or require:
//
//   node scripts/check-release-evidence.mjs <extracted release directory>
//
// - the release is `qualified`, its recorded tests passed, and its vulnerability
//   verdict is `passed`;
// - the SBOM lists the packages `release.json` counts, and the notices index
//   covers every one of them: the logical dependency graph, whatever the file
//   layout of the payload (bundled, shared between Pi packages, or placed from
//   a shared store);
// - every vendored Pi package has its own audit record in `vulnerabilities.json`;
// - the registry signature check is recorded, and an `unavailable` verdict is
//   a warning in the summary: the check could not run on that runner, which is
//   different from a package having no signature. "Found no dependencies to
//   audit" is not that: npm reached no package, so nothing was verified, and
//   that is a problem.
//
// It prints a Markdown summary and exits 1 on any problem.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const read = (dir, path) => JSON.parse(readFileSync(join(dir, path), "utf8"));

/** The problems with `dir`'s recorded evidence, and a summary of it. */
export function checkReleaseEvidence(dir) {
  const problems = [];
  const warnings = [];
  const release = read(dir, "release.json");
  const sbom = read(dir, "sbom.spdx.json");
  const notices = read(dir, "licenses/index.json");
  const vulnerabilities = read(dir, "vulnerabilities.json");
  const id = `${release.distribution?.id}@${release.distribution?.version} ${release.target}`;

  if (release.qualification !== "qualified")
    problems.push(`qualification is ${release.qualification}, not qualified`);
  if (!Array.isArray(release.tests) || release.tests.length === 0)
    problems.push("no smoke test result is recorded");
  for (const test of release.tests ?? [])
    if (test.result !== "passed")
      problems.push(`test ${test.name} is ${test.result}`);
  if (release.vulnerabilities?.verdict !== "passed")
    problems.push(
      `vulnerability verdict is ${release.vulnerabilities?.verdict}`,
    );
  if (vulnerabilities.verdict !== "passed")
    problems.push(`vulnerabilities.json verdict is ${vulnerabilities.verdict}`);

  // The graph: every package the payload carries is in the SBOM and the notices.
  const listed = (sbom.packages ?? []).filter(
    (item) => item.SPDXID !== "SPDXRef-Distribution",
  );
  if (!(release.sbom?.packages > 0))
    problems.push("release.json records no SBOM packages");
  if (listed.length < (release.sbom?.packages ?? 0))
    problems.push(
      `the SBOM lists ${listed.length} packages, release.json counts ${release.sbom?.packages}`,
    );
  const covered = new Set(
    (notices.packages ?? []).map((item) => `${item.name}@${item.version}`),
  );
  const uncovered = listed.filter(
    (item) => !covered.has(`${item.name}@${item.versionInfo}`),
  );
  for (const item of uncovered.slice(0, 5))
    problems.push(`notices omit ${item.name}@${item.versionInfo}`);
  const withIntegrity = listed.filter((item) => item.checksums?.length).length;

  // Every vendored Pi package is audited on its own.
  const vendored = join(dir, "payload", "pi-packages");
  const ids = existsSync(vendored)
    ? readdirSync(vendored, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
        .map((entry) => entry.name)
        .sort()
    : [];
  const audited = (vulnerabilities.packages ?? [])
    .map((item) => item.id)
    .sort();
  if (JSON.stringify(ids) !== JSON.stringify(audited))
    problems.push(
      `Pi packages ${JSON.stringify(ids)} and their audit records ${JSON.stringify(audited)} differ`,
    );

  // The registry signature check: recorded, and visibly unavailable when it was.
  const signatures = release.signatures;
  if (!signatures) problems.push("no registry signature verdict is recorded");
  else if (
    signatures.verdict === "unavailable" &&
    /found no dependencies to audit/.test(signatures.reason ?? "")
  )
    // npm reached no package: the check verified nothing, which is a defect of
    // the build and not a registry that could not be reached.
    problems.push(
      `the registry signature check audited no package (${signatures.reason})`,
    );
  else if (signatures.verdict === "unavailable")
    warnings.push(
      `registry signatures: unavailable (${signatures.reason ?? "no reason recorded"})`,
    );
  else if (signatures.verdict !== "passed")
    problems.push(`registry signature verdict is ${signatures.verdict}`);

  const summary = [
    `### Release evidence: ${id}`,
    "",
    `- qualification: ${release.qualification}; tests: ${(release.tests ?? []).map((test) => `${test.name} ${test.result}`).join(", ")}`,
    `- vulnerabilities: ${release.vulnerabilities?.verdict} (${JSON.stringify(release.vulnerabilities?.counts)}); Pi packages audited: ${audited.length}`,
    `- registry signatures: ${signatures?.verdict ?? "not recorded"}${signatures?.missing?.length ? `, ${signatures.missing.length} package(s) without a registry signature` : ""}`,
    `- SBOM: ${listed.length} packages (${withIntegrity} with a recorded checksum); notices: ${covered.size} distinct name and version pairs; payload files: ${release.payload?.files}`,
    ...warnings.map((warning) => `- warning: ${warning}`),
    ...problems.map((problem) => `- PROBLEM: ${problem}`),
  ];
  return { problems, warnings, summary };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const dir = process.argv[2];
  if (!dir) {
    console.error(
      "Usage: node scripts/check-release-evidence.mjs <extracted release directory>",
    );
    process.exit(2);
  }
  const { problems, warnings, summary } = checkReleaseEvidence(dir);
  console.log(summary.join("\n"));
  for (const warning of warnings) console.error(`::warning::${warning}`);
  process.exit(problems.length ? 1 : 0);
}
