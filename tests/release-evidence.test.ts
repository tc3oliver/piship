import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The evidence script is plain JavaScript.
import { checkReleaseEvidence } from "../scripts/check-release-evidence.mjs";

// What Release candidate asserts of every extracted release on every target
// (scripts/check-release-evidence.mjs): the evidence is present and
// consistent, whatever the payload's file layout.

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function write(root: string, path: string, value: unknown) {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), JSON.stringify(value));
}

/** An extracted release with `packages` in its SBOM and notices and `vendored` Pi packages. */
function release(
  options: {
    release?: Record<string, unknown>;
    notices?: string[];
    audited?: string[];
    vendored?: string[];
  } = {},
): string {
  const root = mkdtempSync(join(tmpdir(), "piship-evidence-"));
  roots.push(root);
  const packages = ["alpha", "beta", "leaf"];
  write(root, "release.json", {
    distribution: { id: "devcode", version: "1.0.0" },
    target: "linux-x64",
    qualification: "qualified",
    tests: [{ name: "offline-smoke", result: "passed" }],
    sbom: { path: "sbom.spdx.json", packages: packages.length },
    vulnerabilities: { verdict: "passed", counts: { high: 0 } },
    signatures: {
      tool: "npm audit signatures",
      verdict: "passed",
      missing: [],
    },
    payload: { files: 10 },
    ...options.release,
  });
  write(root, "sbom.spdx.json", {
    packages: [
      { SPDXID: "SPDXRef-Distribution", name: "DevCode", versionInfo: "1.0.0" },
      ...packages.map((name) => ({
        SPDXID: `SPDXRef-Package-${name}`,
        name,
        versionInfo: "1.0.0",
        checksums: [{ algorithm: "SHA512", checksumValue: "00" }],
      })),
    ],
  });
  write(root, "licenses/index.json", {
    packages: (options.notices ?? packages).map((name) => ({
      name,
      version: "1.0.0",
    })),
  });
  const vendored = options.vendored ?? ["pi-a", "pi-b"];
  for (const id of vendored)
    write(root, `payload/pi-packages/${id}/package.json`, {});
  // The directory a shared dependency lives in is not a package.
  write(root, "payload/pi-packages/.shared/leaf@1.0.0-abc/package.json", {});
  write(root, "vulnerabilities.json", {
    verdict: "passed",
    packages: (options.audited ?? vendored).map((id) => ({ id })),
  });
  return root;
}

describe("the recorded release evidence", () => {
  it("accepts a qualified release whose SBOM, notices, and Pi package audits agree", () => {
    const result = checkReleaseEvidence(release());
    expect(result.problems).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.summary.join("\n")).toContain("devcode@1.0.0 linux-x64");
    expect(result.summary.join("\n")).toContain("3 with a recorded checksum");
  });

  it("names each thing that is missing", () => {
    expect(
      checkReleaseEvidence(
        release({ release: { qualification: "unqualified-local" } }),
      ).problems,
    ).toEqual(["qualification is unqualified-local, not qualified"]);
    expect(
      checkReleaseEvidence(
        release({
          release: { tests: [{ name: "offline-smoke", result: "failed" }] },
        }),
      ).problems,
    ).toEqual(["test offline-smoke is failed"]);
    expect(
      checkReleaseEvidence(release({ notices: ["alpha", "beta"] })).problems,
    ).toEqual(["notices omit leaf@1.0.0"]);
    expect(
      checkReleaseEvidence(release({ audited: ["pi-a"] })).problems,
    ).toHaveLength(1);
    expect(
      checkReleaseEvidence(release({ release: { sbom: { packages: 9 } } }))
        .problems,
    ).toEqual(["the SBOM lists 3 packages, release.json counts 9"]);
  });

  it("makes an unavailable registry signature check visible and a missing record a problem", () => {
    const unavailable = checkReleaseEvidence(
      release({
        release: {
          signatures: {
            verdict: "unavailable",
            missing: [],
            reason: "no registry",
          },
        },
      }),
    );
    expect(unavailable.problems).toEqual([]);
    expect(unavailable.warnings).toEqual([
      "registry signatures: unavailable (no registry)",
    ]);
    // A check that reached no package verified nothing: not a warning.
    const nothing = checkReleaseEvidence(
      release({
        release: {
          signatures: {
            verdict: "unavailable",
            missing: [],
            reason:
              "found no dependencies to audit that were installed from a supported registry",
          },
        },
      }),
    );
    expect(nothing.warnings).toEqual([]);
    expect(nothing.problems).toEqual([
      "the registry signature check audited no package (found no dependencies to audit that were installed from a supported registry)",
    ]);
    expect(
      checkReleaseEvidence(release({ release: { signatures: undefined } }))
        .problems,
    ).toEqual(["no registry signature verdict is recorded"]);
  });
});
