// Which artifacts are qualified. A release is: its `release.json` records that
// it passed the release gates. What `piship build`, `dev`, and `test` produce
// is not, and says so in a file beside the output (never inside the payload,
// whose inventory a release carries byte for byte).
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const RELEASE_QUALIFIED = "qualified";
export const LOCAL_BUILD_UNQUALIFIED = "unqualified-local";
export const QUALIFICATION_SCHEMA = "piship-qualification/v1";

/** The marker `piship build` writes beside `dist/<id>`. */
export function localBuildMarkerPath(output: string): string {
  return `${output}.piship-qualification.json`;
}

/** One line for `piship build` to print: what the output is not. */
export const UNQUALIFIED_BUILD_NOTICE =
  "This is an unqualified local build: it is not audited, has no SBOM or notices, and is not signed. Run piship release for the qualified artifact.";

/** Records that `output`, a payload built locally, was not qualified. */
export function markLocalBuild(output: string): void {
  writeFileSync(
    localBuildMarkerPath(output),
    `${JSON.stringify(
      {
        schema: QUALIFICATION_SCHEMA,
        qualification: LOCAL_BUILD_UNQUALIFIED,
        note: UNQUALIFIED_BUILD_NOTICE,
      },
      null,
      2,
    )}\n`,
  );
}

/**
 * True for a payload directory that is not inside a release: it has the
 * payload's inventory but no `release.json`. Whatever produced it, nothing
 * qualified it.
 */
export function isUnqualifiedPayload(directory: string): boolean {
  return (
    !existsSync(join(directory, "release.json")) &&
    existsSync(join(directory, "metadata", "inventory.json"))
  );
}
