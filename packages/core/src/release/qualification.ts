// Which artifacts are qualified. A release is: its `release.json` records that
// it passed the release gates. What `piship build`, `dev`, and `test` produce
// is not, and says so in a file beside the output (never inside the payload,
// whose inventory a release carries byte for byte).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { pishipCommand } from "../invocation.js";

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

/** The notice with the command that runs this PiShip, for `piship build` to print. */
export function unqualifiedBuildNotice(): string {
  return UNQUALIFIED_BUILD_NOTICE.replace(
    "Run piship release",
    `Run ${pishipCommand()} release`,
  );
}

/** Records that `output`, a payload built locally, was not qualified. */
export function markLocalBuild(output: string): void {
  writeFileSync(
    localBuildMarkerPath(output),
    `${JSON.stringify(
      {
        schema: QUALIFICATION_SCHEMA,
        qualification: LOCAL_BUILD_UNQUALIFIED,
        note: UNQUALIFIED_BUILD_NOTICE,
        host: hostname(),
      },
      null,
      2,
    )}\n`,
  );
}

/**
 * True when `directory` is a payload that `piship build`, `dev`, or `test`
 * produced on this machine: the person who installs it just built it and was
 * told what it is, so the install need not say it again. A payload copied
 * from elsewhere, or built before the marker named its host, is not.
 */
export function isLocalBuildOnThisHost(directory: string): boolean {
  try {
    const marker = JSON.parse(
      readFileSync(localBuildMarkerPath(directory), "utf8"),
    ) as { qualification?: unknown; host?: unknown };
    return (
      marker.qualification === LOCAL_BUILD_UNQUALIFIED &&
      marker.host === hostname()
    );
  } catch {
    return false;
  }
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
