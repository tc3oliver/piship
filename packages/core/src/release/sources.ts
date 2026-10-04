// The release `source` and `install-script` gates over one locked npm
// closure. A leaf module (no import of the core root), so the Pi package
// gates can reuse it without loading the release gates.
import { REVIEWED_INSTALL_SCRIPTS } from "../compatibility.js";
import { gate } from "./shared.js";

/**
 * The `source` and `install-script` gates over any locked npm closure: the
 * payload's, or a Pi package's (spec §9). `reviewed` lists the reviewed
 * `path@version` lifecycle scripts.
 */
export function checkLockedPackageSources(
  packages: readonly {
    readonly path: string;
    readonly version: string;
    readonly integrity: string;
    readonly resolved?: string;
    readonly installScript?: true;
  }[],
  sources: readonly string[],
  stage: "Release" | "Build" = "Release",
  reviewed: readonly string[] = REVIEWED_INSTALL_SCRIPTS,
): void {
  for (const item of packages) {
    // The lock keeps every registry entry, so one the npm lock records
    // without integrity is refused here instead of going unchecked.
    if (!item.integrity)
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} is missing integrity in the npm lock`,
        "Record the registry dist.integrity for this package in package-lock.json and lock again",
        stage,
      );
    if (!item.resolved)
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has no recorded source`,
        undefined,
        stage,
      );
    let origin: string;
    try {
      origin = new URL(item.resolved).origin;
    } catch {
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has an unparsable source`,
        undefined,
        stage,
      );
    }
    if (!sources.includes(origin))
      throw gate(
        "POLICY_DENIED",
        "source",
        `${item.path}@${item.version} comes from ${origin}, which is not in release.sources (${sources.join(", ")})`,
        undefined,
        stage,
      );
    if (!/^sha512-[A-Za-z0-9+/]+=*$/.test(item.integrity))
      throw gate(
        "INTEGRITY_FAILED",
        "source",
        `${item.path}@${item.version} has no sha512 integrity`,
        undefined,
        stage,
      );
    if (
      item.installScript &&
      !reviewed.includes(`${item.path}@${item.version}`)
    )
      throw gate(
        "POLICY_DENIED",
        "install-script",
        `${item.path}@${item.version} runs npm lifecycle scripts that were not reviewed for this PiShip version`,
        undefined,
        stage,
      );
  }
}
