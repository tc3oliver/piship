import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PI_PACKAGE, PI_VERSION, PISHIP_VERSION } from "./compatibility.js";
import { hash } from "./digest.js";
import type { DistributionLock, LockedPackage } from "./lock-schema.js";
import { STATE_SCHEMAS } from "./migration.js";

// This input is prepared with the @piship/core build, and travels with that package.
export const buildInput =
  process.env.PISHIP_BUILD_INPUT ??
  fileURLToPath(new URL("./build-input/", import.meta.url));
export const workspacePackages = [
  "schema",
  "contracts",
  "policy",
  "audit",
  "sandbox",
  "mcp",
  "identity",
  "credentials",
  "inference",
  "core",
  "pi",
  "cli",
] as const;
/** A package-lock link from `node_modules/@piship/<name>` to `packages/<name>`. */
function isWorkspaceLink(path: string, resolved: string | undefined): boolean {
  return workspacePackages.some(
    (name) =>
      path === `node_modules/@piship/${name}` &&
      resolved === `packages/${name}`,
  );
}
export function runtimeDependencies(
  detailed = false,
): DistributionLock["runtime"] {
  const source = readFileSync(join(buildInput, "package-lock.json"));
  const npmLock = JSON.parse(source.toString()) as {
    packages: Record<
      string,
      {
        version?: string;
        integrity?: string;
        dev?: boolean;
        resolved?: string;
        hasInstallScript?: boolean;
        link?: boolean;
      }
    >;
  };
  // Workspace links are PiShip's own packages, covered by the payload
  // inventory rather than registry integrity. Every other runtime entry is
  // kept, including one without integrity, so the release `source` gate
  // sees it and fails instead of the entry silently disappearing.
  const packages: LockedPackage[] = Object.entries(npmLock.packages)
    .filter(
      ([path, value]) =>
        path.startsWith("node_modules/") &&
        !value.dev &&
        !(value.link && isWorkspaceLink(path, value.resolved)),
    )
    .map(([path, value]) => ({
      path,
      version: value.version ?? "",
      integrity: value.integrity ?? "",
      ...(detailed && value.resolved ? { resolved: value.resolved } : {}),
      ...(detailed && value.hasInstallScript
        ? { installScript: true as const }
        : {}),
    }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const pi = packages.find(
    (item) => item.path === `node_modules/${PI_PACKAGE}`,
  );
  if (pi?.version !== PI_VERSION)
    throw new Error("Committed npm lock does not pin the expected Pi runtime");
  return {
    package: PI_PACKAGE,
    version: PI_VERSION,
    pishipVersion: PISHIP_VERSION,
    npmLockSha256: hash(source),
    packages,
    ...(detailed ? { stateSchemas: STATE_SCHEMAS } : {}),
  };
}
