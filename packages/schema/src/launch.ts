// Cross-field checks for settings that validate field by field but cannot
// work on the machine that launches the distribution. A setting that is
// certain to fail at launch is rejected by the parser; one that fails or is
// ignored only in some environments is reported as a warning by `validate`.
import { posix, win32 } from "node:path";
import {
  AccessFieldError,
  type AccessManifest,
  type DeploymentMode,
} from "./access.js";
import type { GovernanceManifest } from "./governance.js";
import type { Manifest, ValidationDiagnostic } from "./index.js";
import { hasRuntimeReference } from "./variables.js";

interface LaunchSections {
  readonly mode: DeploymentMode;
  readonly access?: AccessManifest | undefined;
  readonly governance?: GovernanceManifest | undefined;
}
interface Finding extends ValidationDiagnostic {
  /** The launch fails on every machine; the parser rejects it. */
  readonly certain: boolean;
}

/** The hostname of a URL without runtime references, else undefined. */
function plainHost(url: string | undefined): string | undefined {
  if (url === undefined || hasRuntimeReference(url)) return undefined;
  return new URL(url).hostname.toLowerCase();
}

function caPaths(access: AccessManifest): Finding[] {
  const findings: Finding[] = [];
  // A path that starts with a variable is absolute or not only once the
  // variable is resolved; any other path is checked as written.
  for (const [index, path] of access.network.tls.additionalCA.entries())
    if (
      !path.startsWith("${") &&
      !posix.isAbsolute(path) &&
      !win32.isAbsolute(path)
    )
      findings.push({
        path: `network.tls.additionalCA[${index}]`,
        certain: false,
        message:
          "A relative CA bundle path is read from the directory the command is launched in, and is not packaged or locked; use an absolute path that device management installs on every machine",
      });
  return findings;
}

/**
 * HTTP audit sinks under a private-only network policy, which contacts only
 * `network.allowHosts` and the hosts of the declared access endpoints.
 */
function auditHosts(
  mode: DeploymentMode,
  access: AccessManifest,
  governance: GovernanceManifest,
): Finding[] {
  const privateOnly =
    access.network.privateOnly ||
    (mode === "managed" && access.network.publicFallback === "deny");
  if (!privateOnly || !governance.audit.enabled) return [];
  const endpoints = [
    access.identity.mode === "oidc" ? access.identity.oidc.issuer : undefined,
    access.credential.broker?.endpoint,
    access.credential.broker?.revokeEndpoint,
    access.inference.baseUrl,
  ].filter((url): url is string => url !== undefined);
  // A templated endpoint adds a host that is known only at launch.
  const endpointsKnown = endpoints.every((url) => !hasRuntimeReference(url));
  const allowed = new Set([
    ...access.network.allowHosts,
    ...endpoints.map(plainHost).filter((host) => host !== undefined),
  ]);
  const findings: Finding[] = [];
  for (const [index, sink] of governance.audit.sinks.entries()) {
    if (sink.type !== "http" || sink.url === undefined) continue;
    const path = `audit.sinks[${index}].url`;
    const host = plainHost(sink.url);
    if (host === undefined) {
      findings.push({
        path,
        certain: false,
        message:
          "The network policy is private-only: the host this URL resolves to at launch must be in network.allowHosts or be the host of a declared endpoint, or the sink is refused",
      });
      continue;
    }
    if (allowed.has(host)) continue;
    const refused = `${host} is not in network.allowHosts, and the private-only network policy refuses it`;
    if (!sink.required)
      findings.push({
        path,
        certain: false,
        message: `${refused}${endpointsKnown ? "" : " unless a templated endpoint resolves to it"}; events for this optional sink are dropped. Add ${host} to network.allowHosts`,
      });
    else
      findings.push({
        path,
        certain: endpointsKnown,
        message: endpointsKnown
          ? `${refused}, so this required sink fails every launch (AUDIT_UNAVAILABLE). Add ${host} to network.allowHosts`
          : `${refused} unless a templated endpoint resolves to it; this required sink then fails the launch (AUDIT_UNAVAILABLE). Add ${host} to network.allowHosts`,
      });
  }
  return findings;
}

function findings(sections: LaunchSections): Finding[] {
  const { mode, access, governance } = sections;
  return [
    ...(access ? caPaths(access) : []),
    ...(access && governance ? auditHosts(mode, access, governance) : []),
  ];
}

/**
 * Reject a combination that fails every launch. Called by the parser once
 * the access and governance sections are parsed.
 */
export function assertLaunchable(sections: LaunchSections): void {
  const failure = findings(sections).find((finding) => finding.certain);
  if (failure)
    throw new AccessFieldError("conflict", failure.path, failure.message);
}

/**
 * Warnings for settings that parse but fail at launch in some environments
 * or have no effect. They never change how the manifest is parsed.
 */
export function launchWarnings(manifest: Manifest): ValidationDiagnostic[] {
  return findings({
    mode: manifest.deployment.mode,
    access: manifest.access,
    governance: manifest.governance,
  })
    .filter((finding) => !finding.certain)
    .map(({ path, message }) => ({ path, message }));
}
