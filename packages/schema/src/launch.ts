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
import { governanceReferences } from "./governance-parse.js";
import type { Manifest, ValidationDiagnostic } from "./index.js";
import { lifecycleReferences, updateTrustWarnings } from "./lifecycle.js";
import { hasRuntimeReference, referencedVariables } from "./variables.js";

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

interface PrivateOnlyHosts {
  /** `network.allowHosts` and the plain hosts of the declared endpoints. */
  readonly allowed: ReadonlySet<string>;
  /** False when a templated endpoint adds a host known only at launch. */
  readonly endpointsKnown: boolean;
}

/**
 * The hosts a private-only network policy contacts: `network.allowHosts`
 * and the hosts of the declared access endpoints. Undefined when the policy
 * is not private-only.
 */
function privateOnlyHosts(
  mode: DeploymentMode,
  access: AccessManifest,
): PrivateOnlyHosts | undefined {
  const privateOnly =
    access.network.privateOnly ||
    (mode === "managed" && access.network.publicFallback === "deny");
  if (!privateOnly) return undefined;
  const endpoints = [
    access.identity.mode === "oidc" ? access.identity.oidc.issuer : undefined,
    access.credential.broker?.endpoint,
    access.credential.broker?.revokeEndpoint,
    access.inference.baseUrl,
  ].filter((url): url is string => url !== undefined);
  return {
    endpointsKnown: endpoints.every((url) => !hasRuntimeReference(url)),
    allowed: new Set([
      ...access.network.allowHosts,
      ...endpoints.map(plainHost).filter((host) => host !== undefined),
    ]),
  };
}

/** HTTP audit sinks under a private-only network policy. */
function auditHosts(
  mode: DeploymentMode,
  access: AccessManifest,
  governance: GovernanceManifest,
): Finding[] {
  if (!governance.audit.enabled) return [];
  const hosts = privateOnlyHosts(mode, access);
  if (!hosts) return [];
  const { allowed, endpointsKnown } = hosts;
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

/**
 * `sandbox.credential: runtime` sends the runtime credential, which is
 * issued for the inference gateway, and only to the gateway's origin.
 */
function sandboxCredential(
  access: AccessManifest | undefined,
  governance: GovernanceManifest,
): Finding[] {
  const sandbox = governance.sandbox;
  if (sandbox.credential !== "runtime") return [];
  const gateway = access?.inference.baseUrl;
  if (gateway === undefined || access?.credential.provider === "none")
    return [
      {
        path: "sandbox.credential",
        certain: true,
        message:
          "sandbox.credential: runtime needs the runtime credential of an openai-compatible gateway, and this distribution has no runtime credential; use stored or none",
      },
    ];
  const findings: Finding[] = [];
  for (const [field, url] of [
    ["endpoint", sandbox.endpoint],
    ["router", sandbox.router],
  ] as const) {
    if (url === undefined) continue;
    const path = `sandbox.${field}`;
    if (hasRuntimeReference(url) || hasRuntimeReference(gateway)) {
      findings.push({
        path,
        certain: false,
        message:
          "sandbox.credential: runtime sends the runtime credential only to the origin of inference.baseUrl; this URL must resolve to that origin at launch, or the required sandbox fails",
      });
      continue;
    }
    const expected = new URL(gateway).origin;
    if (new URL(url).origin !== expected)
      findings.push({
        path,
        certain: true,
        message: `sandbox.credential: runtime sends the runtime credential only to the inference gateway origin ${expected}, so the required sandbox fails every launch; serve the sandbox from that origin or use sandbox.credential: stored`,
      });
  }
  return findings;
}

/**
 * Streamable HTTP MCP servers. `credential: runtime` sends the runtime
 * credential only to the inference gateway's origin, and a private-only
 * network policy refuses an undeclared host. Either way the server never
 * starts: a required one fails the launch with MCP_UNHEALTHY.
 */
function mcpServers(
  mode: DeploymentMode,
  access: AccessManifest | undefined,
  governance: GovernanceManifest,
): Finding[] {
  if (governance.mcp.mode === "off") return [];
  const gateway =
    access?.credential.provider === "none"
      ? undefined
      : access?.inference.baseUrl;
  const hosts = access ? privateOnlyHosts(mode, access) : undefined;
  const findings: Finding[] = [];
  for (const server of governance.mcp.servers) {
    if (server.transport !== "streamable-http" || server.url === undefined)
      continue;
    const path = `mcp.servers.${server.id}`;
    const url = server.url;
    if (server.headers && access?.identity.mode !== "oidc")
      findings.push({
        path: `${path}.headers`,
        certain: true,
        message:
          "Identity headers take their value from the signed-in OIDC identity and need identity.mode: oidc",
      });
    if (
      server.httpTransport === "http-allowed" &&
      (hasRuntimeReference(url) || new URL(url).protocol === "http:")
    )
      findings.push({
        path: `${path}.httpTransport`,
        certain: false,
        message: hasRuntimeReference(url)
          ? "http-allowed: if this URL resolves to plain HTTP, traffic to the server, including any identity headers, is unencrypted and unauthenticated on the network path; it must resolve to https or a private or internal host, or the server does not start"
          : "http-allowed: traffic to this server, including any identity headers, is unencrypted and unauthenticated on the network path; serve it over https where possible",
      });
    const plainName = plainHost(url);
    if (
      server.httpTransport === "http-allowed" &&
      plainName !== undefined &&
      new URL(url).protocol === "http:" &&
      (plainName.endsWith(".local") ||
        (!plainName.includes(".") &&
          !plainName.includes(":") &&
          plainName !== "localhost"))
    )
      findings.push({
        path: `${path}.url`,
        certain: false,
        message: `${plainName} is resolved through mDNS or the machine's DNS search domains, which another device on the network can answer for; over plain HTTP nothing verifies the server, so use an IP address or a fully qualified name under .internal or .corp`,
      });
    // `always`: the server can never start; `otherwise`: it starts only if
    // a runtime value resolves as the message says.
    const [always, otherwise] = server.required
      ? [
          "this required server fails every launch (MCP_UNHEALTHY)",
          "this required server fails the launch (MCP_UNHEALTHY)",
        ]
      : [
          "this optional server never starts and its tools are unavailable",
          "this optional server does not start",
        ];
    const report = (field: string, certain: boolean, message: string) =>
      findings.push({
        path: `${path}.${field}`,
        certain: certain && server.required,
        message,
      });
    if (server.credential === "runtime") {
      if (gateway === undefined) {
        report(
          "credential",
          true,
          `credential: runtime needs the runtime credential of an openai-compatible gateway, and this distribution has no runtime credential, so ${always}; use credential: none`,
        );
        continue;
      }
      if (hasRuntimeReference(url) || hasRuntimeReference(gateway)) {
        report(
          "url",
          false,
          `credential: runtime sends the runtime credential only to the origin of inference.baseUrl; this URL must resolve to that origin at launch, or ${otherwise}`,
        );
        continue;
      }
      const expected = new URL(gateway).origin;
      if (new URL(url).origin !== expected) {
        report(
          "url",
          true,
          `credential: runtime sends the runtime credential only to the inference gateway origin ${expected}, so ${always}; serve the server from that origin or use credential: none`,
        );
        continue;
      }
    }
    if (!hosts) continue;
    const host = plainHost(url);
    if (host === undefined) {
      report(
        "url",
        false,
        `The network policy is private-only: the host this URL resolves to at launch must be in network.allowHosts or be the host of a declared endpoint, or ${otherwise}`,
      );
      continue;
    }
    if (hosts.allowed.has(host)) continue;
    const refused = `${host} is not in network.allowHosts, and the private-only network policy refuses it`;
    report(
      "url",
      hosts.endpointsKnown,
      hosts.endpointsKnown
        ? `${refused}, so ${always}. Add ${host} to network.allowHosts`
        : `${refused} unless a templated endpoint resolves to it, or ${otherwise}. Add ${host} to network.allowHosts`,
    );
  }
  return findings;
}

/**
 * The sandbox is activated only when required. An optional sandbox defaults
 * to network allow, so deny was declared and is silently not enforced.
 */
function ignoredSandboxNetwork(governance: GovernanceManifest): Finding[] {
  const sandbox = governance.sandbox;
  if (sandbox.required || sandbox.network.mode !== "deny") return [];
  return [
    {
      path: "sandbox.network.mode",
      certain: false,
      message:
        "deny is not enforced: the sandbox is activated only with sandbox.required: true, so commands run without network denial; set sandbox.required: true or remove sandbox.network.mode",
    },
  ];
}

function findings(sections: LaunchSections): Finding[] {
  const { mode, access, governance } = sections;
  return [
    ...(governance ? ignoredSandboxNetwork(governance) : []),
    ...(access ? caPaths(access) : []),
    ...(access && governance ? auditHosts(mode, access, governance) : []),
    ...(governance ? sandboxCredential(access, governance) : []),
    ...(governance ? mcpServers(mode, access, governance) : []),
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
 * Declared runtime variables by when they are read: `launch` by the branded
 * command (access endpoints, CA bundles, MCP, audit, and sandbox URLs),
 * `update` only by `<command> update` (`updates.source`).
 */
export function runtimeVariableUse(manifest: Manifest): {
  readonly launch: readonly string[];
  readonly update: readonly string[];
} {
  const updateOnly = new Set(
    manifest.lifecycle ? lifecycleReferences(manifest.lifecycle) : [],
  );
  const access = manifest.access;
  if (access) {
    const launch = [
      ...(access.identity.mode === "oidc"
        ? [
            access.identity.oidc.issuer,
            access.identity.oidc.clientId,
            access.identity.oidc.audience,
          ]
        : []),
      access.credential.broker?.endpoint,
      access.credential.broker?.revokeEndpoint,
      access.inference.baseUrl,
      ...access.network.tls.additionalCA,
    ].flatMap((text) => (text ? referencedVariables(text) : []));
    if (manifest.governance)
      launch.push(...governanceReferences(manifest.governance));
    for (const name of launch) updateOnly.delete(name);
  }
  const variables = access?.variables ?? [];
  return {
    launch: variables.filter((name) => !updateOnly.has(name)),
    update: variables.filter((name) => updateOnly.has(name)),
  };
}

/**
 * Warnings for settings that parse but fail at launch in some environments
 * or have no effect, plus update trust warnings (`updateTrustWarnings`).
 * They never change how the manifest is parsed.
 */
export function launchWarnings(manifest: Manifest): ValidationDiagnostic[] {
  return [
    ...findings({
      mode: manifest.deployment.mode,
      access: manifest.access,
      governance: manifest.governance,
    })
      .filter((finding) => !finding.certain)
      .map(({ path, message }) => ({ path, message })),
    ...(manifest.lifecycle
      ? updateTrustWarnings(
          manifest.deployment.mode,
          manifest.lifecycle.updates,
        )
      : []),
  ];
}
