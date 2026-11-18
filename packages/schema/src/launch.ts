// Cross-field checks for settings that validate field by field but cannot
// work on the machine that launches the distribution. A setting that is
// certain to fail at launch is rejected by the parser; one that fails or is
// ignored only in some environments is reported as a warning by `validate`.
import { posix, win32 } from "node:path";
import { isCredentialName, isLoopbackHost } from "@piship/contracts";
import {
  AccessFieldError,
  type AccessManifest,
  type DeploymentMode,
} from "./access.js";
import type { GovernanceManifest, PolicyRule } from "./governance.js";
import { governanceReferences } from "./governance-parse.js";
import { spoofableHostName, spoofableHostWarning } from "./http-transport.js";
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
 * A required sandbox's endpoint and router under a private-only network
 * policy: never allowed implicitly, so an undeclared host stops the sandbox.
 * A templated URL is judged by doctor once it resolves.
 */
function sandboxHosts(
  mode: DeploymentMode,
  access: AccessManifest,
  governance: GovernanceManifest,
): Finding[] {
  const sandbox = governance.sandbox;
  const hosts = sandbox.required ? privateOnlyHosts(mode, access) : undefined;
  if (!hosts) return [];
  const findings: Finding[] = [];
  for (const [field, url] of [
    ["endpoint", sandbox.endpoint],
    ["router", sandbox.router],
  ] as const) {
    const host = plainHost(url);
    if (host === undefined || hosts.allowed.has(host)) continue;
    findings.push({
      path: `sandbox.${field}`,
      certain: false,
      message: `${host} is not in network.allowHosts, and the private-only network policy refuses it${hosts.endpointsKnown ? "" : " unless a templated endpoint resolves to it"}, so the required sandbox cannot start. Add ${host} to network.allowHosts`,
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
          "sandbox.credential set to runtime needs the runtime credential of an openai-compatible gateway, and this distribution has no runtime credential; use stored or none",
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
          "sandbox.credential set to runtime sends the runtime credential only to the origin of inference.baseUrl; this URL must resolve to that origin at launch, or the required sandbox fails",
      });
      continue;
    }
    const expected = new URL(gateway).origin;
    if (new URL(url).origin !== expected)
      findings.push({
        path,
        certain: true,
        message: `sandbox.credential set to runtime sends the runtime credential only to the inference gateway origin ${expected}, so the required sandbox fails every launch; serve the sandbox from that origin or set sandbox.credential to stored`,
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
          `credential set to runtime needs the runtime credential of an openai-compatible gateway, and this distribution has no runtime credential, so ${always}; set credential to none`,
        );
        continue;
      }
      if (hasRuntimeReference(url) || hasRuntimeReference(gateway)) {
        report(
          "url",
          false,
          `credential set to runtime sends the runtime credential only to the origin of inference.baseUrl; this URL must resolve to that origin at launch, or ${otherwise}`,
        );
        continue;
      }
      const expected = new URL(gateway).origin;
      if (new URL(url).origin !== expected) {
        report(
          "url",
          true,
          `credential set to runtime sends the runtime credential only to the inference gateway origin ${expected}, so ${always}; serve the server from that origin or set credential to none`,
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
 * Endpoints that may be reached over plain HTTP to a private or internal
 * host, which is the default: what travels unencrypted, as one warning, and
 * each host name that another device on the network can answer for. An
 * endpoint with `httpTransport: https` is never listed. A `${NAME}` URL is
 * listed only when the owner wrote `http-allowed`, since what it resolves to
 * is unknown until launch.
 */
function plainHttpEndpoints(
  access: AccessManifest | undefined,
  governance: GovernanceManifest | undefined,
): Finding[] {
  const endpoints: {
    readonly transport: string | undefined;
    readonly urls: readonly (readonly [string, string | undefined])[];
    readonly exposed: string;
    readonly always?: boolean;
  }[] = [];
  const oidc =
    access?.identity.mode === "oidc" ? access.identity.oidc : undefined;
  if (oidc)
    endpoints.push({
      transport: oidc.httpTransport,
      urls: [["identity.oidc.issuer", oidc.issuer]],
      exposed:
        "the authorization code and the identity tokens, including the refresh token, which anyone on the network path can read and replay",
      // The discovery document may name plain-HTTP endpoints even when the
      // issuer is https.
      always: true,
    });
  const broker = access?.credential.broker;
  if (broker)
    endpoints.push({
      transport: broker.httpTransport,
      urls: [
        ["credential.broker.endpoint", broker.endpoint],
        ["credential.broker.revokeEndpoint", broker.revokeEndpoint],
      ],
      exposed:
        "the identity token sent to the broker and the gateway credential it issues, which anyone on the network path can read and replay until they expire",
    });
  if (access?.inference.baseUrl !== undefined)
    endpoints.push({
      transport: access.inference.httpTransport,
      urls: [["inference.baseUrl", access.inference.baseUrl]],
      exposed:
        "the gateway credential, which anyone on the network path can read and replay until it expires, and every prompt, file excerpt, and response, which can also be altered in transit",
    });
  for (const [index, sink] of (governance?.audit.sinks ?? []).entries())
    if (sink.url !== undefined)
      endpoints.push({
        transport: sink.httpTransport,
        urls: [[`audit.sinks[${index}].url`, sink.url]],
        exposed:
          "audit events, including any captured content, which can also be dropped or altered in transit",
      });
  const sandbox = governance?.sandbox;
  if (sandbox)
    endpoints.push({
      transport: sandbox.httpTransport,
      urls: [
        ["sandbox.endpoint", sandbox.endpoint],
        ["sandbox.router", sandbox.router],
      ],
      exposed: `commands, their output, and files sent to the sandbox${sandbox.credential === "stored" ? ", and the stored sandbox credential" : ""}, which can also be altered in transit`,
    });
  if (governance?.mcp.mode !== "off")
    for (const server of governance?.mcp.servers ?? [])
      if (server.transport === "streamable-http" && server.url !== undefined)
        endpoints.push({
          transport: server.httpTransport,
          urls: [[`mcp.servers.${server.id}.url`, server.url]],
          exposed:
            "traffic to the server, including any identity headers, which can also be altered in transit",
        });
  const listed: string[] = [];
  const spoofable: Finding[] = [];
  for (const endpoint of endpoints) {
    if (endpoint.transport === "https") continue;
    const declared = endpoint.urls.flatMap(([path, url]) =>
      url === undefined ? [] : [[path, url] as const],
    );
    const plain = declared.filter(
      ([, url]) =>
        !hasRuntimeReference(url) &&
        new URL(url).protocol === "http:" &&
        !isLoopbackHost(new URL(url).hostname),
    );
    const explicit = endpoint.transport === "http-allowed";
    const templated = explicit
      ? declared.filter(([, url]) => hasRuntimeReference(url))
      : [];
    if (plain.length)
      listed.push(
        `${plain.map(([path]) => path).join(", ")} (${endpoint.exposed})`,
      );
    else if (templated.length || (explicit && endpoint.always))
      listed.push(
        `${(templated.length ? templated : declared).map(([path]) => path).join(", ")}, if it resolves to plain HTTP (${endpoint.exposed})`,
      );
    for (const [path, url] of plain) {
      const host = plainHost(url);
      if (host !== undefined && spoofableHostName(host))
        spoofable.push({
          path,
          certain: false,
          message: spoofableHostWarning(host),
        });
    }
  }
  return [
    ...(listed.length
      ? [
          {
            path: "network",
            certain: false,
            message: `Plain HTTP to a private or internal host is admitted by default, and these endpoints travel unencrypted and unauthenticated on the network path: ${listed.join("; ")}. Serve them over https where possible, or set httpTransport: https on an endpoint to require it`,
          },
        ]
      : []),
    ...spoofable,
  ];
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
    ...(access && governance ? sandboxHosts(mode, access, governance) : []),
    ...(governance ? sandboxCredential(access, governance) : []),
    ...(governance ? mcpServers(mode, access, governance) : []),
    ...plainHttpEndpoints(access, governance),
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
  /** Launch variables only optional MCP server urls read, with those servers. */
  readonly optionalMcp: Readonly<Record<string, readonly string[]>>;
} {
  const { launch, update } = variableReferences(manifest);
  const variables = manifest.access?.variables ?? [];
  const optional = optionalMcpVariables(manifest);
  return {
    launch: variables.filter((name) => launch.has(name)),
    update: variables.filter((name) => !launch.has(name) && update.has(name)),
    optionalMcp: Object.fromEntries(
      variables.flatMap((name) => {
        const servers = optional.get(name);
        return servers ? [[name, servers]] : [];
      }),
    ),
  };
}

/**
 * Variables read by optional MCP server urls and nothing else: unset, such a
 * server is marked failed and the launch goes on.
 */
function optionalMcpVariables(manifest: Manifest): Map<string, string[]> {
  const found = new Map<string, string[]>();
  const governance = manifest.governance;
  if (!governance) return found;
  const servers = governance.mcp.servers;
  const rest = variableReferences({
    ...manifest,
    governance: {
      ...governance,
      mcp: {
        ...governance.mcp,
        servers: servers.filter((server) => server.required),
      },
    },
  });
  for (const server of servers)
    if (!server.required && server.url)
      for (const name of referencedVariables(server.url))
        if (!rest.launch.has(name) && !rest.update.has(name))
          found.set(name, [...(found.get(name) ?? []), server.id]);
  return found;
}
/** The variable names the manifest references, by when they are read. */
function variableReferences(manifest: Manifest): {
  readonly launch: ReadonlySet<string>;
  readonly update: ReadonlySet<string>;
} {
  const access = manifest.access;
  const launch = new Set<string>();
  if (access) {
    for (const text of [
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
    ])
      for (const name of text ? referencedVariables(text) : [])
        launch.add(name);
    if (manifest.governance)
      for (const name of governanceReferences(manifest.governance))
        launch.add(name);
  }
  return {
    launch,
    update: new Set(
      manifest.lifecycle ? lifecycleReferences(manifest.lifecycle) : [],
    ),
  };
}
/**
 * Declared variables that nothing references. They change nothing at launch,
 * so they are reported by `launchWarnings` and never refuse the manifest.
 */
function unusedVariables(manifest: Manifest): ValidationDiagnostic[] {
  const { launch, update } = variableReferences(manifest);
  return (manifest.access?.variables ?? []).flatMap((name, index) =>
    launch.has(name) || update.has(name)
      ? []
      : [
          {
            path: `variables[${index}]`,
            message: `${name} is declared but not referenced; remove it from variables, or use \${${name}} in a field that accepts a runtime reference`,
          },
        ],
  );
}

/**
 * Tools a session has before any extension loads: Pi's built-in tools
 * (PiShip governs read, write, edit, and bash and excludes the rest),
 * PiShip's own, and the Codemode and tool search tools. A copy of the
 * lists in packages/pi (governance/exposure.ts), which this package cannot
 * import; exposure.test.ts there fails when the two differ.
 */
export const KNOWN_TOOLS: ReadonlySet<string> = new Set([
  "read",
  "write",
  "edit",
  "bash",
  "grep",
  "find",
  "ls",
  "powershell",
  "ask_user",
  "task_start",
  "task_output",
  "task_stop",
  "codemode",
  "tool_search",
]);

/**
 * A `tool.execute` rule naming one tool that is not built in and not a tool
 * of a declared MCP server matches nothing PiShip knows of: an extension
 * may register that name at run time, or it is a typo and blocks nothing.
 */
export function unknownToolDenials(manifest: Manifest): ValidationDiagnostic[] {
  const policy = manifest.governance?.policy;
  if (!policy) return [];
  const mcp = manifest.governance?.mcp;
  const servers = !mcp || mcp.mode === "off" ? [] : mcp.servers;
  const named = (resource: string) =>
    KNOWN_TOOLS.has(resource) ||
    servers.some((server) => resource.startsWith(`mcp__${server.id}__`));
  return (["enforced", "defaults"] as const).flatMap((list) =>
    policy[list].flatMap((rule, index) =>
      rule.action === "tool.execute" &&
      !/[*?[\]{}]/.test(rule.resource) &&
      !named(rule.resource)
        ? [
            {
              path: `policy.${list}[${index}].resource`,
              message: `${rule.id} ${rule.effect === "deny" ? "denies" : `${rule.effect}s`} tool ${rule.resource}, which is not a Pi or PiShip tool or a tool of a declared MCP server (mcp__<server>__<tool>). An extension tool is only known at run time, so this rule matches it if an extension registers that exact name; otherwise it never applies${rule.effect === "deny" ? " and blocks nothing" : " and policy.default decides"}`,
            },
          ]
        : [],
    ),
  );
}

/**
 * An MCP rule whose resource names no declared server matches nothing: an
 * `mcp.server.start` resource is a server id and an `mcp.tool.call` one is
 * `<server>:<tool>`. The model-facing name (`mcp__docs__search`) is the
 * common slip; it is the `tool.execute` resource, not this one.
 */
export function unknownMcpServerRules(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const policy = manifest.governance?.policy;
  if (!policy) return [];
  const mcp = manifest.governance?.mcp;
  const ids = new Set(
    !mcp || mcp.mode === "off" ? [] : mcp.servers.map((server) => server.id),
  );
  const literal = (text: string) => !/[*?[\]{}]/.test(text);
  // A trusted project's .mcp.json may start a server of any id, so an
  // undeclared id is not proof that the rule matches nothing.
  const projectServers = mcp?.mode === "explicit" && mcp.project === "allow";
  const unknown = (server: string) =>
    literal(server) && !ids.has(server) && !projectServers;
  return (["enforced", "defaults"] as const).flatMap((list) =>
    policy[list].flatMap((rule, index) => {
      const at = `policy.${list}[${index}].resource`;
      const { resource } = rule;
      if (rule.action === "mcp.server.start") {
        return unknown(resource)
          ? [
              {
                path: at,
                message: `${rule.id} (${rule.effect} mcp.server.start) names ${resource}, which is not a server declared under mcp.servers, so it matches nothing; the resource is the server id`,
              },
            ]
          : [];
      }
      if (rule.action !== "mcp.tool.call") return [];
      const modelFacing = modelFacingMcpMessage(rule);
      if (modelFacing) return [{ path: at, message: modelFacing }];
      const separator = resource.indexOf(":");
      const server = separator < 0 ? resource : resource.slice(0, separator);
      return unknown(server)
        ? [
            {
              path: at,
              message: `${rule.id} (${rule.effect} mcp.tool.call) names ${resource}, but ${server} is not a server declared under mcp.servers, so it matches nothing; the resource is <server>:<tool>`,
            },
          ]
        : [];
    }),
  );
}

/**
 * Why a filesystem rule pattern can never match a decided path, which is
 * absolute (`/...` or `C:/...`), symlink-resolved, with `/` separators and no
 * `.`, `..`, empty, or trailing segment; undefined when it can. Path tokens
 * (`workspace`, `~`, `tmp`) expand to such a path.
 */
function unmatchablePath(pattern: string): string | undefined {
  const token = ["workspace", "~", "tmp"].find(
    (name) => pattern === name || pattern.startsWith(`${name}/`),
  );
  const rest = token ? pattern.slice(token.length) : pattern;
  if (/^(?:[A-Za-z]:)?\\/.test(pattern))
    return `it uses \\ separators, and a decided path uses /; write ${pattern.replace(/\\/g, "/")}`;
  // `*` never matches `/` or `:`, so a pattern that starts with a single
  // `*` cannot match the empty segment before an absolute path's first `/`
  // (or a drive), unless that segment is `*` itself, which matches only at
  // the filesystem root.
  const first = pattern.split("/")[0] as string;
  if (!token && first.startsWith("*") && !first.startsWith("**")) {
    if (first !== "*" || !pattern.includes("/"))
      return `a leading ${first} never matches the / a decided path starts with; write **/${pattern} for any directory`;
    return `only at the filesystem root (as ${pattern.slice(1)}): a leading * never matches a /; write *${pattern} for any directory`;
  }
  if (!token && !/^(?:\/|\*|[A-Za-z]:\/)/.test(pattern))
    return `it is relative, and a decided path is absolute; write workspace/${pattern.replace(/^(?:\.\/)+/, "")} for the project, or **/${pattern.replace(/^(?:\.\/)+/, "")} for any directory`;
  // Segments after the root or token: a leading `//` (a UNC share) is fine.
  const segments = (token ? rest : rest.replace(/^\/\/(?=[^/])/, "/"))
    .split("/")
    .slice(1);
  if (segments.some((segment) => segment === "." || segment === ".."))
    return "it has a . or .. segment, and a decided path is normalized; remove the segment";
  const trailing = segments.length > 1 && segments.at(-1) === "";
  if (trailing && !/^[A-Za-z]:\/$/.test(pattern))
    return `it ends with /, and a decided path does not; write ${pattern}** to cover the directory and everything in it`;
  if (segments.slice(0, -1).some((segment) => segment === ""))
    return "it has an empty segment (//), and a decided path does not; remove the extra /";
  return undefined;
}

/**
 * A filesystem `deny` or `ask` whose pattern no decided path can match: the
 * administrator believes something is denied or asked for, and nothing is.
 */
export function unmatchablePathRules(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const policy = manifest.governance?.policy;
  if (!policy) return [];
  return (["enforced", "defaults"] as const).flatMap((list) =>
    policy[list].flatMap((rule, index) => {
      const message = unmatchablePathMessage(rule);
      return message
        ? [{ path: `policy.${list}[${index}].resource`, message }]
        : [];
    }),
  );
}

/**
 * Rules whose resource glob is too narrow (`shellGlobMessage`) or that parse
 * but can never match (`inertRuleMessage`).
 */
export function narrowRuleWarnings(manifest: Manifest): ValidationDiagnostic[] {
  const policy = manifest.governance?.policy;
  if (!policy) return [];
  return (["enforced", "defaults"] as const).flatMap((list) =>
    policy[list].flatMap((rule, index) =>
      [shellGlobMessage(rule), inertRuleMessage(rule)].flatMap((message) =>
        message
          ? [
              {
                path: `policy.${list}[${index}].resource`,
                message: `${rule.id}: ${message}`,
              },
            ]
          : [],
      ),
    ),
  );
}

function unmatchablePathMessage(rule: PolicyRule): string | undefined {
  if (
    rule.effect === "allow" ||
    !["filesystem.read", "filesystem.write", "filesystem.*"].includes(
      rule.action,
    )
  )
    return undefined;
  const why = unmatchablePath(rule.resource);
  if (!why) return undefined;
  return why.startsWith("only at the filesystem root")
    ? `${rule.id} (${rule.effect} ${rule.action}) matches ${rule.resource} ${why}`
    : `${rule.id} (${rule.effect} ${rule.action}) never matches ${rule.resource}: ${why}`;
}

/** An mcp.tool.call rule naming the model-facing tool (`mcp__docs__search`). */
function modelFacingMcpMessage(rule: PolicyRule): string | undefined {
  if (rule.action !== "mcp.tool.call") return undefined;
  const tool = /^mcp__([^_]+(?:_[^_]+)*)__(.+)$/.exec(rule.resource);
  return tool
    ? `${rule.id} (${rule.effect} mcp.tool.call) names the model-facing tool ${rule.resource}, so it matches nothing; write it as ${tool[1]}:${tool[2]} (<server>:<tool>)`
    : undefined;
}

/**
 * A shell.execute deny or ask whose resource has a single `*` (not part of
 * `**`): `*` stops at `/` and `:`, so `rm -rf *` lets `rm -rf /` through and
 * `git push ** --force*` misses `--force-with-lease=main:abc`.
 */
export function shellGlobMessage(rule: PolicyRule): string | undefined {
  const single = /(?<!\*)\*(?!\*)/;
  return rule.action === "shell.execute" &&
    rule.effect !== "allow" &&
    single.test(rule.resource)
    ? `"${rule.resource}" does not match arguments containing / or :, because * stops at both; use ** (for example "${rule.resource.replace(new RegExp(single, "g"), "**")}")`
    : undefined;
}

const LOAD_ACTIONS = new Set<string>([
  "resource.load",
  "skill.load",
  "instruction.load",
  "extension.load",
]);

/**
 * Why a rule parses but can never match: a `git.push` resource is
 * `<remote>/<branch>`, and a load resource is `<class>:./<path>` or
 * `<class>:**`.
 */
export function inertRuleMessage(rule: PolicyRule): string | undefined {
  if (rule.action === "git.push" && /\s/.test(rule.resource))
    return `"${rule.resource}" never matches: a git.push resource is <remote>/<branch> (for example "origin/main"), not a command`;
  if (
    rule.action === "git.push" &&
    !rule.resource.includes("/") &&
    !rule.resource.includes("**")
  )
    return `"${rule.resource}" never matches: a git.push resource is <remote>/<branch> (for example "origin/${rule.resource}", or "**/${rule.resource}" for any remote)`;
  // `<class>:` then `./...` or a glob; builtin and project resources are
  // named differently (`builtin:<name>`, `project:<path>`).
  const colon = rule.resource.indexOf(":");
  const rest = rule.resource.slice(colon + 1);
  if (
    LOAD_ACTIONS.has(rule.action) &&
    ["certified", "company", "user"].includes(rule.resource.slice(0, colon)) &&
    !rest.startsWith("./") &&
    !rest.startsWith("*")
  )
    return `"${rule.resource}" never matches: a ${rule.action} resource is <class>:./<path> or <class>:** (for example "company:./resources/skills/**")`;
  return undefined;
}

/**
 * The manifest's rule checks that need nothing but the rule itself, for rules
 * from outside the manifest (team, project, and user policy files).
 */
export function ruleWarnings(rule: PolicyRule): string[] {
  const shell = shellGlobMessage(rule);
  const inert = inertRuleMessage(rule);
  return [
    unmatchablePathMessage(rule),
    modelFacingMcpMessage(rule),
    shell && `${rule.id}: ${shell}`,
    inert && `${rule.id}: ${inert}`,
  ].filter((message): message is string => message !== undefined);
}

/**
 * `filesystem.read` denies that no enforced `sandbox.filesystem.read.deny`
 * directory covers. They refuse Pi's file tools, but a command (`bash`, a
 * user's `!` command) reads files through the sandbox, or without one when
 * `sandbox.required` is not true, so `cat .env` still works. One warning per
 * policy layer names every such rule; it never refuses the manifest.
 */
export function uncontainedReadDenials(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const governance = manifest.governance;
  if (!governance) return [];
  // The sandbox (and its read-deny list) runs only when it is required.
  const required = governance.sandbox.required === true;
  const directories = required
    ? governance.sandbox.filesystem.read.deny.map((entry) => {
        let end = entry.length;
        while (end > 0 && entry[end - 1] === "/") end--;
        return entry.slice(0, end);
      })
    : [];
  return (["enforced", "defaults"] as const).flatMap((layer) => {
    const uncovered = governance.policy[layer].filter((rule) => {
      if (
        rule.effect !== "deny" ||
        !["filesystem.read", "filesystem.*", "*"].includes(rule.action)
      )
        return false;
      // The literal directory before the first glob character.
      const literal = rule.resource.split(/[*?[{]/)[0] as string;
      const prefix = literal.slice(0, literal.lastIndexOf("/") + 1);
      const path = rule.resource === literal ? literal : prefix;
      return !directories.some(
        (dir) => dir !== "" && (path === dir || path.startsWith(`${dir}/`)),
      );
    });
    return uncovered.length
      ? [
          {
            path: `policy.${layer}`,
            message: `${uncovered.map((rule) => `${rule.id} (${rule.resource})`).join(", ")}: these filesystem.read denies refuse the file tools only; a command such as cat in bash or a ! command can still read the files unless ${required ? "" : "sandbox.required is true and "}sandbox.filesystem.read.deny lists their directory (docs/sandbox.md#configuration)`,
          },
        ]
      : [];
  });
}

/**
 * An opted-in rule pack whose sandbox-gated rules stay inactive because
 * `sandbox.required` is not true: its shell commands fall back to the policy
 * default (usually a prompt for each one).
 */
export function inactivePackRules(manifest: Manifest): ValidationDiagnostic[] {
  const governance = manifest.governance;
  if (!governance || governance.sandbox.required === true) return [];
  return (governance.policy.packs ?? []).flatMap(({ pack, version }) => {
    const gated = governance.policy.defaults.filter(
      (rule) => rule.contained && rule.id.startsWith(`${pack}.`),
    );
    return gated.length
      ? [
          {
            path: "policy.packs",
            message: `${pack}@${version}: its ${gated.length} sandbox-gated rules (such as ${(gated.find((rule) => rule.resource === "git status") ?? gated[0])?.id}) are inactive because sandbox.required is not true, so commands like git status and npm test fall back to policy.default (${governance.policy.default}); set sandbox.required: true to activate them`,
          },
        ]
      : [];
  });
}

/**
 * `audit.capture` classes no runtime flow records: only `commandText` (shell
 * and background task commands) is ever captured, so an administrator who
 * opts in to the others must not believe the content is being kept.
 */
export function inertCaptureClasses(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const audit = manifest.governance?.audit;
  if (!audit?.enabled) return [];
  return (["promptContent", "responseContent", "sourceContent"] as const)
    .filter((key) => audit.capture[key])
    .map((key) => ({
      path: `audit.capture.${key}`,
      message:
        "no audit event records this content class yet, so nothing is captured for it; only commandText (bash, ! and background task commands) is recorded",
    }));
}

/**
 * Purge settings no command acts on: `onLogout` runs only in the branded
 * `logout`, which a distribution that leaves sign-in to Pi does not have, and
 * never purges `temp` (a live temporary belongs to a running process), and
 * `uninstall` does not read `onUninstall` yet.
 */
export function inertDataPurge(manifest: Manifest): ValidationDiagnostic[] {
  const purge = manifest.data?.purge;
  if (!purge) return [];
  const piSignIn =
    !manifest.access || manifest.access.credential.provider === "pi-native";
  return [
    ...(piSignIn && purge.onLogout.length
      ? [
          {
            path: "data.purge.onLogout",
            message:
              "nothing runs it: sign-in is left to Pi (credential.provider: pi-native), so there is no branded logout, and Pi's /logout purges nothing; the retention sweep still applies",
          },
        ]
      : !piSignIn && purge.onLogout.includes("temp")
        ? [
            {
              path: "data.purge.onLogout",
              message:
                "temp is not acted on: logout purges sessions and cache only, and PiShip removes its temporaries once the process that owns them is gone; remove temp from onLogout",
            },
          ]
        : []),
    ...(purge.onUninstall === "all"
      ? [
          {
            path: "data.purge.onUninstall",
            message:
              "uninstall does not act on it yet and keeps the state; users delete it with purge <id> --yes or uninstall <id> --purge --yes",
          },
        ]
      : []),
  ];
}

/**
 * `data.temp.retention`, which no sweep applies: PiShip's temporaries are
 * removed by the abandoned-temporaries sweep once their process is gone, and
 * deleting a live one by age would break the run that owns it.
 */
export function inertTempRetention(manifest: Manifest): ValidationDiagnostic[] {
  return manifest.data?.retention.temp
    ? [
        {
          path: "data.temp.retention",
          message:
            "nothing applies it: PiShip removes a temporary when its process ends, or at a later start once the process is gone, whatever its age; remove data.temp.retention",
        },
      ]
    : [];
}

/**
 * Task grant settings for hosts: `/grant` and `taskGrants.declared` cover
 * paths, tools and commands only, so no grant can name a host yet.
 */
export function inertTaskGrantHosts(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const grants = manifest.governance?.policy.taskGrants;
  if (!grants) return [];
  return [
    ...(grants.wildcardHosts
      ? [
          {
            path: "policy.taskGrants.wildcardHosts",
            message:
              "has no effect yet: no task grant can name a host (/grant covers a folder and shell commands); remove policy.taskGrants.wildcardHosts",
          },
        ]
      : []),
    ...(grants.actions?.includes("web.request")
      ? [
          {
            path: "policy.taskGrants.actions",
            message:
              "web.request has no effect yet: no task grant can name a host (/grant covers a folder and shell commands); remove web.request from policy.taskGrants.actions",
          },
        ]
      : []),
  ];
}

/**
 * An openai-compatible endpoint without `models.default` (managed mode
 * already refuses it): every launch fails until the user passes `--model` or
 * sets one. A warning, not an error, because a user `model` preference makes
 * such a manifest work.
 */
export function missingDefaultModel(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const access = manifest.access;
  return access?.inference.provider === "openai-compatible" &&
    access.models.default === undefined &&
    access.config.enforced.model === undefined
    ? [
        {
          path: "models.default",
          message: `no default model is set, so ${manifest.app.command} fails to start until the user passes --model or sets one with config set model; set models.default to one of models.allowed`,
        },
      ]
    : [];
}

/**
 * An optional HTTP audit sink in a managed distribution drops what it cannot
 * deliver, and nothing says so until `doctor`.
 */
export function optionalHttpAuditSinks(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const audit = manifest.governance?.audit;
  if (manifest.deployment.mode !== "managed" || !audit?.enabled) return [];
  return audit.sinks.flatMap((sink, index) =>
    sink.type === "http" && !sink.required
      ? [
          {
            path: `audit.sinks[${index}].required`,
            message:
              "this optional HTTP sink drops events while its collector is unreachable, and only doctor shows the count afterwards; set required: true if events must not be lost",
          },
        ]
      : [],
  );
}

/**
 * Allow-listed variable names the runtime treats as credentials (a name such
 * as AWS_REGION matches a provider prefix) and drops from the child
 * environment without a message. A warning, so existing manifests still load.
 */
export function droppedCredentialNames(
  manifest: Manifest,
): ValidationDiagnostic[] {
  const governance = manifest.governance;
  if (!governance) return [];
  const lists: [string, readonly string[]][] = [
    ["sandbox.environment.allow", governance.sandbox.environment.allow],
    ...governance.mcp.servers.map((server): [string, readonly string[]] => [
      `mcp.servers.${server.id}.env.allow`,
      server.env.allow,
    ]),
  ];
  return lists.flatMap(([path, names]) =>
    names.filter(isCredentialName).map((name) => ({
      path,
      message: `${name} is treated as a credential and is never passed to the child process; remove it from the list`,
    })),
  );
}

/**
 * Warnings for settings that parse but fail at launch in some environments
 * or have no effect, plus update trust warnings (`updateTrustWarnings`).
 * They never change how the manifest is parsed.
 */
export function launchWarnings(manifest: Manifest): ValidationDiagnostic[] {
  return [
    ...unusedVariables(manifest),
    ...missingDefaultModel(manifest),
    ...unknownToolDenials(manifest),
    ...unknownMcpServerRules(manifest),
    ...unmatchablePathRules(manifest),
    ...narrowRuleWarnings(manifest),
    ...uncontainedReadDenials(manifest),
    ...inactivePackRules(manifest),
    ...inertCaptureClasses(manifest),
    ...inertDataPurge(manifest),
    ...inertTempRetention(manifest),
    ...inertTaskGrantHosts(manifest),
    ...droppedCredentialNames(manifest),
    ...optionalHttpAuditSinks(manifest),
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
