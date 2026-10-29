// Network group: TLS verification, the outbound policy, the proxy and
// enterprise CA settings, and the network environment the agent's own
// commands (the bash tool) receive; MCP stdio servers only get env.allow.
// Proxies are shown as scheme://host:port only; NO_PROXY and withheld
// variables by name, never by value.
import {
  DEFAULT_NETWORK_POLICY,
  isPrivateNetworkHost,
  plainHttpProxy,
} from "@piship/contracts";
import { resolveTemplate } from "@piship/schema";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";
import { itEgress, networkText } from "./sandbox.js";

/**
 * Endpoints that may use plain HTTP (every one not set to
 * `httpTransport: https`), by host only: a warning for each that resolves to
 * plain HTTP, and a note for an endpoint that says `http-allowed` but does
 * not. MCP servers are reported with each server; here only when a proxy
 * would refuse them.
 */
function plainHttpGroup(data: DoctorData, out: DoctorSection): void {
  const metadata = data.ctx.metadata;
  const access = metadata.access;
  const governance = metadata.governance?.manifest;
  // Doctor reports whatever the lock holds; a section may be partial.
  const oidc =
    access?.identity?.mode === "oidc" ? access.identity.oidc : undefined;
  const endpoints: {
    readonly key: string;
    readonly urls: readonly (readonly [string, string | undefined])[];
    readonly exposed: string;
    /** The manifest says `http-allowed`, not just the default. */
    readonly explicit?: boolean;
    /** Reported elsewhere; only a proxy refusal is shown here. */
    readonly proxyOnly?: boolean;
  }[] = [];
  if (oidc && oidc.httpTransport !== "https")
    endpoints.push({
      key: "identity.oidc.httpTransport",
      explicit: oidc.httpTransport === "http-allowed",
      urls: [["identity.oidc.issuer", oidc.issuer]],
      exposed: "sign-in tokens, including the refresh token, are",
    });
  const broker = access?.credential?.broker;
  if (broker && broker.httpTransport !== "https")
    endpoints.push({
      key: "credential.broker.httpTransport",
      explicit: broker.httpTransport === "http-allowed",
      urls: [
        ["credential.broker.endpoint", broker.endpoint],
        ["credential.broker.revokeEndpoint", broker.revokeEndpoint],
      ],
      exposed: "the identity token and the issued gateway credential are",
    });
  if (access?.inference?.baseUrl && access.inference.httpTransport !== "https")
    endpoints.push({
      key: "inference.httpTransport",
      explicit: access.inference.httpTransport === "http-allowed",
      urls: [["inference.baseUrl", access.inference.baseUrl]],
      exposed: "the gateway credential and every prompt and response are",
    });
  for (const sink of governance?.audit?.sinks ?? [])
    if (sink.url !== undefined && sink.httpTransport !== "https")
      endpoints.push({
        key: `audit sink ${sink.id} httpTransport`,
        explicit: sink.httpTransport === "http-allowed",
        urls: [["audit.sinks.url", sink.url]],
        exposed: "audit events are",
      });
  if (
    governance?.sandbox?.endpoint !== undefined &&
    governance.sandbox.httpTransport !== "https"
  )
    endpoints.push({
      key: "sandbox.httpTransport",
      explicit: governance.sandbox.httpTransport === "http-allowed",
      urls: [
        ["sandbox.endpoint", governance.sandbox.endpoint],
        ["sandbox.router", governance.sandbox.router],
      ],
      exposed: "sandbox commands, their output, and files are",
    });
  for (const server of governance?.mcp?.servers ?? [])
    if (server.url !== undefined && server.httpTransport !== "https")
      endpoints.push({
        key: `mcp ${server.id} proxy`,
        urls: [[`mcp.servers.${server.id}.url`, server.url]],
        exposed: "",
        proxyOnly: true,
      });
  const policy = {
    ...DEFAULT_NETWORK_POLICY,
    inheritProxyEnvironment: data.access?.network.inheritProxy ?? true,
  };
  for (const endpoint of endpoints) {
    const plain: string[] = [];
    const proxied: string[] = [];
    let unresolved = false;
    for (const [field, template] of endpoint.urls) {
      if (template === undefined) continue;
      try {
        const url = new URL(
          resolveTemplate(
            field,
            template,
            access?.variables ?? [],
            process.env,
          ),
        );
        if (url.protocol === "http:") {
          plain.push(url.host);
          // A plain-HTTP request is refused through a proxy that is not
          // itself private (it would cross it unencrypted).
          const proxy = plainHttpProxy(url, policy);
          if (proxy && !isPrivateNetworkHost(proxy.hostname))
            proxied.push(url.hostname);
        }
      } catch {
        unresolved = true;
      }
    }
    if (proxied.length)
      out.bad(
        endpoint.key,
        `plain HTTP to ${proxied.join(", ")} would go through a proxy that is not a private host and is refused (NETWORK_DENIED); add ${proxied.join(", ")} to NO_PROXY`,
      );
    if (endpoint.proxyOnly) continue;
    if (plain.length)
      out.warn(
        endpoint.key,
        `http-allowed: plain HTTP to ${plain.join(", ")}; ${endpoint.exposed} unencrypted on the network path`,
      );
    else if (endpoint.explicit)
      out.info(
        endpoint.key,
        unresolved
          ? "http-allowed; the URL does not resolve here"
          : endpoint.key === "identity.oidc.httpTransport"
            ? "http-allowed; the issuer resolves to https"
            : "http-allowed; the URL resolves to https",
      );
  }
}

function networkLines(data: DoctorData, out: DoctorSection): void {
  plainHttpGroup(data, out);
  const access = data.access;
  if (!access) {
    out.info("outbound", "any host (personal mode; no PiShip network policy)");
    out.info(
      "agent commands",
      "not restricted (personal mode; child processes keep the shell's proxy and CA variables)",
    );
    return;
  }
  const network = access.network;
  if (access.tlsError) out.bad("TLS verification", "DISABLED in environment");
  else out.ok("TLS verification", "on");
  const hosts = network.allowHosts.join(", ");
  if (network.privateOnly)
    out.ok(
      "outbound",
      `private-only: declared hosts only${hosts ? ` (${hosts})` : ""}; public fallback denied`,
    );
  else if (data.ctx.mode === "managed")
    out.bad("outbound", "not private-only; public fallback is not enforced");
  else
    out.info(
      "outbound",
      "any host (personal mode; network.privateOnly is off)",
    );
  for (const item of network.undeclared)
    out.warn(
      item.label,
      `host ${item.host} is not a declared endpoint or in network.allowHosts; private-only requests to it fail with NETWORK_DENIED`,
    );
  const approved = network.approved;
  if (!network.inheritProxy)
    out.ok("proxy", "not used; network.proxy.inheritEnvironment is off");
  else if (approved) {
    const { http, https, noProxy } = approved.proxy;
    const proxies = [
      ...(http ? [`http ${http}`] : []),
      ...(https ? [`https ${https}`] : []),
    ];
    const checks = network.proxyChecks ?? [];
    const refused = checks.filter((check) => check.error);
    if (!proxies.length) out.ok("proxy", "none set in the environment");
    else if (refused.length)
      out.bad(
        "proxy",
        `active (${proxies.join(", ")}); cannot connect to ${refused.map((check) => `${check.proxy} (${check.error})`).join(", ")}: check that the proxy is running and that HTTPS_PROXY and HTTP_PROXY name it`,
      );
    else
      out.ok(
        "proxy",
        `active (${proxies.join(", ")})${checks.length ? "; accepts connections" : ""}`,
      );
    out.ok("NO_PROXY", noProxy ? "set" : "not set");
  }
  const paths = network.paths ?? [];
  if (network.caError) out.bad("enterprise CA", network.caError);
  else if (network.caBundles)
    out.ok(
      "enterprise CA",
      `${network.caBundles} additional bundle(s) declared${network.caCertificates === undefined ? "" : `; ${network.caCertificates} certificate(s) loaded`}`,
    );
  else if (paths.some((path) => path.code === "TLS_POLICY_VIOLATION"))
    out.warn(
      "enterprise CA",
      "none declared; default trust roots, and an endpoint failed TLS verification: if it uses an enterprise or private CA, declare that CA in network.tls.additionalCA",
    );
  else out.ok("enterprise CA", "none declared; default trust roots");
  for (const path of paths)
    if (path.error)
      out.bad(`path ${path.label}`, `${path.host}: ${path.error}`);
    else
      out.ok(
        `path ${path.label}`,
        `${path.host} answered (HTTP ${path.status})`,
      );
  if (!network.childrenRestricted) {
    out.info(
      "agent commands",
      "not restricted (personal mode; child processes keep the shell's proxy and CA variables)",
    );
    return;
  }
  if (!approved) return;
  const names = Object.keys(approved.variables);
  out.ok(
    "agent commands",
    `approved network variables only${names.length ? `: ${names.join(", ")}` : " (none)"}`,
  );
  for (const item of approved.withheld)
    out.warn(`withheld ${item.name}`, item.reason);
  for (const name of network.notApproved)
    out.info(
      `withheld ${name}`,
      "not passed to child processes: not approved by the network policy",
    );
}

/**
 * Who limits where each kind of process can connect. PiShip restricts only
 * what it can show: the private-only policy for Pi's own HTTP requests, and
 * the sandbox's network denial for tool subprocesses and MCP stdio servers.
 * Everything else is IT's firewall, proxy, DLP and EDR, which PiShip does not
 * read or verify, so it is reported as not enforced by PiShip.
 */
function egressLines(data: DoctorData, out: DoctorSection): void {
  const report = data.governance?.inspection?.sandbox;
  const denial =
    report?.level === "enforced" ? report.networkDenial : undefined;
  const denied = report?.level === "enforced" && report.network === "deny";
  // Only a live-probed denial is PiShip's to claim; an attested one is the
  // backend's word, reported as such.
  const verified = denied && denial?.evidence === "verified";
  // A personal default restricts nothing, so one line says so for every path.
  if (
    data.ctx.mode === "personal" &&
    !data.access?.network.privateOnly &&
    !denied
  ) {
    out.info(
      "egress",
      "not enforced by PiShip: Pi, extensions, shell, MCP stdio, Git and npm reach any host; only IT's firewall, proxy, DLP or EDR can limit it, and PiShip cannot verify them",
    );
    return;
  }
  if (data.access?.network.privateOnly)
    out.ok("egress: Pi", "PiShip: private-only, declared hosts");
  else
    out.info(
      "egress: Pi",
      "not restricted by PiShip (network.privateOnly is off)",
    );
  out.info(
    "egress: extensions",
    "not restricted by PiShip; in-process extensions are not contained",
  );
  const delegated = itEgress(data) && report?.network === "allow";
  const none = `not enforced by PiShip: no hostname-level egress control; only IT's firewall, proxy, DLP or EDR can limit it, and PiShip cannot verify them${report?.level === "enforced" ? "" : process.platform === "win32" ? " (Windows has no native sandbox adapter)" : ""}`;
  for (const label of ["shell", "MCP stdio"]) {
    const name = `egress: ${label}`;
    if (delegated)
      out.info(name, "delegated to IT (declared, not verified by PiShip)");
    else if (verified && report)
      out.ok(name, `PiShip: network ${networkText(report)}`);
    else if (denied && report)
      out.info(name, `not verified: network ${networkText(report)}`);
    else out.info(name, none);
  }
  out.info(
    "egress: Git, npm",
    "run as shell children or in the Pi process; covered as above, not separately",
  );
  out.info(
    "IT egress",
    delegated
      ? "declared by the distribution (sandbox.network.egress: it); PiShip reads no firewall, proxy, DLP or EDR state"
      : "externally attested at most; PiShip does not read endpoint firewall, proxy, DLP or EDR state",
  );
}

export function networkGroup(data: DoctorData, out: DoctorSection): void {
  networkLines(data, out);
  egressLines(data, out);
}
