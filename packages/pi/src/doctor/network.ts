// Network group: TLS verification, the outbound policy, the proxy and
// enterprise CA settings, and the network environment the agent's own
// commands (the bash tool) receive; MCP stdio servers only get env.allow.
// Proxies are shown as scheme://host:port only; NO_PROXY and withheld
// variables by name, never by value.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function networkGroup(data: DoctorData, out: DoctorSection): void {
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
