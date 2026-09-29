// Network group: TLS verification, the outbound policy, the proxy and
// enterprise CA settings, and the network environment child processes
// receive. Proxies are shown as scheme://host:port only; NO_PROXY and
// withheld variables by name, never by value.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function networkGroup(data: DoctorData, out: DoctorSection): void {
  const access = data.access;
  if (!access) {
    out.info("outbound", "any host (personal mode; no PiShip network policy)");
    out.info(
      "child environment",
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
    out.ok(
      "proxy",
      proxies.length
        ? `active (${proxies.join(", ")})`
        : "none set in the environment",
    );
    out.ok("NO_PROXY", noProxy ? "set" : "not set");
  }
  out.ok(
    "enterprise CA",
    network.caBundles
      ? `${network.caBundles} additional bundle(s) declared`
      : "none declared; default trust roots",
  );
  if (!network.childrenRestricted) {
    out.info(
      "child environment",
      "not restricted (personal mode; child processes keep the shell's proxy and CA variables)",
    );
    return;
  }
  if (!approved) return;
  const names = Object.keys(approved.variables);
  out.ok(
    "child environment",
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
