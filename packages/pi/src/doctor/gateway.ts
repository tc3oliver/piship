// Gateway group: the managed inference endpoint (by origin only) and whether
// its model list answers.
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

export function gatewayGroup(data: DoctorData, out: DoctorSection): void {
  const access = data.access;
  if (!access || access.configError) return;
  const activation = access.activation;
  if (!activation) {
    out.info("gateway", "not checked; access did not activate");
    return;
  }
  if (activation.runtime !== "managed-endpoint") {
    out.info(
      "gateway",
      "not used; the runtime uses Pi's own provider configuration",
    );
    return;
  }
  if (activation.gatewayOrigin) out.ok("endpoint", activation.gatewayOrigin);
  if (access.gateway?.error) out.bad("gateway", access.gateway.error);
  else if (access.gateway?.listed !== undefined)
    out.ok("gateway", `reachable (${access.gateway.listed} listed)`);
  else out.info("gateway", "not probed; the provider has no model list");
}
