import type { LocalMetrics } from "@piship/audit";
import { PiShipError } from "@piship/contracts";

/**
 * The local metrics access records: identity and credential durations, gateway
 * reachability, live catalog fetches, and adapter load failures. Only numbers
 * and PiShip error codes cross this boundary; `LocalMetrics` implements it.
 */
export type AccessMetrics = Pick<
  LocalMetrics,
  | "recordIdentityLatency"
  | "recordCredentialLatency"
  | "recordGatewayReachability"
  | "recordModelCatalogFetch"
  | "recordLoadFailure"
>;

/** Error codes that mean the gateway did not answer at all. */
const GATEWAY_UNREACHABLE_CODES = new Set<string>([
  "GATEWAY_UNREACHABLE",
  "NETWORK_DENIED",
  "TLS_POLICY_VIOLATION",
]);

/**
 * Record the result of a gateway probe. A gateway that answered with a
 * rejection (401, 403, 404, 429, a malformed list) is reachable. Transport
 * failures, destination refusals, TLS policy failures, timeouts, and 5xx
 * answers (which map to GATEWAY_UNREACHABLE) are recorded as unreachable.
 */
export function recordGatewayResult(
  metrics: Pick<AccessMetrics, "recordGatewayReachability"> | undefined,
  error?: unknown,
): void {
  if (!metrics) return;
  try {
    if (error === undefined) metrics.recordGatewayReachability(true);
    else if (!(error instanceof PiShipError))
      metrics.recordGatewayReachability(false, "UNKNOWN");
    else if (GATEWAY_UNREACHABLE_CODES.has(error.code))
      metrics.recordGatewayReachability(false, error.code);
    else metrics.recordGatewayReachability(true);
  } catch {
    // Metrics never break access.
  }
}
