import {
  PiShipError,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  sanitizeManagedEnvironment,
} from "@piship/contracts";
import {
  type AccessEvent,
  type ActivatedAccess,
  type BrandedContext,
  type DistributionAccess,
  openAccess,
} from "@piship/core";
import type { LocalMetrics } from "@piship/audit";
import { VERSION } from "@earendil-works/pi-coding-agent";
import { launchMetrics, saveMetrics } from "../launch-metrics.js";

export interface LaunchContext extends BrandedContext {
  readonly agentDir: string;
}

/**
 * Access lifecycle events raised before the audit log is open are buffered,
 * then forwarded as they happen once a governed session exists.
 */
export class AccessEvents {
  #buffer: AccessEvent[] = [];
  #target: ((event: AccessEvent) => void) | null = null;
  readonly listener = (event: AccessEvent): void => {
    if (this.#target) this.#target(event);
    else this.#buffer.push(event);
  };
  drain(): AccessEvent[] {
    const events = this.#buffer;
    this.#buffer = [];
    return events;
  }
  forward(target: ((event: AccessEvent) => void) | null): void {
    if (target) for (const event of this.drain()) target(event);
    this.#target = target;
  }
}

export interface PreparedAccess {
  readonly metrics: LocalMetrics | undefined;
  readonly access: DistributionAccess | null;
  readonly activated: ActivatedAccess | null;
  readonly removedEnvironment: readonly string[];
  readonly events: AccessEvents;
}

export async function prepareAccess(
  ctx: LaunchContext,
  requestedModel: string | undefined,
): Promise<PreparedAccess> {
  const metrics = launchMetrics(ctx.metadata, ctx.stateDir, VERSION);
  if (!ctx.metadata.access) {
    if (requestedModel && !/^[^/]+\/.+$/.test(requestedModel))
      throw new PiShipError(
        "MODEL_DENIED",
        "Use --model provider/model for Pi-native distributions",
      );
    return {
      metrics,
      access: null,
      activated: null,
      removedEnvironment: [],
      events: new AccessEvents(),
    };
  }
  // Refuse before sanitizing: silently dropping a disabled-TLS setting would hide it.
  assertTlsVerificationEnabled();
  const events = new AccessEvents();
  const access = openAccess(ctx, events.listener, metrics);
  let removedEnvironment: string[] = [];
  if (ctx.mode === "managed")
    removedEnvironment = sanitizeManagedEnvironment(
      process.env,
      access.network,
      ctx.metadata.access.variables,
    );
  // Only a managed distribution narrows what child processes inherit; a
  // personal one keeps the environment of the user's shell.
  applyProcessNetworkPolicy(access.network, {
    restrictChildren: ctx.mode === "managed",
  });
  try {
    const activated = await access.activate(
      requestedModel ? { requestedModel } : {},
    );
    return { metrics, access, activated, removedEnvironment, events };
  } finally {
    saveMetrics(metrics);
  }
}
