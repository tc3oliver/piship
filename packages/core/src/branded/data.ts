// The retention sweep of a built distribution at launch and logout.
import { formatError, redact } from "@piship/contracts";
import {
  type DataSweepResult,
  type DataSweepTrigger,
  declaredRetention,
  sweepData,
  sweepRetention,
} from "../data/lifecycle.js";
import { type BrandedContext, recordAudit } from "./context.js";
import { lifecycleNetwork } from "./lifecycle.js";

/**
 * Sweep what the declared retention no longer keeps (at logout, also purge
 * `data.purge.onLogout`). A distribution without a `data` section sweeps
 * nothing. Each class's `data.swept` event is recorded first; when a
 * required audit sink does not take it, that class is kept. Never throws:
 * what could not be done is a warning.
 */
export async function sweepDistributionData(
  ctx: BrandedContext,
  trigger: DataSweepTrigger,
  options: {
    /** packages/pi passes its live session owner check. */
    readonly sessionHeld?: (sessionFile: string) => boolean;
    readonly now?: number;
  } = {},
): Promise<DataSweepResult | undefined> {
  const data = ctx.metadata.data?.declared;
  if (!data) return undefined;
  try {
    const network = lifecycleNetwork(ctx);
    const result = await sweepData({
      stateDir: ctx.stateDir,
      trigger,
      retention: sweepRetention(
        trigger,
        declaredRetention(data),
        data.purge.onLogout,
      ),
      record: (event) =>
        recordAudit(
          ctx,
          network,
          [{ ...event, user: null, session: null }],
          `The ${event.resource} retention sweep did not run`,
        ),
      ...(options.sessionHeld ? { sessionHeld: options.sessionHeld } : {}),
      ...(options.now === undefined ? {} : { now: options.now }),
    });
    for (const entry of result.classes) {
      if (entry.unrecorded)
        ctx.err(
          `Warning: ${entry.class} past their retention were kept: the data.swept audit event was not recorded`,
        );
      else if (entry.failed)
        ctx.err(
          `Warning: ${entry.failed} ${entry.class} file${entry.failed > 1 ? "s" : ""} past the retention could not be deleted; the next sweep retries`,
        );
    }
    return result;
  } catch (error) {
    ctx.err(
      `Warning: the data retention sweep did not run: ${redact(formatError(error))}`,
    );
    return undefined;
  }
}
