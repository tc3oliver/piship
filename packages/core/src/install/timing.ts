// Phase markers for `PISHIP_DEBUG_TIMING=1`: each lap reports the time since
// the previous one.
import { debugTiming } from "../lock.js";

export function stopwatch(): (label: string) => void {
  let last = process.hrtime.bigint();
  return (label) => {
    debugTiming(label, last);
    last = process.hrtime.bigint();
  };
}
