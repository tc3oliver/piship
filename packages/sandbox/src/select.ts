import { PiShipError } from "@piship/contracts";
import type {
  AdapterAvailability,
  SandboxAdapter,
  SandboxAdapterId,
  WrappedCommand,
} from "./adapter.js";
import { BubblewrapAdapter } from "./bubblewrap.js";
import { SeatbeltAdapter } from "./seatbelt.js";

/** Environment override used by tests and diagnostics to force an adapter. */
export const ADAPTER_OVERRIDE_VARIABLE = "PISHIP_SANDBOX_ADAPTER";

/** Windows and every platform without a supported mechanism. */
export class UnsupportedAdapter implements SandboxAdapter {
  readonly id = "unsupported" as const;
  readonly #platform: string;

  constructor(platform: string = process.platform) {
    this.#platform = platform;
  }

  async available(): Promise<AdapterAvailability> {
    return {
      available: false,
      reason: `A managed sandbox is not supported on this platform (${this.#platform}); tool subprocesses cannot be contained`,
    };
  }

  wrap(): WrappedCommand {
    throw new PiShipError(
      "SANDBOX_UNAVAILABLE",
      `A managed sandbox is not supported on this platform (${this.#platform})`,
      { component: "sandbox" },
    );
  }
}

export function adapterIdFor(
  platform: NodeJS.Platform | string = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): SandboxAdapterId {
  if (env[ADAPTER_OVERRIDE_VARIABLE] === "unsupported") return "unsupported";
  if (platform === "linux") return "linux-bubblewrap";
  if (platform === "darwin") return "macos-seatbelt";
  return "unsupported";
}

/** Choose the adapter for a platform (defaults to the current one). */
export function selectAdapter(
  platform: NodeJS.Platform | string = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): SandboxAdapter {
  switch (adapterIdFor(platform, env)) {
    case "linux-bubblewrap":
      return new BubblewrapAdapter();
    case "macos-seatbelt":
      return new SeatbeltAdapter();
    default:
      return new UnsupportedAdapter(platform);
  }
}
