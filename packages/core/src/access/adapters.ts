import { existsSync } from "node:fs";
import { resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
  ADAPTER_CALL_TIMEOUT_MS,
  type AdapterContext,
  callWithDeadline,
  PiShipError,
} from "@piship/contracts";

// Defined in @piship/contracts so the adapter SDK can name it without core.
export type { AdapterContext };

export async function loadAdapter<T>(
  distributionDir: string,
  path: string,
  kind: string,
  context: AdapterContext,
  timeoutMs: number = ADAPTER_CALL_TIMEOUT_MS,
): Promise<T> {
  const base = resolve(distributionDir, "resources");
  const absolute = resolve(base, ...path.slice(2).split("/"));
  if (!absolute.startsWith(`${base}${sep}`) || !existsSync(absolute))
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter is missing from the verified payload: ${path}`,
      {
        component: kind,
      },
    );
  // Importing the module and running its factory are the adapter's code: a
  // top-level await or a factory that never settles must not hang PiShip.
  const instance = await callWithDeadline(
    async () => {
      const module = (await import(pathToFileURL(absolute).href)) as {
        default?: unknown;
      };
      if (typeof module.default !== "function")
        throw new PiShipError(
          "CONFIG_INVALID",
          `The ${kind} adapter must default-export a factory function`,
          {
            component: kind,
          },
        );
      return (module.default as (context: AdapterContext) => unknown)(context);
    },
    {
      timeoutMs,
      timedOut: () =>
        new PiShipError(
          "CONFIG_UNAVAILABLE",
          `The ${kind} adapter ${path} did not load within ${Math.ceil(timeoutMs / 1000)} s`,
          {
            component: kind,
            retryable: true,
            sanitizedDetail: {
              adapter: path,
              phase: "load",
              reason: "timeout",
              timeoutMs,
            },
          },
        ),
      // No caller signal: never called.
      cancelled: () => undefined,
    },
  );
  if (!instance || typeof instance !== "object")
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter factory returned no provider`,
      { component: kind },
    );
  return instance as T;
}
