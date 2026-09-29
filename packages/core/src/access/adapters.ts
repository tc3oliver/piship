import { existsSync } from "node:fs";
import { resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { type AdapterContext, PiShipError } from "@piship/contracts";

// Defined in @piship/contracts so the adapter SDK can name it without core.
export type { AdapterContext };

export async function loadAdapter<T>(
  distributionDir: string,
  path: string,
  kind: string,
  context: AdapterContext,
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
  const instance = await (
    module.default as (context: AdapterContext) => unknown
  )(context);
  if (!instance || typeof instance !== "object")
    throw new PiShipError(
      "CONFIG_INVALID",
      `The ${kind} adapter factory returned no provider`,
      { component: kind },
    );
  return instance as T;
}
