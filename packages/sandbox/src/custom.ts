// Custom backends: a company's own sandbox or remote execution service,
// shipped as a module in the distribution. PiShip checks the shape of what
// the module returns and keeps the provider fixed to `custom`; it trusts
// nothing the module declares until activation checked it.
import type { ManagedFetch } from "@piship/contracts";
import { SANDBOX_ADAPTER_IDS } from "./adapter.js";
import {
  isBackendId,
  SANDBOX_PROVIDERS,
  type SandboxBackend,
  type SandboxInstance,
} from "./backend.js";

/** What a custom adapter module's default-export factory receives. */
export interface CustomBackendContext {
  readonly distributionId: string;
  /** PiShip's managed fetch: proxy, CA, and private-only policy applied. */
  readonly fetch: ManagedFetch;
  /** The resolved `sandbox.endpoint`, when declared. */
  readonly endpoint?: string;
  /**
   * The runtime credential, when `sandbox.credential: runtime` is declared
   * and the endpoint is on an origin the credential is issued for.
   */
  readonly credential?: () => Promise<string | undefined>;
}

const RESERVED = new Set<string>([
  ...SANDBOX_ADAPTER_IDS,
  ...SANDBOX_PROVIDERS,
]);

function invalid(reason: string): Error {
  return new Error(`The custom sandbox adapter is invalid: ${reason}`);
}

function checkInstance(value: unknown): SandboxInstance {
  const instance = value as Partial<SandboxInstance> | null;
  if (
    !instance ||
    typeof instance !== "object" ||
    typeof instance.exec !== "function" ||
    typeof instance.dispose !== "function" ||
    (instance.wrap !== undefined && typeof instance.wrap !== "function") ||
    (instance.epoch !== undefined && typeof instance.epoch !== "function")
  )
    throw invalid("prepare() must return an object with exec() and dispose()");
  const exec = instance.exec.bind(instance);
  const dispose = instance.dispose.bind(instance);
  const wrap = instance.wrap?.bind(instance);
  const epoch = instance.epoch?.bind(instance);
  return {
    exec: (request, io) => exec(request, io),
    dispose: async () => {
      await dispose();
    },
    ...(wrap ? { wrap: (command) => wrap(command) } : {}),
    ...(epoch
      ? {
          epoch: () => {
            const value: unknown = epoch();
            return typeof value === "string" ? value : undefined;
          },
        }
      : {}),
  };
}

/** Check a custom adapter's backend object and fix its provider to `custom`. */
export function customBackend(value: unknown): SandboxBackend {
  const backend = value as Partial<SandboxBackend> | null;
  if (!backend || typeof backend !== "object")
    throw invalid("the factory returned no backend object");
  if (!isBackendId(backend.id))
    throw invalid("id must be a short lowercase identifier");
  if (RESERVED.has(backend.id))
    throw invalid(`id ${backend.id} is reserved for a built-in backend`);
  for (const method of ["available", "capabilities", "prepare"] as const)
    if (typeof backend[method] !== "function")
      throw invalid(`${method}() is missing`);
  const source = backend as SandboxBackend;
  return {
    id: source.id,
    provider: "custom",
    available: () => source.available(),
    capabilities: () => source.capabilities(),
    prepare: async (request) => checkInstance(await source.prepare(request)),
  };
}
