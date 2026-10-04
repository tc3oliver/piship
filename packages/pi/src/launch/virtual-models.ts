// Virtual model registration. Pi queues an extension's registerVirtualModel
// while extensions load and registers the queue when the session binds them,
// where a failure is an error event no listener hears yet and the extension
// path is dropped. PiShip registers the queue itself, right after the loader
// loads (at launch and on /reload), as Pi's own createAgentSessionServices
// does, so that the router's identity is known and a refusal fails the load.
import { realpathSync } from "node:fs";
import { join, sep } from "node:path";
import type {
  DefaultResourceLoader,
  ModelRuntime,
} from "@earendil-works/pi-coding-agent";
import { PiShipError } from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import type { GovernedRuntime, VirtualModelRule } from "../governance.js";

const real = (path: string): string => {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
};

/** Built path of a declared router: a `./` path or a certified extension id. */
export function routerPath(
  lock: DistributionLock,
  distributionDir: string,
  router: string,
): string | undefined {
  const declared = router.startsWith("./")
    ? router
    : lock.governance?.certified.find(
        (entry) => entry.kind === "extensions" && entry.evidence.id === router,
      )?.path;
  // `package:<id>` resolves once Pi packages are vendored; until then it
  // names no built extension and nothing may register the model.
  if (!declared || !lock.declared.extensions.includes(declared))
    return undefined;
  return join(distributionDir, "resources", ...declared.slice(2).split("/"));
}

/**
 * The declared virtual models of a lock: managed ones under the managed
 * provider (routes are bare catalog ids), pi-native ones keyed provider/id.
 */
export function virtualModelRules(
  lock: DistributionLock,
  distributionDir: string,
  managedProviderId?: string,
): VirtualModelRule[] {
  const split = (id: string) => {
    if (managedProviderId) return { provider: managedProviderId, id };
    const [provider = "", ...rest] = id.split("/");
    return { provider, id: rest.join("/") };
  };
  return (lock.access?.models.catalog ?? []).flatMap((entry) => {
    if (!entry.virtual) return [];
    const path = routerPath(lock, distributionDir, entry.virtual.router);
    return [
      {
        ...split(entry.id),
        routes: entry.virtual.routes.map(split),
        router: entry.virtual.router,
        ...(path ? { routerPath: path } : {}),
      },
    ];
  });
}

/**
 * Register the loaded extensions' virtual models now, and again after every
 * reload of the resource loader (Pi's `/reload` calls it), so a refusal fails
 * the launch or the reload instead of being dropped.
 */
export function governVirtualModels(
  resourceLoader: DefaultResourceLoader,
  governed: GovernedRuntime,
  modelRuntime: Pick<
    ModelRuntime,
    "registerVirtualModel" | "unregisterVirtualModel"
  >,
  rules: readonly VirtualModelRule[],
): void {
  let registered = registerVirtualModels(
    resourceLoader,
    governed,
    modelRuntime,
    rules,
  );
  const reload = resourceLoader.reload.bind(resourceLoader);
  resourceLoader.reload = async () => {
    const previous = registered;
    const next = new Set<string>();
    let failed = true;
    try {
      await reload();
      registerVirtualModels(
        resourceLoader,
        governed,
        modelRuntime,
        rules,
        next,
      );
      failed = false;
    } finally {
      // Pi keeps a registration the reloaded extensions no longer make, with
      // the replaced router; it is removed, so the model fails closed. A
      // failed reload removes them all, the ones it registered included.
      registered = failed ? new Set() : next;
      for (const name of new Set([...previous, ...next]))
        if (!registered.has(name)) {
          const rule = rules.find(
            (item) => `${item.provider}/${item.id}` === name,
          );
          if (rule)
            governed.withRegistrationWindow(() =>
              modelRuntime.unregisterVirtualModel(rule.provider, rule.id),
            );
        }
    }
  };
}

/** Whether an extension Pi loaded from `extensionPath` is the declared router. */
function fromRouter(extensionPath: string, router: string): boolean {
  const loaded = real(extensionPath);
  const declared = real(router);
  return loaded === declared || loaded.startsWith(`${declared}${sep}`);
}

/**
 * Register the virtual models the loaded extensions queued. Each must be a
 * declared virtual model, registered by its declared router; anything else
 * fails the launch (or the reload). The queue is emptied, so Pi registers
 * nothing further when it binds the extensions. Returns the registered
 * `provider/id` names, added to `registered` as they register, so a caller
 * knows them even when a later one fails.
 */
export function registerVirtualModels(
  resourceLoader: Pick<DefaultResourceLoader, "getExtensions">,
  governed: GovernedRuntime,
  modelRuntime: Pick<ModelRuntime, "registerVirtualModel">,
  rules: readonly VirtualModelRule[],
  registered: Set<string> = new Set(),
): Set<string> {
  const runtime = resourceLoader.getExtensions().runtime;
  const pending = runtime.pendingVirtualModelRegistrations;
  runtime.pendingVirtualModelRegistrations = [];
  for (const { definition, extensionPath } of pending) {
    const name = `${definition.provider}/${definition.id}`;
    const rule = rules.find(
      (item) =>
        item.provider === definition.provider && item.id === definition.id,
    );
    if (!rule)
      throw new PiShipError(
        "MODEL_DENIED",
        `Virtual model ${name}, registered by ${extensionPath}, is not in models.catalog`,
        { component: "inference" },
      );
    if (!rule.routerPath || !fromRouter(extensionPath, rule.routerPath))
      throw new PiShipError(
        "POLICY_DENIED",
        `Virtual model ${name} was registered by ${extensionPath}; its declared router is ${rule.router}`,
        { component: "inference" },
      );
    try {
      governed.withRegistrationWindow(() =>
        modelRuntime.registerVirtualModel(definition),
      );
    } catch (error) {
      throw new PiShipError(
        "CONFIG_INVALID",
        `Virtual model ${name} could not be registered: ${(error as Error).message}`,
        { component: "inference" },
      );
    }
    registered.add(name);
  }
  return registered;
}
