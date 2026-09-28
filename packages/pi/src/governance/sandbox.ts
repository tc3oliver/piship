// The sandbox backend a distribution declares. PiShip resolves endpoints,
// decides whether the runtime credential may be sent, and loads a custom
// adapter from the verified payload; anything that cannot be built fails
// closed, since only a required sandbox uses a non-native backend.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { PiShipError, redact } from "@piship/contracts";
import {
  type CustomBackendContext,
  customBackend,
  E2bCompatibleBackend,
  KubernetesAgentSandboxBackend,
  type SandboxBackend,
} from "@piship/sandbox";
import type { GovernanceOptions } from "./options.js";

function unavailable(reason: string): PiShipError {
  return new PiShipError(
    "SANDBOX_UNAVAILABLE",
    `The distribution requires a sandbox, but its backend cannot be used: ${redact(reason)}`,
    {
      component: "sandbox",
      userAction:
        "Fix the sandbox backend configuration or its runtime variables; PiShip does not fall back to running unsandboxed",
    },
  );
}

function origin(url: string): string | undefined {
  try {
    const { origin: value } = new URL(url);
    return value === "null" ? undefined : value;
  } catch {
    return undefined;
  }
}

/**
 * The runtime credential for the given URLs, only when every one of them is
 * on an origin the credential is issued for (the rule MCP servers follow).
 */
function runtimeCredential(
  options: GovernanceOptions,
  urls: readonly string[],
): () => Promise<string | undefined> {
  const provide = options.credential;
  if (!provide)
    throw unavailable(
      "sandbox.credential is runtime, but this launch has no runtime credential",
    );
  const allowed = new Set(
    (options.credentialOrigins ?? []).map(origin).filter(Boolean),
  );
  for (const url of urls)
    if (!allowed.has(origin(url)))
      throw unavailable(
        `the runtime credential is only sent to ${allowed.size ? [...allowed].join(", ") : "the inference gateway origin, which is not configured"}, not to ${origin(url) ?? "an invalid URL"}`,
      );
  return provide;
}

function resolve(
  options: GovernanceOptions,
  field: string,
  template: string | undefined,
): string | undefined {
  if (template === undefined) return undefined;
  try {
    return options.resolveTemplate(field, template);
  } catch (error) {
    throw unavailable(String((error as Error)?.message ?? error));
  }
}

async function loadCustom(
  options: GovernanceOptions,
  adapter: string,
  context: CustomBackendContext,
): Promise<SandboxBackend> {
  const path = join(
    options.distributionDir,
    "resources",
    ...adapter.slice(2).split("/"),
  );
  try {
    const module = (await import(pathToFileURL(path).href)) as {
      default?: unknown;
    };
    if (typeof module.default !== "function")
      throw new Error("the adapter must default-export a factory function");
    return customBackend(
      await (module.default as (value: unknown) => unknown)(context),
    );
  } catch (error) {
    throw unavailable(
      `the custom sandbox adapter could not be loaded: ${String((error as Error)?.message ?? error)}`,
    );
  }
}

/** The declared backend, or undefined for the native OS sandbox. */
export async function sandboxBackend(
  options: GovernanceOptions,
): Promise<SandboxBackend | undefined> {
  const config = options.lock.governance.manifest.sandbox;
  if (!config.required || config.provider === undefined) return undefined;
  const endpoint = resolve(options, "sandbox.endpoint", config.endpoint);
  const router = resolve(options, "sandbox.router", config.router);
  const targets = [endpoint, router].filter(
    (url): url is string => url !== undefined,
  );
  const credential =
    config.credential === "runtime"
      ? runtimeCredential(options, targets)
      : undefined;
  const remote = {
    fetch: options.fetch,
    ...(credential ? { credential } : {}),
    ...(config.workdir ? { workdir: config.workdir } : {}),
  };
  try {
    switch (config.provider) {
      case "e2b-compatible":
        return new E2bCompatibleBackend({
          ...remote,
          endpoint: endpoint ?? "",
          ...(config.template ? { template: config.template } : {}),
          ...(config.user ? { user: config.user } : {}),
        });
      case "kubernetes-agent-sandbox":
        return new KubernetesAgentSandboxBackend({
          ...remote,
          endpoint: endpoint ?? "",
          router: router ?? "",
          template: config.template ?? "",
          ...(config.namespace ? { namespace: config.namespace } : {}),
        });
      case "custom":
        return await loadCustom(options, config.adapter ?? "", {
          distributionId: options.lock.app.id,
          fetch: options.fetch,
          ...(endpoint ? { endpoint } : {}),
          ...(credential ? { credential } : {}),
        });
    }
  } catch (error) {
    if (error instanceof PiShipError) throw error;
    throw unavailable(String((error as Error)?.message ?? error));
  }
}
