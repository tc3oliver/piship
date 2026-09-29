// The sandbox backend a distribution declares. PiShip resolves endpoints,
// decides which credential may be sent where, and loads a custom adapter
// from the verified payload; anything that cannot be built fails closed,
// since only a required sandbox uses a non-native backend.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { PiShipError, redact } from "@piship/contracts";
import { AdapterSandboxCredential } from "@piship/core";
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

/** What a backend is given to authenticate, and to whom it may send it. */
interface Credentialing {
  readonly credential?: () => Promise<string | undefined>;
  readonly credentialRejected?: () => Promise<boolean>;
  readonly credentialOrigins?: readonly string[];
}

/**
 * The runtime credential for the given URLs, only when every one of them is
 * on an origin the credential is issued for (the rule MCP servers follow).
 */
function runtimeCredential(
  options: GovernanceOptions,
  urls: readonly string[],
): Credentialing {
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
  return {
    credential: provide,
    credentialOrigins: [...allowed] as string[],
  };
}

/**
 * The stored sandbox credential for the given URLs. Core refuses it, before
 * the secret is read, unless it is the launch principal's and was stored
 * for every one of these origins; the check is repeated here so no URL
 * outside the returned origins is ever handed the credential.
 */
async function storedCredential(
  options: GovernanceOptions,
  urls: readonly string[],
): Promise<Credentialing> {
  const provide = options.sandboxCredential;
  if (!provide)
    throw unavailable(
      "sandbox.credential is stored, but this launch has no signed-in user to check the stored sandbox credential against",
    );
  const access = await provide(urls);
  const allowed = new Set(access.origins);
  for (const url of urls)
    if (!allowed.has(origin(url) ?? ""))
      throw unavailable(
        "the stored sandbox credential is not sent to an origin it was not stored for",
      );
  return {
    credential: async () => (await access.secret()).reveal(),
    // A stored secret is the user's: it is marked rejected, never renewed
    // here, so the request is not repeated.
    credentialRejected: async () => {
      await access.rejected();
      return false;
    },
    credentialOrigins: access.origins,
  };
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

/** Revoke the adapter's in-memory credential when the instance is gone. */
function releasing(
  backend: SandboxBackend,
  release: () => Promise<void>,
): SandboxBackend {
  return {
    id: backend.id,
    provider: backend.provider,
    available: () => backend.available(),
    capabilities: () => backend.capabilities(),
    prepare: async (request) => {
      let instance: Awaited<ReturnType<SandboxBackend["prepare"]>>;
      try {
        instance = await backend.prepare(request);
      } catch (error) {
        await release().catch(() => undefined);
        throw error;
      }
      return {
        ...instance,
        dispose: async () => {
          try {
            await instance.dispose();
          } finally {
            await release().catch(() => undefined);
          }
        },
      };
    },
  };
}

async function loadCustom(
  options: GovernanceOptions,
  adapter: string,
  endpoint: string | undefined,
  declared: Credentialing,
): Promise<SandboxBackend> {
  const path = join(
    options.distributionDir,
    "resources",
    ...adapter.slice(2).split("/"),
  );
  let module: { default?: unknown; sandboxCredential?: unknown };
  try {
    module = (await import(pathToFileURL(path).href)) as typeof module;
  } catch (error) {
    throw unavailable(
      `the custom sandbox adapter could not be loaded: ${String((error as Error)?.message ?? error)}`,
    );
  }
  const config = options.lock.governance.manifest.sandbox;
  let credentialing = declared;
  let own: AdapterSandboxCredential | undefined;
  if (module.sandboxCredential !== undefined) {
    // One credential per backend: an adapter credential and a declared one
    // would leave it unclear which is sent where.
    if (config.credential !== undefined)
      throw unavailable(
        `the custom sandbox adapter exports sandboxCredential, but sandbox.credential is ${config.credential}; declare one or the other`,
      );
    const endpointOrigin = endpoint ? origin(endpoint) : undefined;
    own = new AdapterSandboxCredential({
      distributionId: options.lock.app.id,
      command: options.lock.app.command,
      provider: module.sandboxCredential,
      identity: options.sandboxIdentity?.current ?? (async () => null),
      principal: options.sandboxIdentity?.principal ?? null,
      origins: endpointOrigin ? [endpointOrigin] : [],
      ...(options.onSandboxCredentialEvent
        ? { onEvent: options.onSandboxCredentialEvent }
        : {}),
    });
    const access = await own.access();
    credentialing = {
      credential: async () => (await access.secret()).reveal(),
      // An organization-issued credential is renewed once, and the one
      // request that created nothing is repeated with it.
      credentialRejected: async () => {
        await access.rejected();
        return true;
      },
      credentialOrigins: access.origins,
    };
  }
  const context: CustomBackendContext = {
    distributionId: options.lock.app.id,
    fetch: options.fetch,
    ...(endpoint ? { endpoint } : {}),
    ...credentialing,
  };
  let backend: SandboxBackend;
  try {
    if (typeof module.default !== "function")
      throw new Error("the adapter must default-export a factory function");
    backend = customBackend(
      await (module.default as (value: unknown) => unknown)(context),
    );
  } catch (error) {
    await own?.revoke().catch(() => undefined);
    throw unavailable(
      `the custom sandbox adapter could not be loaded: ${String((error as Error)?.message ?? error)}`,
    );
  }
  return own ? releasing(backend, () => own.revoke()) : backend;
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
  try {
    const credentialing: Credentialing =
      config.credential === "runtime"
        ? runtimeCredential(options, targets)
        : config.credential === "stored"
          ? await storedCredential(options, targets)
          : {};
    const remote = {
      fetch: options.fetch,
      ...(credentialing.credential
        ? { credential: credentialing.credential }
        : {}),
      ...(credentialing.credentialRejected
        ? { credentialRejected: credentialing.credentialRejected }
        : {}),
      ...(config.workdir ? { workdir: config.workdir } : {}),
    };
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
        return await loadCustom(
          options,
          config.adapter ?? "",
          endpoint,
          credentialing,
        );
    }
  } catch (error) {
    if (error instanceof PiShipError) throw error;
    throw unavailable(String((error as Error)?.message ?? error));
  }
}
