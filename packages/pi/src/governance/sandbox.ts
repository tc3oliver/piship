// The sandbox backend a distribution declares. PiShip resolves endpoints,
// decides which credential may be sent where, and loads a custom adapter
// from the verified payload; anything that cannot be built fails closed,
// since only a required sandbox uses a non-native backend.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  ADAPTER_CALL_TIMEOUT_MS,
  type CredentialProvider,
  callWithDeadline,
  isPrivateNetworkHost,
  PiShipError,
  plainHttpOrigins,
  redact,
} from "@piship/contracts";
import {
  AdapterSandboxCredential,
  boundedCredentialProvider,
} from "@piship/core";
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
  // The module and its factory are the distribution's code: neither may
  // hang the launch.
  const timeoutMs = options.adapterTimeoutMs ?? ADAPTER_CALL_TIMEOUT_MS;
  const bounded = <T>(what: string, call: () => Promise<T>): Promise<T> =>
    callWithDeadline(call, {
      timeoutMs,
      timedOut: () =>
        new Error(
          `${what} did not settle within ${Math.ceil(timeoutMs / 1000)} s`,
        ),
      cancelled: () => new Error(`${what} was cancelled`),
    });
  let module: { default?: unknown; sandboxCredential?: unknown };
  try {
    module = (await bounded(
      "the module",
      () => import(pathToFileURL(path).href),
    )) as typeof module;
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
      // Bounded like a credential adapter; anything else is refused there.
      provider:
        typeof (module.sandboxCredential as Partial<CredentialProvider> | null)
          ?.acquire === "function"
          ? boundedCredentialProvider(
              module.sandboxCredential as CredentialProvider,
              `${adapter} sandboxCredential`,
              options.adapterTimeoutMs
                ? {
                    timeoutMs: options.adapterTimeoutMs,
                    interactiveTimeoutMs: options.adapterTimeoutMs,
                  }
                : {},
            )
          : module.sandboxCredential,
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
    const factory = module.default as (value: unknown) => unknown;
    backend = customBackend(
      await bounded("the factory", async () => factory(context)),
      options.adapterTimeoutMs
        ? {
            availableMs: options.adapterTimeoutMs,
            prepareMs: options.adapterTimeoutMs,
            disposeMs: options.adapterTimeoutMs,
          }
        : {},
    );
  } catch (error) {
    await own?.revoke().catch(() => undefined);
    throw unavailable(
      `the custom sandbox adapter could not be loaded: ${String((error as Error)?.message ?? error)}`,
    );
  }
  return own ? releasing(backend, () => own.revoke()) : backend;
}

/**
 * The fetch for the sandbox backend. With `sandbox.httpTransport:
 * http-allowed` a resolved endpoint or router may be plain HTTP to a
 * private or internal host, and only those origins are admitted over plain
 * HTTP; an e2b-compatible backend's command endpoint (envd) is a host
 * under the endpoint's domain, admitted when it is private too.
 */
function sandboxFetch(
  options: GovernanceOptions,
  fields: readonly (readonly [string, string | undefined])[],
): GovernanceOptions["fetch"] {
  const config = options.lock.governance.manifest.sandbox;
  if (config.httpTransport !== "http-allowed") return options.fetch;
  const urls: URL[] = [];
  for (const [field, value] of fields) {
    if (value === undefined) continue;
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw unavailable(`${field} resolved to a value that is not a URL`);
    }
    if (url.protocol === "http:" && !isPrivateNetworkHost(url.hostname))
      throw unavailable(
        `${field} is plain HTTP to ${url.hostname}, which is public; sandbox.httpTransport: http-allowed permits plain HTTP only to a private or internal host`,
      );
    urls.push(url);
  }
  const exact = plainHttpOrigins(urls);
  if (!exact || !options.plainHttpFetch) return options.fetch;
  const endpoint = urls[0];
  const envdDomain =
    config.provider === "e2b-compatible" && endpoint?.protocol === "http:"
      ? endpoint.hostname.replace(/^api\./, "")
      : undefined;
  // envd is `<port>-<sandbox id>.<domain>` on the scheme's default port, as
  // the backend builds its URL (no port of its own). It is matched by name:
  // the sandbox ID is known only once the sandbox exists. An IP-literal
  // endpoint has no domain to put it under, so envd is never admitted then.
  const envd = (target: URL) => {
    const [label = "", ...domain] = target.hostname.split(".");
    return (
      envdDomain !== undefined &&
      target.protocol === "http:" &&
      target.port === "" &&
      /^\d+-[a-z0-9-]+$/i.test(label) &&
      domain.join(".") === envdDomain &&
      isPrivateNetworkHost(target.hostname)
    );
  };
  return options.plainHttpFetch((target) => exact(target) || envd(target));
}

/** The declared backend, or undefined for the native OS sandbox. */
export async function sandboxBackend(
  governance: GovernanceOptions,
): Promise<SandboxBackend | undefined> {
  const config = governance.lock.governance.manifest.sandbox;
  if (!config.required || config.provider === undefined) return undefined;
  const endpoint = resolve(governance, "sandbox.endpoint", config.endpoint);
  const router = resolve(governance, "sandbox.router", config.router);
  const options = {
    ...governance,
    fetch: sandboxFetch(governance, [
      ["sandbox.endpoint", endpoint],
      ["sandbox.router", router],
    ]),
  };
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
