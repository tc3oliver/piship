import {
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
  PiShipError,
} from "@piship/contracts";
import {
  type AccessManifest,
  checkUrl,
  RuntimeReferenceError,
  resolveTemplate,
} from "@piship/schema";

export interface ResolvedEndpoints {
  readonly issuer?: string;
  readonly clientId?: string;
  readonly audience?: string;
  readonly brokerEndpoint?: string;
  readonly brokerRevokeEndpoint?: string;
  readonly baseUrl?: string;
  readonly additionalCA: readonly string[];
}

/** Resolve allowlisted `${NAME}` references from the launch environment. */
export function resolveRuntimeReferences(
  access: AccessManifest,
  env: Readonly<Record<string, string | undefined>> = process.env,
): ResolvedEndpoints {
  const variables = access.variables;
  const one = (field: string, value: string | undefined, url: boolean) => {
    if (value === undefined) return undefined;
    let resolved: string;
    try {
      resolved = resolveTemplate(field, value, variables, env);
    } catch (error) {
      if (error instanceof RuntimeReferenceError)
        throw new PiShipError("CONFIG_UNAVAILABLE", error.message, {
          component: "config",
          userAction: error.variable
            ? `Set ${error.variable} in the launch environment (see the distribution documentation)`
            : "Fix the runtime reference in piship.yaml",
        });
      throw error;
    }
    if (url)
      try {
        checkUrl(resolved, field);
      } catch (error) {
        throw new PiShipError(
          "CONFIG_INVALID",
          `${field} resolved to an unacceptable URL: ${(error as Error).message}`,
          {
            component: "config",
          },
        );
      }
    return resolved;
  };
  const identity =
    access.identity.mode === "oidc" ? access.identity.oidc : undefined;
  const values = {
    issuer: one("identity.oidc.issuer", identity?.issuer, true),
    clientId: one("identity.oidc.clientId", identity?.clientId, false),
    audience: one("identity.oidc.audience", identity?.audience, false),
    brokerEndpoint: one(
      "credential.broker.endpoint",
      access.credential.broker?.endpoint,
      true,
    ),
    brokerRevokeEndpoint: one(
      "credential.broker.revokeEndpoint",
      access.credential.broker?.revokeEndpoint,
      true,
    ),
    baseUrl: one("inference.baseUrl", access.inference.baseUrl, true),
  };
  const output: Record<string, unknown> = {
    additionalCA: access.network.tls.additionalCA.map((path, index) =>
      one(`network.tls.additionalCA[${index}]`, path, false),
    ),
  };
  for (const [key, value] of Object.entries(values))
    if (value !== undefined) output[key] = value;
  return output as unknown as ResolvedEndpoints;
}

/**
 * Whether only declared endpoint hosts and `network.allowHosts` may be
 * contacted. In managed mode `publicFallback: deny` (which managed mode
 * requires) implies it, so the declaration is enforced by the managed fetch
 * rather than only displayed. Personal mode uses `network.privateOnly` as
 * declared.
 */
export function effectivePrivateOnly(
  access: AccessManifest,
  mode: "personal" | "managed",
): boolean {
  return (
    access.network.privateOnly ||
    (mode === "managed" && access.network.publicFallback === "deny")
  );
}

export function networkPolicyFor(
  access: AccessManifest | undefined,
  endpoints?: ResolvedEndpoints,
  mode: "personal" | "managed" = "personal",
): NetworkPolicy {
  if (!access) return DEFAULT_NETWORK_POLICY;
  const hosts = new Set(access.network.allowHosts);
  for (const url of [
    endpoints?.issuer,
    endpoints?.brokerEndpoint,
    endpoints?.brokerRevokeEndpoint,
    endpoints?.baseUrl,
  ])
    if (url) hosts.add(new URL(url).hostname.toLowerCase());
  return {
    inheritProxyEnvironment: access.network.proxy.inheritEnvironment,
    additionalCA: endpoints?.additionalCA ?? [],
    privateOnly: effectivePrivateOnly(access, mode),
    allowHosts: [...hosts].sort(),
  };
}
