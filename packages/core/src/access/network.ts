import {
  DEFAULT_NETWORK_POLICY,
  type NetworkPolicy,
  PiShipError,
  type ResolvedEndpoints,
} from "@piship/contracts";
import {
  type AccessManifest,
  checkUrl,
  RuntimeReferenceError,
  resolveTemplate,
} from "@piship/schema";

// Defined in @piship/contracts so the adapter SDK can name it without core.
export type { ResolvedEndpoints };

type Environment = Readonly<Record<string, string | undefined>>;

/** Resolve one template; an unset variable is CONFIG_UNAVAILABLE by name. */
function resolveReference(
  access: AccessManifest,
  env: Environment,
  field: string,
  value: string,
): string {
  try {
    return resolveTemplate(field, value, access.variables, env);
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
}

/**
 * Resolve `network.tls.additionalCA`. A declared bundle is never dropped: an
 * unset variable fails exactly as it does at launch.
 */
export function resolveAdditionalCA(
  access: AccessManifest,
  env: Environment = process.env,
): string[] {
  return access.network.tls.additionalCA.map((path, index) =>
    resolveReference(access, env, `network.tls.additionalCA[${index}]`, path),
  );
}

/** Resolve allowlisted `${NAME}` references from the launch environment. */
export function resolveRuntimeReferences(
  access: AccessManifest,
  env: Environment = process.env,
): ResolvedEndpoints {
  // `plainHttp`: the endpoint's `httpTransport` is not `https`; the resolved
  // URL is checked as a static one is, so a public plain-HTTP host fails.
  const one = (
    field: string,
    value: string | undefined,
    url: boolean,
    plainHttp = false,
  ) => {
    if (value === undefined) return undefined;
    const resolved = resolveReference(access, env, field, value);
    if (url)
      try {
        checkUrl(resolved, field, plainHttp);
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
  const brokerPlainHttp = access.credential.broker?.httpTransport !== "https";
  const values = {
    issuer: one(
      "identity.oidc.issuer",
      identity?.issuer,
      true,
      identity?.httpTransport !== "https",
    ),
    clientId: one("identity.oidc.clientId", identity?.clientId, false),
    audience: one("identity.oidc.audience", identity?.audience, false),
    brokerEndpoint: one(
      "credential.broker.endpoint",
      access.credential.broker?.endpoint,
      true,
      brokerPlainHttp,
    ),
    brokerRevokeEndpoint: one(
      "credential.broker.revokeEndpoint",
      access.credential.broker?.revokeEndpoint,
      true,
      brokerPlainHttp,
    ),
    baseUrl: one(
      "inference.baseUrl",
      access.inference.baseUrl,
      true,
      access.inference.httpTransport !== "https",
    ),
  };
  const output: Record<string, unknown> = {
    additionalCA: resolveAdditionalCA(access, env),
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
