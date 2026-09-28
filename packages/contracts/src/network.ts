import { readFileSync } from "node:fs";
import tls from "node:tls";
import {
  Agent,
  EnvHttpProxyAgent,
  type Dispatcher,
  fetch as undiciFetch,
  setGlobalDispatcher,
} from "undici";
import { PiShipError } from "./errors.js";

export interface NetworkPolicy {
  /** Honor HTTP_PROXY, HTTPS_PROXY, and NO_PROXY from the launch environment. */
  readonly inheritProxyEnvironment: boolean;
  /** PEM bundle files added to (never replacing) the default trust roots. */
  readonly additionalCA: readonly string[];
  /** When true, only allowHosts may be contacted; no public fallback. */
  readonly privateOnly: boolean;
  /** Lowercase hostnames permitted when privateOnly is set. */
  readonly allowHosts: readonly string[];
}

export const DEFAULT_NETWORK_POLICY: NetworkPolicy = {
  inheritProxyEnvironment: true,
  additionalCA: [],
  privateOnly: false,
  allowHosts: [],
};

export type ManagedFetch = (
  url: string | URL,
  init?: RequestInit,
) => Promise<Response>;

const PROXY_VARIABLES = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
];
const CA_VARIABLES = ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR"];
// Agent sockets are local IPC paths, not secret values; git and signing need them.
const PRESERVED_VARIABLES = ["SSH_AUTH_SOCK", "GPG_AGENT_INFO"];

export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return (
    host === "localhost" || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host)
  );
}

/** Refuse to run managed network flows when TLS verification was disabled. */
export function assertTlsVerificationEnabled(
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0")
    throw new PiShipError(
      "TLS_POLICY_VIOLATION",
      "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification; PiShip managed access refuses to run this way",
      {
        userAction:
          "Unset NODE_TLS_REJECT_UNAUTHORIZED and declare the enterprise CA bundle in network.tls.additionalCA",
        component: "network",
      },
    );
}

function loadCertificates(paths: readonly string[]): string[] {
  const output: string[] = [];
  for (const path of paths) {
    let pem: string;
    try {
      pem = readFileSync(path, "utf8");
    } catch {
      throw new PiShipError(
        "CONFIG_UNAVAILABLE",
        `Enterprise CA bundle is unreadable: ${path}`,
        { component: "network" },
      );
    }
    const certificates = pem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
    );
    if (!certificates?.length)
      throw new PiShipError(
        "CONFIG_INVALID",
        `Enterprise CA bundle contains no PEM certificate: ${path}`,
        { component: "network" },
      );
    output.push(...certificates);
  }
  return output;
}

function trustRoots(extra: readonly string[]): string[] | undefined {
  if (!extra.length) return undefined;
  const defaults =
    typeof tls.getCACertificates === "function"
      ? tls.getCACertificates("default")
      : [...tls.rootCertificates];
  return [...defaults, ...extra];
}

export function createDispatcher(policy: NetworkPolicy): Dispatcher {
  const ca = trustRoots(loadCertificates(policy.additionalCA));
  const connect = ca
    ? { ca, rejectUnauthorized: true }
    : { rejectUnauthorized: true };
  const base = policy.inheritProxyEnvironment
    ? new EnvHttpProxyAgent({ connect })
    : new Agent({ connect });
  if (!policy.privateOnly) return base;
  // Private-only: refuse undeclared origins for every request that uses this
  // dispatcher, including Pi's in-process provider requests and extensions'
  // fetch calls. Raw sockets and child processes are not covered.
  return base.compose((dispatch) => (options, handler) => {
    const origin =
      typeof options.origin === "string"
        ? options.origin
        : options.origin?.toString();
    if (origin) checkDestination(new URL(origin), policy, "network");
    return dispatch(options, handler);
  });
}

/** Validate a destination against transport and private-only policy. */
export function checkDestination(
  target: URL,
  policy: NetworkPolicy,
  component = "network",
): void {
  if (target.username || target.password)
    throw new PiShipError(
      "CONFIG_INVALID",
      "Endpoint URLs must not embed credentials",
      { component },
    );
  if (
    target.protocol !== "https:" &&
    !(target.protocol === "http:" && isLoopbackHost(target.hostname))
  )
    throw new PiShipError(
      "NETWORK_DENIED",
      `Refusing non-HTTPS endpoint ${target.protocol}//${target.host}; plain HTTP is only allowed for loopback test fixtures`,
      { component },
    );
  if (
    policy.privateOnly &&
    !policy.allowHosts.includes(target.hostname.toLowerCase())
  )
    throw new PiShipError(
      "NETWORK_DENIED",
      `Private-only network policy denies undeclared host ${target.hostname}`,
      {
        component,
        userAction:
          "Declare the host through a managed endpoint or network.allowHosts",
      },
    );
}

/**
 * A fetch for PiShip-managed clients (identity, broker, gateway probes). It
 * honors declared proxy/CA settings, never disables TLS verification, never
 * follows redirects to another host, and enforces private-only destinations.
 */
export function createManagedFetch(
  policy: NetworkPolicy,
  component = "network",
): ManagedFetch {
  const dispatcher = createDispatcher(policy);
  return async (url, init = {}) => {
    assertTlsVerificationEnabled();
    const target = new URL(url.toString());
    checkDestination(target, policy, component);
    try {
      const response = await undiciFetch(target, {
        ...(init as Record<string, unknown>),
        redirect: "manual",
        dispatcher,
      } as Parameters<typeof undiciFetch>[1]);
      return response as unknown as Response;
    } catch (error) {
      if (error instanceof PiShipError) throw error;
      // Caller cancellations and deadlines stay recognizable to the caller.
      if (["AbortError", "TimeoutError"].includes((error as Error)?.name))
        throw error;
      const cause = (error as { cause?: { code?: string; message?: string } })
        ?.cause;
      throw new PiShipError(
        "GATEWAY_UNREACHABLE",
        `${component} request to ${target.host} failed: ${cause?.code ?? cause?.message ?? (error as Error)?.message ?? "network error"}`,
        { retryable: true, component },
      );
    }
  };
}

/**
 * Apply the policy to in-process HTTP used by the Pi runtime: add enterprise
 * CA roots and install a proxy-aware dispatcher. TLS verification stays on.
 */
export function applyProcessNetworkPolicy(policy: NetworkPolicy): void {
  assertTlsVerificationEnabled();
  const extra = loadCertificates(policy.additionalCA);
  const roots = trustRoots(extra);
  if (roots && typeof tls.setDefaultCACertificates === "function")
    tls.setDefaultCACertificates(roots);
  setGlobalDispatcher(createDispatcher(policy));
}

const CREDENTIAL_VARIABLE =
  /(?:^|_)(?:API_?KEY|ACCESS_?KEY|SECRET(?:_ACCESS)?_?KEY|SECRET|TOKEN|SESSION_?TOKEN|PASSWORD|CREDENTIALS?|AUTH)(?:_|$)/i;
const CREDENTIAL_PREFIXES = [
  "AWS_",
  "AZURE_",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_",
  "VERTEX_",
  "ANTHROPIC_",
  "OPENAI_",
  "GEMINI_",
  "MISTRAL_",
  "GROQ_",
  "XAI_",
  "OPENROUTER_",
  "CEREBRAS_",
  "DEEPSEEK_",
  "HF_",
  "COPILOT_",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "PI_",
];

/**
 * Remove ambient credentials (and, unless inherited, proxy settings) from an
 * environment used by the managed runtime and its child processes. Returns
 * only the removed variable names, never values.
 */
export function sanitizeManagedEnvironment(
  env: NodeJS.ProcessEnv,
  policy: NetworkPolicy,
  keep: readonly string[] = [],
): string[] {
  const removed: string[] = [];
  for (const name of Object.keys(env)) {
    if (keep.includes(name) || PRESERVED_VARIABLES.includes(name)) continue;
    const upper = name.toUpperCase();
    const credential =
      CREDENTIAL_VARIABLE.test(name) ||
      CREDENTIAL_PREFIXES.some((prefix) => upper.startsWith(prefix));
    const proxy =
      PROXY_VARIABLES.includes(name) && !policy.inheritProxyEnvironment;
    const disabledTls = name === "NODE_TLS_REJECT_UNAUTHORIZED";
    if ((credential && !CA_VARIABLES.includes(upper)) || proxy || disabledTls) {
      delete env[name];
      removed.push(name);
    }
  }
  return removed.sort();
}
