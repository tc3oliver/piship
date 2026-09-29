import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import tls from "node:tls";
import {
  Agent,
  EnvHttpProxyAgent,
  type Dispatcher,
  fetch as undiciFetch,
  Pool,
  setGlobalDispatcher,
} from "undici";
import { PiShipError } from "./errors.js";
import { redact } from "./secret.js";

export interface NetworkPolicy {
  /** Honor HTTP_PROXY, HTTPS_PROXY, and NO_PROXY from the launch environment. */
  readonly inheritProxyEnvironment: boolean;
  /** PEM bundle files added to (never replacing) the default trust roots. */
  readonly additionalCA: readonly string[];
  /** When true, only allowHosts may be contacted; no public fallback. */
  readonly privateOnly: boolean;
  /**
   * Lowercase hostnames permitted when privateOnly is set. Only the hostname
   * is compared: the port and scheme are ignored, and nothing checks that the
   * host is a private address.
   */
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
// Other variables that pick a child's proxy or trust roots, or turn TLS
// verification off or on, for curl, wget, git, Python, npm, Cargo, Deno, Java
// and Node. Names are matched case-insensitively.
const OTHER_NETWORK_VARIABLES = [
  "ALL_PROXY",
  "all_proxy",
  "FTP_PROXY",
  "ftp_proxy",
  "RSYNC_PROXY",
  "SOCKS_PROXY",
  "SOCKS5_SERVER",
  "CURL_CA_BUNDLE",
  "CURL_HOME",
  "WGETRC",
  "REQUESTS_CA_BUNDLE",
  "PIP_CERT",
  "PIP_PROXY",
  "PIP_TRUSTED_HOST",
  "PYTHONHTTPSVERIFY",
  "GIT_SSL_CAINFO",
  "GIT_SSL_CAPATH",
  "GIT_SSL_NO_VERIFY",
  "GIT_PROXY_COMMAND",
  "CARGO_HTTP_PROXY",
  "CARGO_HTTP_CAINFO",
  "DENO_CERT",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
];
// Families that carry the same settings through per-tool configuration.
const NETWORK_NAME_PATTERNS = [
  /^NPM_CONFIG_(?:HTTPS?_PROXY|PROXY|NO_?PROXY|CAFILE|CA|CAPATH|STRICT_SSL|CERT|LOCAL_ADDRESS)$/,
  /^YARN_(?:HTTPS?_PROXY|CA_FILE_PATH|ENABLE_STRICT_SSL|NETWORK_SETTINGS)$/,
  /^GIT_CONFIG_(?:COUNT|PARAMETERS|GLOBAL|SYSTEM|KEY_\d+|VALUE_\d+)$/,
];
// Node options that change trust roots or TLS behavior.
const TRUST_NODE_OPTIONS =
  /--(?:use-(?:openssl|bundled|system)-ca|openssl-|tls-|insecure-http-parser)/;
/** The one CA variable that adds to the default roots instead of replacing them. */
const CHILD_CA_VARIABLE = "NODE_EXTRA_CA_CERTS";
// Agent sockets are local IPC paths, not secret values; git and signing need them.
const PRESERVED_VARIABLES = ["SSH_AUTH_SOCK", "GPG_AGENT_INFO"];

/** Remove trailing `/` characters in linear time (a `/\/+$/` regex is quadratic on long runs). */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end -= 1;
  return value.slice(0, end);
}

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

export interface DispatcherOptions {
  /**
   * Reuse connections between requests (the default). Without keep-alive
   * every request opens its own connection and closes it after the
   * response, including the connection to a plain-HTTP proxy.
   */
  readonly keepAlive?: boolean;
}

export function createDispatcher(
  policy: NetworkPolicy,
  options: DispatcherOptions = {},
): Dispatcher {
  const ca = trustRoots(loadCertificates(policy.additionalCA));
  const connect = ca
    ? { ca, rejectUnauthorized: true }
    : { rejectUnauthorized: true };
  // `pipelining: 0` disables keep-alive. The factory carries it to every
  // pool the agents create, including a proxy agent's pool to the proxy,
  // which does not receive the agent's own options.
  const pooling =
    options.keepAlive === false
      ? {
          pipelining: 0,
          factory: (origin: string | URL, opts: object) =>
            new Pool(origin, { ...opts, pipelining: 0 }),
        }
      : {};
  const base = policy.inheritProxyEnvironment
    ? new EnvHttpProxyAgent({ connect, ...pooling })
    : new Agent({ connect, ...pooling });
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
  // Platform secret store calls block the process (PowerShell on Windows
  // for seconds), and a pooled connection the server closed meanwhile still
  // looks usable until the close is read, which depends on where in the
  // event loop the next request is made. A request sent on it fails with
  // ECONNRESET, and a broker call that fails that way has an unknown outcome
  // and is never retried. Managed requests are few, so each opens its own
  // connection.
  const dispatcher = createDispatcher(policy, { keepAlive: false });
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
      // Only a system error code, never a message: undici puts an invalid
      // header value, such as a bearer token, into its message.
      throw new PiShipError(
        "GATEWAY_UNREACHABLE",
        `${component} request to ${target.host} failed: ${typeof cause?.code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(cause.code) ? cause.code : "network error"}`,
        { retryable: true, component },
      );
    }
  };
}

let processNetwork: ApprovedNetworkEnvironment | undefined;

/**
 * Apply the policy to in-process HTTP used by the Pi runtime: add enterprise
 * CA roots and install a proxy-aware dispatcher. TLS verification stays on.
 *
 * With `restrictChildren` (a managed distribution) it also records the network
 * environment child processes may receive (`processNetworkEnvironment`), read
 * from the launch environment as it is now, so call it after
 * `sanitizeManagedEnvironment`. Without it (a personal distribution) children
 * keep the launch environment as it is, and any earlier record is cleared.
 */
export function applyProcessNetworkPolicy(
  policy: NetworkPolicy,
  options: { readonly restrictChildren?: boolean } = {},
): void {
  assertTlsVerificationEnabled();
  const extra = loadCertificates(policy.additionalCA);
  const roots = trustRoots(extra);
  if (roots && typeof tls.setDefaultCACertificates === "function")
    tls.setDefaultCACertificates(roots);
  setGlobalDispatcher(createDispatcher(policy));
  processNetwork = options.restrictChildren
    ? approvedNetworkEnvironment(policy)
    : undefined;
}

/**
 * The network environment child processes of this process may receive, or
 * undefined when they keep their environment as it is: before
 * `applyProcessNetworkPolicy` ran, and for a personal distribution, whose
 * children see the same proxy and CA variables as the user's shell.
 */
export function processNetworkEnvironment():
  | ApprovedNetworkEnvironment
  | undefined {
  return processNetwork;
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

/**
 * The network environment a child process may receive, derived from the
 * policy and the launch environment. Children get exactly these variables and
 * no other proxy, CA, or TLS-verification variable, so the settings a
 * distribution declares are the ones its children run with.
 */
export interface ApprovedNetworkEnvironment {
  /**
   * Variables a child may receive, by name. Never a credential, and never a
   * setting that relaxes TLS verification.
   */
  readonly variables: Readonly<Record<string, string>>;
  readonly proxy: {
    /** Whether the policy inherits the launch proxy environment. */
    readonly inherited: boolean;
    /** The proxy PiShip's own clients use, as `scheme://host:port` (no credentials). */
    readonly http: string | undefined;
    readonly https: string | undefined;
    /** Whether the launch environment excludes hosts from the proxy. */
    readonly noProxy: boolean;
  };
  /** How many enterprise CA bundles the policy declares. */
  readonly caBundles: number;
  /** Variables PiShip configured but did not give to children, and why. Never values. */
  readonly withheld: readonly {
    readonly name: string;
    readonly reason: string;
  }[];
}

const GOVERNED_NETWORK_NAMES = new Set(
  [...PROXY_VARIABLES, ...CA_VARIABLES, ...OTHER_NETWORK_VARIABLES].map(
    (name) => name.toUpperCase(),
  ),
);

/**
 * Whether a variable picks a proxy, trust roots, or TLS verification for a
 * child process. A child environment keeps such a variable only when it is
 * approved. Give the value to also catch `NODE_OPTIONS` that changes trust
 * roots or TLS behavior; without a value only the names are checked.
 */
export function isNetworkEnvironmentName(
  name: string,
  value?: string,
): boolean {
  const upper = name.toUpperCase();
  if (GOVERNED_NETWORK_NAMES.has(upper)) return true;
  if (NETWORK_NAME_PATTERNS.some((pattern) => pattern.test(upper))) return true;
  return (
    upper === "NODE_OPTIONS" &&
    value !== undefined &&
    TRUST_NODE_OPTIONS.test(value)
  );
}

function checkProxyUrl(value: string): {
  shown: string | undefined;
  refusal: string | undefined;
} {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:")
      return { shown: undefined, refusal: "it is not an http or https URL" };
    // A proxy is a host and port. A path, query or fragment can carry a
    // token, and a backslash is read as a path separator by one URL parser
    // and as part of the authority by another.
    const plain =
      (url.pathname === "/" || url.pathname === "") &&
      !url.search &&
      !url.hash &&
      !value.includes("\\");
    return {
      shown: `${url.protocol}//${url.host}`,
      refusal:
        url.username || url.password
          ? "the URL embeds credentials"
          : plain
            ? undefined
            : "the URL has a path, query, fragment, or backslash",
    };
  } catch {
    return { shown: undefined, refusal: "it is not a valid URL" };
  }
}

/**
 * Derive the network environment child processes may receive. Fail closed:
 *
 * - Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, in both cases)
 *   only when the policy inherits them, with the value PiShip's own clients
 *   use (a lowercase name wins, as in undici). A proxy URL that embeds
 *   credentials, is not an http(s) URL, or looks like a credential is
 *   withheld: a child never receives a proxy credential.
 * - `NODE_EXTRA_CA_CERTS` only from a single declared `network.tls.additionalCA`
 *   bundle, the one CA variable that adds to the default roots. Several
 *   bundles cannot be expressed as one file and are withheld; `SSL_CERT_FILE`
 *   and `SSL_CERT_DIR` replace the roots, so they are never passed.
 * - Nothing that relaxes TLS verification, whatever the environment holds.
 */
export function approvedNetworkEnvironment(
  policy: NetworkPolicy,
  env: NodeJS.ProcessEnv = process.env,
): ApprovedNetworkEnvironment {
  const variables: Record<string, string> = {};
  const withheld: { name: string; reason: string }[] = [];
  const proxy: {
    inherited: boolean;
    http: string | undefined;
    https: string | undefined;
    noProxy: boolean;
  } = {
    inherited: policy.inheritProxyEnvironment,
    http: undefined,
    https: undefined,
    noProxy: false,
  };
  const withhold = (name: string, refusal: string) =>
    withheld.push({
      name,
      reason: `not passed to child processes: ${refusal}`,
    });
  if (policy.inheritProxyEnvironment) {
    const effective = (name: string) => env[name.toLowerCase()] ?? env[name];
    for (const [name, key] of [
      ["HTTP_PROXY", "http"],
      ["HTTPS_PROXY", "https"],
    ] as const) {
      const value = effective(name);
      if (!value) continue;
      const check = checkProxyUrl(value);
      proxy[key] = check.shown;
      const refusal =
        check.refusal ??
        (redact(value) === value
          ? undefined
          : "the value looks like a credential");
      if (refusal) {
        withhold(name, refusal);
        continue;
      }
      variables[name] = value;
      variables[name.toLowerCase()] = value;
    }
    const noProxy = effective("NO_PROXY");
    if (noProxy) {
      proxy.noProxy = true;
      if (redact(noProxy) === noProxy) {
        variables.NO_PROXY = noProxy;
        variables.no_proxy = noProxy;
      } else withhold("NO_PROXY", "the value looks like a credential");
    }
  }
  const [bundle] = policy.additionalCA;
  if (bundle && policy.additionalCA.length === 1)
    variables[CHILD_CA_VARIABLE] = resolve(bundle);
  else if (policy.additionalCA.length > 1)
    withhold(
      CHILD_CA_VARIABLE,
      "network.tls.additionalCA lists several bundles and a child accepts one file",
    );
  return { variables, proxy, caBundles: policy.additionalCA.length, withheld };
}
