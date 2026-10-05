import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { connect as connectSocket } from "node:net";
import { resolve } from "node:path";
import tls from "node:tls";
import {
  Agent,
  Client,
  type Dispatcher,
  EnvHttpProxyAgent,
  Pool,
  setGlobalDispatcher,
  fetch as undiciFetch,
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

export interface ManagedRequestInit extends RequestInit {
  /**
   * The request lasts as long as the work it starts, such as a remote
   * sandbox command whose response comes when the command ends: undici's
   * header and body timeouts (300 s each) do not apply, and the caller's
   * `signal` alone ends it. Every other request keeps them.
   */
  readonly longRunning?: boolean;
}

export type ManagedFetch = (
  url: string | URL,
  init?: ManagedRequestInit,
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

/** Name suffixes that mark an internal (never publicly delegated) host. */
const INTERNAL_SUFFIXES = [
  ".internal",
  ".local",
  ".lan",
  ".corp",
  ".home.arpa",
  ".intranet",
];

/**
 * Single labels that are public top-level domains, never an intranet host:
 * a sample of common generic ones. Every two-letter label (a country code
 * TLD) is refused as well. The list is deliberately short, not the public
 * suffix list: a name that is not here is still only as internal as DNS
 * makes it (see `isPrivateNetworkHost`).
 */
const PUBLIC_TLD_LABELS = new Set([
  "app",
  "arpa",
  "biz",
  "cloud",
  "com",
  "dev",
  "edu",
  "gov",
  "info",
  "int",
  "mil",
  "mobi",
  "name",
  "net",
  "online",
  "org",
  "page",
  "pro",
  "shop",
  "site",
  "tech",
  "top",
  "xyz",
]);

/**
 * Whether `hostname` (a URL hostname, IPv6 in brackets or not) names a
 * private or internal host: loopback; an IPv4 literal in 10/8, 172.16/12,
 * 192.168/16, or 100.64/10; an IPv6 literal in fc00::/7 or fe80::/10; a
 * single-label name that is not a public TLD (two letters, or one of
 * `PUBLIC_TLD_LABELS`); or a name ending in .internal, .local, .lan, .corp,
 * .home.arpa, or .intranet. Only the text is judged, never DNS: a single
 * label is resolved through the machine's search domains, and an internal
 * looking name that resolves to a public address is the owner's to prevent.
 */
export function isPrivateNetworkHost(hostname: string): boolean {
  const host = hostname
    .replace(/^\[|\]$/g, "")
    .toLowerCase()
    .replace(/\.$/, "");
  if (!host) return false;
  if (isLoopbackHost(host)) return true;
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (ipv4) {
    const [a, b] = ipv4.slice(1, 3).map(Number) as [number, number];
    if (ipv4.slice(1).some((part) => Number(part) > 255)) return false;
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  // A first group of four digits: `fc::1` is 00fc::1, not fc00::/7.
  if (host.includes(":"))
    return /^(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):/.test(host);
  if (!host.includes("."))
    return (
      /^[a-z0-9-]+$/.test(host) &&
      !/^[a-z]{2}$/.test(host) &&
      !PUBLIC_TLD_LABELS.has(host)
    );
  return INTERNAL_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

/**
 * A `plainHttp` predicate for an endpoint that opted in to plain HTTP
 * (`httpTransport: http-allowed`): it admits plain HTTP only to the exact
 * origin (scheme, host, and port) of each given URL that is plain HTTP to a
 * private or internal host (`isPrivateNetworkHost`), and to nothing else.
 * Undefined when no URL is one, so a caller keeps the loopback-only rule.
 */
export function plainHttpOrigins(
  urls: readonly (string | URL | undefined)[],
): ((target: URL) => boolean) | undefined {
  const origins = new Set<string>();
  for (const value of urls) {
    if (value === undefined) continue;
    let url: URL;
    try {
      url = new URL(value.toString());
    } catch {
      continue;
    }
    if (url.protocol === "http:" && isPrivateNetworkHost(url.hostname))
      origins.add(url.origin);
  }
  if (!origins.size) return undefined;
  return (target) => target.protocol === "http:" && origins.has(target.origin);
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

/**
 * How many certificates the declared CA bundles hold, each parsed as X.509.
 * Fails as loading them for a request does, and also on a certificate that
 * does not parse; for doctor.
 */
export function countCertificates(paths: readonly string[]): number {
  let count = 0;
  for (const path of paths)
    for (const pem of loadCertificates([path])) {
      try {
        new X509Certificate(pem);
      } catch {
        throw new PiShipError(
          "CONFIG_INVALID",
          `Enterprise CA bundle contains a certificate that does not parse: ${path}`,
          { component: "network" },
        );
      }
      count += 1;
    }
  return count;
}

/**
 * Whether a TCP connection to the proxy opens within the deadline: undefined
 * when it does, otherwise a bare system code or `timeout`. Sends nothing; for
 * doctor. The proxy is given as `scheme://host:port`.
 */
export function checkProxyConnection(
  proxy: string,
  timeoutMs = 3_000,
): Promise<string | undefined> {
  let url: URL;
  try {
    url = new URL(proxy);
  } catch {
    return Promise.resolve("invalid URL");
  }
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return new Promise((done) => {
    const socket = connectSocket({ host, port });
    const timer = setTimeout(() => finish("timeout"), timeoutMs);
    const finish = (result: string | undefined) => {
      clearTimeout(timer);
      socket.destroy();
      done(result);
    };
    socket.once("connect", () => finish(undefined));
    socket.once("error", (error) => {
      const code = (error as { code?: unknown }).code;
      finish(
        typeof code === "string" && SYSTEM_CODE.test(code)
          ? code
          : "network error",
      );
    });
  });
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
   * response, including the connection to a plain-HTTP proxy, and HTTP/2 is
   * not negotiated: its one session per origin would be reused like a
   * pooled connection.
   */
  readonly keepAlive?: boolean;
  /**
   * Apply undici's header and body timeouts (the default). Without them a
   * request ends only when its response does or its signal aborts.
   */
  readonly inactivityTimeouts?: boolean;
  /** Plain HTTP destinations the private-only check also accepts; see checkDestination. */
  readonly plainHttp?: (target: URL) => boolean;
}

export function createDispatcher(
  policy: NetworkPolicy,
  options: DispatcherOptions = {},
): Dispatcher {
  return buildDispatcher(policy, options).dispatcher;
}

/** The proxy hop a transport failure happened on, keyed by the error object. */
interface ProxyHop {
  /** The proxy as `scheme://host:port`, never with credentials. */
  readonly proxy: string;
  /** The proxy's answer to CONNECT, when it was not 200. */
  readonly status?: number;
}
const proxyHops = new WeakMap<object, ProxyHop>();

function markProxyHop(error: unknown, hop: ProxyHop): void {
  if (error && typeof error === "object" && !proxyHops.has(error))
    proxyHops.set(error, hop);
}

/** A proxy URL as it may be shown: scheme, host and port, never credentials. */
function shownProxy(value: string | URL): string {
  try {
    const url = new URL(value.toString());
    return `${url.protocol}//${url.host}`;
  } catch {
    return "(unparseable proxy URL)";
  }
}

type Connector = (
  options: object,
  callback: (error: Error | null, socket: unknown) => void,
) => void;

interface BuiltDispatcher {
  readonly dispatcher: Dispatcher;
  /** The proxy still opening a CONNECT tunnel to `host:port`, if any. */
  readonly pendingTunnel: (hostPort: string) => string | undefined;
}

function buildDispatcher(
  policy: NetworkPolicy,
  options: DispatcherOptions,
): BuiltDispatcher {
  const ca = trustRoots(loadCertificates(policy.additionalCA));
  const connect = ca
    ? { ca, rejectUnauthorized: true }
    : { rejectUnauthorized: true };
  const keepAlive = options.keepAlive !== false;
  // The proxies undici's EnvHttpProxyAgent reads, read at the same moment.
  const proxies = policy.inheritProxyEnvironment
    ? [
        process.env.http_proxy ?? process.env.HTTP_PROXY,
        process.env.https_proxy ?? process.env.HTTPS_PROXY,
      ].flatMap((value) => {
        try {
          return value ? [new URL(value)] : [];
        } catch {
          return [];
        }
      })
    : [];
  const proxyAt = (origin: string | URL): string | undefined => {
    try {
      const url = new URL(origin.toString());
      const proxy = proxies.find(
        (candidate) =>
          candidate.protocol === url.protocol && candidate.host === url.host,
      );
      return proxy && shownProxy(proxy);
    } catch {
      return undefined;
    }
  };
  // A connection opened to the proxy itself: its failure is the proxy's,
  // whatever the system code.
  const toProxy =
    (connector: Connector, proxy: string): Connector =>
    (opts, callback) =>
      connector(opts, (error, socket) => {
        if (error) markProxyHop(error, { proxy });
        callback(error, socket);
      });
  // `pipelining: 0` disables keep-alive for HTTP/1.1; HTTP/2, which undici
  // negotiates by default over TLS, keeps one session per origin and ignores
  // `pipelining`, so it is turned off too. The factory carries both to every
  // pool the agents create, including a proxy agent's pool to the proxy,
  // which does not receive the agent's own options. A plain-HTTP request to
  // a forward proxy is sent on such a pool, whose origin is the proxy.
  const timeouts =
    options.inactivityTimeouts === false
      ? { headersTimeout: 0, bodyTimeout: 0 }
      : {};
  const factory = (origin: string | URL, opts: object): Dispatcher => {
    const proxy = proxyAt(origin);
    const given = (opts as { connect?: unknown }).connect;
    const settings = {
      ...opts,
      ...(proxy && typeof given === "function"
        ? { connect: toProxy(given as Connector, proxy) }
        : {}),
      ...(keepAlive ? {} : { pipelining: 0, allowH2: false }),
      ...timeouts,
    } as Pool.Options;
    return keepAlive && (opts as { connections?: unknown }).connections === 1
      ? new Client(origin, settings)
      : new Pool(origin, settings);
  };
  // The proxy agent's client to the proxy, which opens CONNECT tunnels. Its
  // failures and a CONNECT answer other than 200 are the proxy's, and a
  // tunnel still opening when a deadline expires was never answered.
  const tunnels = new Map<string, { proxy: string; count: number }>();
  const clientFactory = (origin: URL, opts: object): Dispatcher => {
    const proxy = shownProxy(origin);
    const pool = new Pool(origin, { ...(opts as Pool.Options), ...timeouts });
    const open = pool.connect.bind(pool) as unknown as (
      params: Dispatcher.ConnectOptions,
    ) => Promise<Dispatcher.ConnectData>;
    const tunnel = async (
      params: Dispatcher.ConnectOptions,
    ): Promise<Dispatcher.ConnectData> => {
      const key = String(params.path);
      const pending = tunnels.get(key) ?? { proxy, count: 0 };
      pending.count += 1;
      tunnels.set(key, pending);
      try {
        const data = await open(params);
        if (data.statusCode !== 200) {
          data.socket.on("error", () => {}).destroy();
          const refused = Object.assign(
            new Error(`proxy answered CONNECT with HTTP ${data.statusCode}`),
            { code: "PISHIP_PROXY_STATUS" },
          );
          markProxyHop(refused, { proxy, status: data.statusCode });
          throw refused;
        }
        return data;
      } catch (error) {
        markProxyHop(error, { proxy });
        throw error;
      } finally {
        pending.count -= 1;
        if (pending.count === 0) tunnels.delete(key);
      }
    };
    Object.assign(pool, { connect: tunnel });
    return pool;
  };
  const pooling = keepAlive ? {} : { pipelining: 0, allowH2: false };
  const base = policy.inheritProxyEnvironment
    ? new EnvHttpProxyAgent({
        connect,
        // Inside a CONNECT tunnel the target's TLS, and an HTTPS proxy's own,
        // use these settings instead of `connect`: both verify against the
        // declared roots.
        requestTls: connect,
        proxyTls: connect,
        ...pooling,
        ...timeouts,
        factory,
        clientFactory,
      })
    : new Agent({ connect, ...pooling, ...timeouts, factory });
  const pendingTunnel = (hostPort: string) => tunnels.get(hostPort)?.proxy;
  if (!policy.privateOnly) return { dispatcher: base, pendingTunnel };
  const { plainHttp } = options;
  // Private-only: refuse undeclared origins for every request that uses this
  // dispatcher, including Pi's in-process provider requests and extensions'
  // fetch calls. Raw sockets and child processes are not covered.
  return {
    dispatcher: base.compose((dispatch) => (options, handler) => {
      const origin =
        typeof options.origin === "string"
          ? options.origin
          : options.origin?.toString();
      if (origin)
        checkDestination(new URL(origin), policy, "network", plainHttp);
      return dispatch(options, handler);
    }),
    pendingTunnel,
  };
}

/** TLS verification codes that mean the chain does not lead to a trusted root. */
const UNTRUSTED_CHAIN_CODES = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "CERT_UNTRUSTED",
  "CERT_REJECTED",
  "INVALID_CA",
  "CERT_CHAIN_TOO_LONG",
]);
const EXPIRED_CERT_CODES = new Set(["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID"]);
const NAME_MISMATCH_CODE = "ERR_TLS_CERT_ALTNAME_INVALID";
const SYSTEM_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
/**
 * undici's error for a 407 from a forward proxy (a plain-HTTP request sent to
 * the proxy, not a CONNECT tunnel). It carries no status field, so its fixed
 * text at the pinned undici version is compared whole, never searched.
 */
const FORWARD_PROXY_407 = "Proxy Authentication Required (407)";

const PROXY_ACTION = (proxy: string) =>
  `Check that the proxy ${proxy} is running and reachable from this machine, and that HTTPS_PROXY and HTTP_PROXY name it correctly; list hosts that must bypass it in NO_PROXY`;

/**
 * Classify a transport failure of a managed request by the hop it happened
 * on, from structured fields only (system and TLS error codes, the proxy's
 * CONNECT status, which connection failed): the proxy, the TLS chain of the
 * host, or the target. Never an error message: undici puts an invalid header
 * value, such as a bearer token, into its message.
 */
function transportFailure(
  error: unknown,
  target: URL,
  component: string,
): PiShipError {
  let hop: ProxyHop | undefined;
  let code: string | undefined;
  let tlsCode: string | undefined;
  let forward407 = false;
  for (
    let current: unknown = error, depth = 0;
    current && typeof current === "object" && depth < 8;
    current = (current as { cause?: unknown }).cause, depth += 1
  ) {
    hop ??= proxyHops.get(current);
    const value = (current as { code?: unknown }).code;
    if (typeof value === "string" && SYSTEM_CODE.test(value)) {
      if (
        UNTRUSTED_CHAIN_CODES.has(value) ||
        EXPIRED_CERT_CODES.has(value) ||
        value === NAME_MISMATCH_CODE
      )
        tlsCode ??= value;
      // The innermost code is the most specific one.
      code = value;
    }
    if (
      value === "UND_ERR_INVALID_ARG" &&
      (current as Error).message === FORWARD_PROXY_407
    )
      forward407 = true;
  }
  if (forward407) {
    const proxy = shownProxy(
      process.env.http_proxy ?? process.env.HTTP_PROXY ?? "",
    );
    hop = { proxy, status: 407 };
  }
  const host = target.host;
  if (hop?.status !== undefined) {
    const { proxy, status } = hop;
    const detail = { hop: "proxy", proxy, status };
    if (status === 407)
      return new PiShipError(
        "NETWORK_DENIED",
        `${component} request to ${host} was refused by the proxy ${proxy}: it requires authentication (HTTP 407)`,
        {
          component,
          sanitizedDetail: detail,
          userAction: `Check the proxy credentials: put them in HTTPS_PROXY or HTTP_PROXY as http://user:password@host:port for ${proxy}, or ask the proxy administrator how this machine authenticates`,
        },
      );
    if (status === 403)
      return new PiShipError(
        "NETWORK_DENIED",
        `${component} request to ${host} was refused by the proxy ${proxy} (HTTP 403)`,
        {
          component,
          sanitizedDetail: detail,
          userAction: `Ask the proxy administrator to allow ${target.hostname}, or list it in NO_PROXY if it must not use the proxy`,
        },
      );
    return new PiShipError(
      "GATEWAY_UNREACHABLE",
      `${component} request to ${host} failed: the proxy ${proxy} could not open a tunnel (HTTP ${status})`,
      {
        retryable: true,
        component,
        sanitizedDetail: detail,
        userAction: `Check that ${target.hostname} is reachable from the proxy ${proxy}, or list it in NO_PROXY if it must not use the proxy`,
      },
    );
  }
  if (tlsCode) {
    // The TLS chain of the proxy itself (an HTTPS proxy) or of the target.
    const subject = hop ? `the proxy ${hop.proxy}` : host;
    const name = hop ? hop.proxy : target.hostname;
    const detail = {
      hop: hop ? "proxy" : "target",
      ...(hop ? { proxy: hop.proxy } : {}),
      tls: tlsCode,
    };
    const [what, action] = EXPIRED_CERT_CODES.has(tlsCode)
      ? [
          "its certificate has expired or is not yet valid",
          `Check this machine's clock; if it is right, ask the administrator of ${name} to renew its certificate`,
        ]
      : tlsCode === NAME_MISMATCH_CODE
        ? [
            "its certificate does not name this host",
            `Use the host name on ${name}'s certificate in the endpoint URL, or ask its administrator for a certificate that names it`,
          ]
        : [
            "its certificate chain is not trusted",
            `If ${name} uses an enterprise or private CA, or a TLS-inspecting proxy re-signs its traffic, declare that CA's PEM bundle in network.tls.additionalCA (a \${NAME} reference must be quoted: additionalCA: ["\${CORP_CA_BUNDLE}"]); never turn TLS verification off`,
          ];
    return new PiShipError(
      "TLS_POLICY_VIOLATION",
      `${component} request to ${host} failed TLS verification of ${subject}: ${what} (${tlsCode})`,
      { component, sanitizedDetail: detail, userAction: action },
    );
  }
  const shownCode = code ?? "network error";
  if (hop)
    return new PiShipError(
      "GATEWAY_UNREACHABLE",
      `${component} request to ${host} failed at the proxy ${hop.proxy}: ${shownCode}`,
      {
        retryable: true,
        component,
        sanitizedDetail: {
          hop: "proxy",
          proxy: hop.proxy,
          ...(code ? { transport: code } : {}),
        },
        userAction: PROXY_ACTION(hop.proxy),
      },
    );
  return new PiShipError(
    "GATEWAY_UNREACHABLE",
    `${component} request to ${host} failed: ${shownCode}`,
    { retryable: true, component },
  );
}

/**
 * Validate a destination against transport and private-only policy.
 * `plainHttp` may permit plain HTTP to a non-loopback destination. Only an
 * endpoint that opted in passes it (`updates.transport: http-allowed`, or
 * `httpTransport: http-allowed`, usually through `plainHttpOrigins` for its
 * own origin), so every other request keeps the loopback-only rule.
 */
export function checkDestination(
  target: URL,
  policy: NetworkPolicy,
  component = "network",
  plainHttp?: (target: URL) => boolean,
): void {
  if (target.username || target.password)
    throw new PiShipError(
      "CONFIG_INVALID",
      "Endpoint URLs must not embed credentials",
      { component },
    );
  if (
    target.protocol !== "https:" &&
    !(
      target.protocol === "http:" &&
      (isLoopbackHost(target.hostname) || plainHttp?.(target) === true)
    )
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
  options: {
    /**
     * Permit plain HTTP to a non-loopback destination it accepts. Only the
     * fetch of an endpoint that opted in passes it; see checkDestination.
     */
    readonly plainHttp?: (target: URL) => boolean;
  } = {},
): ManagedFetch {
  // Platform secret store calls block the process (PowerShell on Windows
  // for seconds), and a pooled connection the server closed meanwhile still
  // looks usable until the close is read, which depends on where in the
  // event loop the next request is made. A request sent on it fails with
  // ECONNRESET, and a broker call that fails that way has an unknown outcome
  // and is never retried. Managed requests (identity, broker, gateway probes,
  // the audit sinks and update downloads) are few and small, so each opens its
  // own connection.
  const plainHttp = options.plainHttp ? { plainHttp: options.plainHttp } : {};
  const { dispatcher, pendingTunnel } = buildDispatcher(policy, {
    keepAlive: false,
    ...plainHttp,
  });
  // A long-running request has a dispatcher of its own, without undici's
  // header and body timeouts, created on first use.
  let untimed: BuiltDispatcher | undefined;
  const longRunningDispatcher = () => {
    untimed ??= buildDispatcher(policy, {
      keepAlive: false,
      inactivityTimeouts: false,
      ...plainHttp,
    });
    return untimed;
  };
  return async (url, { longRunning, ...init } = {}) => {
    assertTlsVerificationEnabled();
    const target = new URL(url.toString());
    checkDestination(target, policy, component, options.plainHttp);
    try {
      const response = await undiciFetch(target, {
        ...(init as Record<string, unknown>),
        redirect: "manual",
        dispatcher: longRunning
          ? longRunningDispatcher().dispatcher
          : dispatcher,
      } as Parameters<typeof undiciFetch>[1]);
      return response as unknown as Response;
    } catch (error) {
      if (error instanceof PiShipError) throw error;
      const name = (error as Error)?.name;
      // A deadline that expired while the proxy was still opening the tunnel
      // is the proxy's: the request never reached the target.
      if (name === "TimeoutError") {
        const proxy = (
          longRunning ? longRunningDispatcher() : { pendingTunnel }
        ).pendingTunnel(
          `${target.hostname}:${target.port || (target.protocol === "https:" ? "443" : "80")}`,
        );
        if (proxy)
          throw new PiShipError(
            "GATEWAY_UNREACHABLE",
            `${component} request to ${target.host} failed: the proxy ${proxy} did not open a tunnel in time`,
            {
              retryable: true,
              component,
              sanitizedDetail: { hop: "proxy", proxy, transport: "timeout" },
              userAction: PROXY_ACTION(proxy),
            },
          );
      }
      // Caller cancellations and deadlines stay recognizable to the caller.
      if (name === "AbortError" || name === "TimeoutError") throw error;
      throw transportFailure(error, target, component);
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
  options: {
    readonly restrictChildren?: boolean;
    /**
     * Plain HTTP destinations a private-only policy also accepts: only the
     * inference gateway's own origin with `inference.httpTransport:
     * http-allowed` (`plainHttpOrigins`). Without a private-only policy the
     * process dispatcher checks no destination, as before.
     */
    readonly plainHttp?: (target: URL) => boolean;
  } = {},
): void {
  assertTlsVerificationEnabled();
  const extra = loadCertificates(policy.additionalCA);
  const roots = trustRoots(extra);
  if (roots && typeof tls.setDefaultCACertificates === "function")
    tls.setDefaultCACertificates(roots);
  setGlobalDispatcher(
    createDispatcher(
      policy,
      options.plainHttp ? { plainHttp: options.plainHttp } : {},
    ),
  );
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
