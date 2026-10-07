// `httpTransport` (piship/v1alpha6): the per-endpoint transport. Plain HTTP to
// a private or internal host is admitted by default, so an intranet needs no
// opt-in; `https` forces HTTPS-only (loopback aside) for one endpoint, and
// `http-allowed` is the explicit spelling of the default.
import { isPrivateNetworkHost } from "@piship/contracts";

/**
 * `<endpoint>.httpTransport`: `https` forces HTTPS-only for the endpoint;
 * `http-allowed` (and an absent field, which the parsed manifest keeps
 * absent so existing lock digests hold) admits plain HTTP to a private or
 * internal host.
 */
export const HTTP_TRANSPORTS = ["https", "http-allowed"] as const;
export type HttpTransport = (typeof HTTP_TRANSPORTS)[number];

/**
 * Whether an endpoint may use plain HTTP to a private or internal host: every
 * transport but an explicit `https`. Loopback is always admitted.
 */
export function plainHttpPermitted(
  transport: HttpTransport | undefined,
): boolean {
  return transport !== "https";
}

/**
 * The transport an endpoint effectively has, for display: `https` when the
 * owner forced it or a runtime credential is involved (never sent over plain
 * HTTP), else `http-allowed`.
 */
export function effectiveHttpTransport(
  transport: HttpTransport | undefined,
  runtimeCredential = false,
): HttpTransport {
  return runtimeCredential || !plainHttpPermitted(transport)
    ? "https"
    : "http-allowed";
}

/**
 * The hosts plain HTTP is accepted to by default (`isPrivateNetworkHost`).
 * Only the name is judged, never DNS: a single label is completed with the
 * machine's DNS search domains, so it reaches whatever those domains resolve
 * it to, and an internal-looking name that resolves to a public address is
 * the owner's to prevent.
 */
export const PRIVATE_HOSTS =
  "loopback, a private IP address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, fe80::/10), a single-label name that is not a public top-level domain, or a name ending in .internal, .local, .lan, .corp, .home.arpa, or .intranet";

/**
 * Why `url` is not acceptable when plain HTTP is permitted, or undefined:
 * plain HTTP is accepted only to a private or internal host.
 * An https URL is never this function's concern.
 */
export function plainHttpProblem(url: URL): string | undefined {
  if (url.protocol !== "http:" || isPrivateNetworkHost(url.hostname))
    return undefined;
  return `Plain HTTP is accepted only to a private or internal host (${PRIVATE_HOSTS}); ${url.hostname} is public, so serve it over https`;
}

/**
 * Whether a plain-HTTP host name is answered by mDNS (`.local`) or completed
 * with the machine's DNS search domains (a single label), either of which
 * another device on the network can answer for.
 */
export function spoofableHostName(hostname: string): boolean {
  const name = hostname.toLowerCase();
  return (
    name.endsWith(".local") ||
    (!name.includes(".") && !name.includes(":") && name !== "localhost")
  );
}

/** The `validate` warning for `spoofableHostName`. */
export function spoofableHostWarning(hostname: string): string {
  return `${hostname} is resolved through mDNS or the machine's DNS search domains, which another device on the network can answer for; over plain HTTP nothing verifies the server, so use an IP address or a fully qualified name under .internal or .corp`;
}
