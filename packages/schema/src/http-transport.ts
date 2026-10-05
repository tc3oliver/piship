// `httpTransport` (piship/v1alpha6): the per-endpoint opt-in to plain HTTP
// to a private or internal host. The default, `https`, keeps plain HTTP to
// loopback only.
import { isPrivateNetworkHost } from "@piship/contracts";

/** `<endpoint>.httpTransport`: `https` (the default) or `http-allowed`. */
export const HTTP_TRANSPORTS = ["https", "http-allowed"] as const;
export type HttpTransport = (typeof HTTP_TRANSPORTS)[number];

/**
 * The hosts `http-allowed` accepts over plain HTTP (`isPrivateNetworkHost`).
 * Only the name is judged, never DNS: a single label is completed with the
 * machine's DNS search domains, so it reaches whatever those domains resolve
 * it to, and an internal-looking name that resolves to a public address is
 * the owner's to prevent.
 */
export const PRIVATE_HOSTS =
  "loopback, a private IP address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, fe80::/10), a single-label name that is not a public top-level domain, or a name ending in .internal, .local, .lan, .corp, .home.arpa, or .intranet";

/**
 * Why `url` is not acceptable under `httpTransport: http-allowed`, or
 * undefined: plain HTTP is accepted only to a private or internal host.
 * An https URL is never this function's concern.
 */
export function plainHttpProblem(url: URL): string | undefined {
  if (url.protocol !== "http:" || isPrivateNetworkHost(url.hostname))
    return undefined;
  return `httpTransport: http-allowed permits plain HTTP only to a private or internal host (${PRIVATE_HOSTS}); ${url.hostname} is public, so serve it over https`;
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
