// Identity headers of Streamable HTTP MCP servers: which identity claims may
// become a header value and which header names are refused. The manifest
// parser and the MCP transport both apply these rules.

/**
 * The identity claims an MCP header may carry: string claims of the
 * signed-in OIDC identity that PiShip keeps (`RETAINED_CLAIMS`). `name` is a
 * display field and not offered; `email` is sent only when the identity also
 * has `email_verified: true`.
 */
export const MCP_IDENTITY_HEADER_CLAIMS = [
  "sub",
  "preferred_username",
  "email",
] as const;
export type McpIdentityHeaderClaim =
  (typeof MCP_IDENTITY_HEADER_CLAIMS)[number];

/** An HTTP field name (RFC 9110 token), at most 64 characters. */
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;

/**
 * Header names an identity header may not use: authentication, cookies,
 * hop-by-hop and framing headers, content negotiation, proxy and client
 * address headers, method overrides, and the headers the Streamable HTTP
 * transport sets itself. Compared case-insensitively; `Sec-` and
 * `X-Forwarded-` names are refused as prefixes.
 */
const RESERVED_HEADERS = new Set([
  "accept",
  "accept-encoding",
  "authorization",
  "connection",
  "content-encoding",
  "content-length",
  "content-type",
  "cookie",
  "expect",
  "forwarded",
  "host",
  "keep-alive",
  "last-event-id",
  "mcp-protocol-version",
  "mcp-session-id",
  "origin",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "set-cookie",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "user-agent",
  "via",
  "www-authenticate",
  "x-http-method",
  "x-http-method-override",
  "x-method-override",
  "x-real-ip",
]);
const RESERVED_PREFIXES = ["sec-", "x-forwarded-"];

/**
 * Why `name` cannot be an identity header, or undefined when it can. The
 * message never needs the header's value.
 */
export function mcpIdentityHeaderProblem(name: string): string | undefined {
  if (!HEADER_NAME.test(name) || name === "__proto__")
    return "Header names are HTTP tokens: letters, digits, and !#$%&'*+.^_`|~- (at most 64)";
  const lower = name.toLowerCase();
  if (
    RESERVED_HEADERS.has(lower) ||
    RESERVED_PREFIXES.some((prefix) => lower.startsWith(prefix))
  )
    return `${name} is reserved: authentication, cookie, hop-by-hop, framing, proxy, method-override, and MCP transport headers cannot be set`;
  return undefined;
}
