// The `PiShip-Client` request header: which distribution, at which version,
// built with which PiShip, speaking which wire protocol, sent to the
// credential broker and the LLM gateway so they can see what calls them.
// It is a self-reported label for the service's own policy, never an
// authentication or authorization input inside PiShip.

/** The header name, lowercase as fetch sends it. */
export const PISHIP_CLIENT_HEADER = "piship-client";

/**
 * The broker and gateway wire protocol this PiShip speaks. 1 is the
 * contract in docs/enterprise-integration.md as of v0.7.x; it increases
 * only when PiShip's requests or its reading of answers change in a way a
 * service must know about.
 */
export const PISHIP_CLIENT_PROTOCOL = 1;

export interface PiShipClient {
  /** The distribution's `app.id`. */
  readonly distribution: string;
  /** The distribution's `app.version`. */
  readonly version: string;
  /** The PiShip version the release was built with. */
  readonly piship: string;
}

// What an RFC 8941 string may hold unescaped: visible ASCII except `"` and `\`.
const SF_STRING = /^[\x21\x23-\x5b\x5d-\x7e]+$/;

/**
 * The header value, an RFC 8941 structured field dictionary:
 * `distribution="acmecode", version="1.4.0", piship="0.7.0", protocol=1`.
 * A service should ignore members it does not know; members are only added.
 */
export function pishipClientHeader(client: PiShipClient): string {
  for (const [name, value] of Object.entries(client))
    if (!SF_STRING.test(value))
      throw new TypeError(`PiShip-Client ${name} is not a header-safe string`);
  return `distribution="${client.distribution}", version="${client.version}", piship="${client.piship}", protocol=${PISHIP_CLIENT_PROTOCOL}`;
}
