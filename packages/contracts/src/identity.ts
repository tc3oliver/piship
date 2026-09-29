// Identity contract pieces an adapter author needs alongside
// `IdentityProvider`: the claim allowlist PiShip keeps, and the provider
// shape of a workload identity. `@piship/identity` re-exports both.
import type { IdentityProvider } from "./contracts.js";

/**
 * The only ID-token claims PiShip keeps in session state, which is written to
 * the plaintext `identity/session.json`: identifiers, validity times, and
 * display fields. Anything else an IdP or adapter returns is dropped.
 */
export const RETAINED_CLAIMS: readonly string[] = [
  "sub",
  "iss",
  "aud",
  "azp",
  "exp",
  "iat",
  "auth_time",
  "name",
  "preferred_username",
  "email",
  "email_verified",
  "groups",
];

/**
 * An identity adapter that obtains its session without a person: the
 * identity of a CI job, a scheduled automation, or a managed worker.
 * `login()` must never call `openUrl`; PiShip obtains a session from it at
 * every activation, holds the session in memory only, and never stores it.
 */
export interface WorkloadIdentityProvider extends IdentityProvider {
  readonly interactive: false;
}
