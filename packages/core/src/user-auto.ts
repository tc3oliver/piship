// The user's auto mode switch (`policy.userAuto: allowed`): a managed user
// may have every policy `ask` approved without a prompt. The switch lives in
// the distribution state, so `uninstall` keeps it and `purge` removes it. It
// is bound to the principal binding it was turned on under, so a different
// signed-in identity (or the same one after another took the state in
// between) finds it off, as it finds its model selection cleared.
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { PolicyConfig } from "@piship/schema";
import { accessStatePaths, writeJsonAtomic } from "./access/state.js";

export const USER_AUTO_SCHEMA = "piship-user-auto/v1";

/** `<state>/config/auto.json`. Tools never read or write the state. */
export function userAutoPath(stateDir: string): string {
  return join(stateDir, "config", "auto.json");
}

/** The principal binding record the switch was turned on under. */
interface Binding {
  readonly issuer: string;
  readonly subject: string;
  readonly bound_at: string;
}

/**
 * The state's principal binding as stored: null when there is none (no
 * identity, or never signed in), undefined when it cannot be read.
 */
function readBinding(stateDir: string): Binding | null | undefined {
  const path = accessStatePaths(stateDir).principal;
  if (!existsSync(path)) return null;
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as Partial<Binding>;
    if (
      typeof value?.issuer !== "string" ||
      typeof value.subject !== "string" ||
      typeof value.bound_at !== "string"
    )
      return undefined;
    return {
      issuer: value.issuer,
      subject: value.subject,
      bound_at: value.bound_at,
    };
  } catch {
    return undefined;
  }
}

function sameBinding(a: Binding | null, b: Binding | null): boolean {
  if (!a || !b) return !a && !b;
  return (
    a.issuer === b.issuer &&
    a.subject === b.subject &&
    a.bound_at === b.bound_at
  );
}

/** The stored switch; an unreadable or foreign file counts as off. */
function readStored(
  stateDir: string,
): { readonly binding: Binding | null } | null {
  const path = userAutoPath(stateDir);
  if (!existsSync(path)) return null;
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as {
      schema?: unknown;
      enabled?: unknown;
      binding?: unknown;
    };
    if (value?.schema !== USER_AUTO_SCHEMA || value.enabled !== true)
      return null;
    const binding = value.binding as Partial<Binding> | null | undefined;
    if (binding === null) return { binding: null };
    if (
      typeof binding?.issuer !== "string" ||
      typeof binding.subject !== "string" ||
      typeof binding.bound_at !== "string"
    )
      return null;
    return {
      binding: {
        issuer: binding.issuer,
        subject: binding.subject,
        bound_at: binding.bound_at,
      },
    };
  } catch {
    return null;
  }
}

/**
 * - `on`: allowed and switched on by the identity that owns the state.
 * - `off`: allowed and not switched on.
 * - `reset`: switched on under another principal binding; off until turned
 *   on again.
 * - `inert`: switched on, but the installed release does not allow auto
 *   mode, so the switch has no effect.
 * - `not-allowed`: the release does not allow auto mode.
 */
export type UserAutoState = "on" | "off" | "reset" | "inert" | "not-allowed";

export interface UserAutoStatus {
  /** Whether the installed release lets this user switch auto mode on. */
  readonly allowed: boolean;
  readonly state: UserAutoState;
  /** Whether `ask` decisions are approved without a prompt. */
  readonly active: boolean;
}

/** Auto mode exists only for managed distributions that declare `allowed`. */
export function userAutoAllowed(
  policy: Pick<PolicyConfig, "userAuto"> | undefined,
  mode: "personal" | "managed",
): boolean {
  return mode === "managed" && policy?.userAuto === "allowed";
}

/** The effective auto mode for the release and state in hand. */
export function userAutoStatus(
  stateDir: string,
  policy: Pick<PolicyConfig, "userAuto"> | undefined,
  mode: "personal" | "managed",
): UserAutoStatus {
  const allowed = userAutoAllowed(policy, mode);
  const stored = readStored(stateDir);
  if (!stored)
    return { allowed, state: allowed ? "off" : "not-allowed", active: false };
  if (!allowed) return { allowed, state: "inert", active: false };
  const binding = readBinding(stateDir);
  if (binding === undefined || !sameBinding(stored.binding, binding))
    return { allowed, state: "reset", active: false };
  return { allowed, state: "on", active: true };
}

/**
 * Switch auto mode on (bound to the current principal binding) or off (the
 * file is removed). The caller checks that the release allows it.
 */
export function setUserAuto(
  stateDir: string,
  enabled: boolean,
  now: Date = new Date(),
): void {
  const path = userAutoPath(stateDir);
  if (!enabled) {
    rmSync(path, { force: true });
    return;
  }
  const binding = readBinding(stateDir);
  writeJsonAtomic(path, {
    schema: USER_AUTO_SCHEMA,
    enabled: true,
    // An unreadable binding binds to nothing a later read can match.
    binding: binding ?? null,
    changed_at: now.toISOString(),
  });
}

/** The principal binding as an audit principal, or null without one. */
export function userAutoPrincipal(
  stateDir: string,
): { readonly issuer: string; readonly subject: string } | null {
  const binding = readBinding(stateDir);
  return binding ? { issuer: binding.issuer, subject: binding.subject } : null;
}

/** One line for `doctor` and `auto status`. */
export function describeUserAuto(status: UserAutoStatus): string {
  switch (status.state) {
    case "on":
      return "on: asks from the distribution defaults are approved without a prompt and audited; deny and enforced rules still apply";
    case "off":
      return "off (the distribution allows it)";
    case "reset":
      return "off: it was turned on under a previously signed-in identity, so it was reset; turn it on again to use it";
    case "inert":
      return "off: the switch is on, but this release does not allow auto mode (policy.userAuto), so it has no effect";
    case "not-allowed":
      return "not allowed by this distribution";
  }
}
