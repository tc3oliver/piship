import { existsSync, readFileSync } from "node:fs";
import { PiShipError } from "@piship/contracts";
import {
  CONFIG_KEYS,
  type AccessManifest,
  type ConfigKey,
  THINKING_LEVELS,
} from "@piship/schema";
import { writeJsonAtomic } from "./access/state.js";

export const PREFERENCES_SCHEMA = "piship-preferences/v1";

export interface UserPreferences {
  readonly schema: typeof PREFERENCES_SCHEMA;
  readonly values: Partial<Record<ConfigKey, string>>;
  /** Optional narrowing of the model allowlist; never widens it. */
  readonly modelsAllowed?: readonly string[];
}

export type ConfigSource =
  | "distribution-enforced"
  | "distribution-default"
  | "user-preference"
  | "builtin-default"
  | "runtime-environment"
  | "intersection";

export interface ExplainedValue {
  readonly key: string;
  readonly value: unknown;
  readonly source: ConfigSource;
  readonly overridable: boolean;
  readonly note?: string;
}

export interface EffectiveConfig {
  readonly values: Readonly<Record<ConfigKey, string | undefined>>;
  readonly allowedModels: readonly string[];
  /**
   * True when any policy, entitlement, or preference restricts models. An
   * empty `allowedModels` then means no model is selectable, not "any model".
   */
  readonly modelsRestricted: boolean;
  readonly entries: readonly ExplainedValue[];
  /** Visible problems, such as a user preference that policy overrides. */
  readonly notices: readonly string[];
}

const EMPTY: UserPreferences = { schema: PREFERENCES_SCHEMA, values: {} };

export function readPreferences(path: string): UserPreferences {
  if (!existsSync(path)) return EMPTY;
  try {
    const value = JSON.parse(
      readFileSync(path, "utf8"),
    ) as Partial<UserPreferences>;
    if (
      value.schema !== PREFERENCES_SCHEMA ||
      typeof value.values !== "object" ||
      value.values === null
    )
      throw new Error("schema");
    const values: Partial<Record<ConfigKey, string>> = {};
    for (const key of CONFIG_KEYS) {
      const item = (value.values as Record<string, unknown>)[key];
      if (typeof item === "string") values[key] = item;
    }
    return {
      schema: PREFERENCES_SCHEMA,
      values,
      ...(Array.isArray(value.modelsAllowed)
        ? {
            modelsAllowed: value.modelsAllowed.filter(
              (item): item is string => typeof item === "string",
            ),
          }
        : {}),
    };
  } catch {
    throw new PiShipError(
      "CONFIG_INVALID",
      `User preferences are unreadable: ${path}`,
      {
        component: "config",
        userAction: "Fix or delete the preferences file",
      },
    );
  }
}

function writePreferences(path: string, preferences: UserPreferences): void {
  writeJsonAtomic(path, preferences);
}

interface PolicyView {
  readonly enforced: Partial<Record<ConfigKey, string>>;
  readonly defaults: Partial<Record<ConfigKey, string>>;
  readonly userOverridable: readonly ConfigKey[];
  readonly allowed: readonly string[];
  readonly defaultModel: string | undefined;
}

function policyView(
  access: AccessManifest | undefined,
  appTheme: string | undefined,
): PolicyView {
  if (!access)
    return {
      enforced: {},
      defaults: appTheme ? { theme: appTheme } : {},
      userOverridable: ["model", "theme", "thinkingLevel"],
      allowed: [],
      defaultModel: undefined,
    };
  return {
    enforced: access.config.enforced,
    defaults: {
      ...(appTheme ? { theme: appTheme } : {}),
      ...access.config.defaults,
      ...(access.models.default ? { model: access.models.default } : {}),
    },
    userOverridable: access.config.userOverridable,
    allowed: access.models.allowed,
    defaultModel: access.models.default,
  };
}

/** Validate and store one user preference; enforced and security fields are refused. */
export function setPreference(
  path: string,
  access: AccessManifest | undefined,
  appTheme: string | undefined,
  key: string,
  value: string | undefined,
): UserPreferences {
  const policy = policyView(access, appTheme);
  const current = readPreferences(path);
  if (key === "models.allowed") {
    if (value === undefined) {
      const { modelsAllowed: _removed, ...rest } = current;
      writePreferences(path, rest);
      return rest;
    }
    const list = value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    if (!list.length)
      throw new PiShipError(
        "CONFIG_INVALID",
        "models.allowed needs at least one model",
        { component: "config" },
      );
    const widening = policy.allowed.length
      ? list.filter((item) => !policy.allowed.includes(item))
      : [];
    if (widening.length)
      throw new PiShipError(
        "POLICY_DENIED",
        `User preferences can only narrow the distribution allowlist; not allowed: ${widening.join(", ")}`,
        { component: "config" },
      );
    const next = { ...current, modelsAllowed: list };
    writePreferences(path, next);
    return next;
  }
  if (!(CONFIG_KEYS as readonly string[]).includes(key))
    throw new PiShipError(
      "POLICY_DENIED",
      /^(identity|credential|inference|network|variables|models)(\.|$)/.test(
        key,
      )
        ? `${key} is security-sensitive and cannot be set by a user preference`
        : `Unknown preference ${key}; use one of ${[...CONFIG_KEYS, "models.allowed"].join(", ")}`,
      { component: "config" },
    );
  const configKey = key as ConfigKey;
  if (
    policy.enforced[configKey] !== undefined ||
    !policy.userOverridable.includes(configKey)
  )
    throw new PiShipError(
      "POLICY_DENIED",
      `${key} is enforced by the distribution and cannot be overridden`,
      {
        component: "config",
      },
    );
  if (value !== undefined) {
    if (
      configKey === "thinkingLevel" &&
      !(THINKING_LEVELS as readonly string[]).includes(value)
    )
      throw new PiShipError(
        "CONFIG_INVALID",
        `thinkingLevel must be one of ${THINKING_LEVELS.join(", ")}`,
        { component: "config" },
      );
    if (configKey === "theme" && !/^[a-z][a-z0-9-]*$/.test(value))
      throw new PiShipError(
        "CONFIG_INVALID",
        "Theme names use lowercase letters, digits, and hyphens",
        { component: "config" },
      );
    if (
      configKey === "model" &&
      policy.allowed.length &&
      !policy.allowed.includes(value)
    )
      throw new PiShipError(
        "MODEL_DENIED",
        `Model ${value} is not allowed by this distribution`,
        {
          component: "config",
          userAction: `Choose one of: ${policy.allowed.join(", ")}`,
        },
      );
  }
  const values = { ...current.values };
  if (value === undefined) delete values[configKey];
  else values[configKey] = value;
  const next = { ...current, values };
  writePreferences(path, next);
  return next;
}

/**
 * Resolve Distribution Enforced > Distribution Defaults > User Preferences:
 * enforced values can never be overridden; defaults apply unless the
 * distribution permits a user preference for that key, which then replaces the
 * default; a user value applies only for permitted keys;
 * model allowlists intersect (distribution ∩ credential entitlement ∩ user).
 */
export function resolveEffectiveConfig(
  access: AccessManifest | undefined,
  appTheme: string | undefined,
  preferences: UserPreferences,
  entitledModels?: readonly string[],
): EffectiveConfig {
  const policy = policyView(access, appTheme);
  const notices: string[] = [];
  const entries: ExplainedValue[] = [];
  const values = {} as Record<ConfigKey, string | undefined>;
  for (const key of CONFIG_KEYS) {
    const enforced = policy.enforced[key];
    const user = preferences.values[key];
    const permitted =
      policy.userOverridable.includes(key) && enforced === undefined;
    if (enforced !== undefined) {
      values[key] = enforced;
      if (user !== undefined && user !== enforced)
        notices.push(
          `Preference ${key}=${user} is ignored: the distribution enforces ${enforced}`,
        );
      entries.push({
        key,
        value: enforced,
        source: "distribution-enforced",
        overridable: false,
      });
    } else if (user !== undefined && permitted) {
      values[key] = user;
      entries.push({
        key,
        value: user,
        source: "user-preference",
        overridable: true,
      });
    } else if (policy.defaults[key] !== undefined) {
      if (user !== undefined)
        notices.push(
          `Preference ${key}=${user} is ignored: ${key} is not user-overridable`,
        );
      values[key] = policy.defaults[key];
      entries.push({
        key,
        value: policy.defaults[key],
        source: "distribution-default",
        overridable: permitted,
      });
    } else {
      values[key] = undefined;
      entries.push({
        key,
        value: null,
        source: "builtin-default",
        overridable: permitted,
        note: "Pi default",
      });
    }
  }
  let allowed = [...policy.allowed];
  const sources: string[] = ["distribution"];
  if (policy.enforced.model !== undefined) {
    // An enforced model is the only selectable model, at startup and later.
    allowed = allowed.length
      ? allowed.filter((item) => item === policy.enforced.model)
      : [policy.enforced.model];
    sources.push("enforced model");
  }
  if (entitledModels) {
    // A credential is entitled to physical models; a virtual model is
    // entitled through any of its routes.
    const routes = (id: string) =>
      access?.models.catalog.find((entry) => entry.id === id)?.virtual?.routes;
    allowed = allowed.filter(
      (item) =>
        entitledModels.includes(item) ||
        (routes(item)?.some((route) => entitledModels.includes(route)) ??
          false),
    );
    sources.push("credential entitlement");
  }
  if (preferences.modelsAllowed) {
    // Users only narrow: without any other restriction their list is the
    // allowlist; otherwise it intersects the enforced, allowed, and entitled set.
    allowed =
      sources.length > 1 || policy.allowed.length
        ? allowed.filter((item) => preferences.modelsAllowed?.includes(item))
        : [...preferences.modelsAllowed];
    sources.push("user narrowing");
  }
  entries.push({
    key: "models.allowed",
    value: allowed,
    source: sources.length > 1 ? "intersection" : "distribution-enforced",
    overridable: false,
    note: `${sources.join(" ∩ ")}; users may only narrow`,
  });
  return {
    values,
    allowedModels: allowed,
    modelsRestricted: policy.allowed.length > 0 || sources.length > 1,
    entries,
    notices,
  };
}
