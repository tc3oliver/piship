import { existsSync, readFileSync, renameSync } from "node:fs";
import { PiShipError } from "@piship/contracts";
import {
  type AccessManifest,
  CONFIG_KEYS,
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
  /**
   * The allowlist before the user's own narrowing, when there is one: a model
   * in it but not in `allowedModels` is unavailable by preference, not
   * refused by the distribution. `"any"` when nothing else restricted models.
   */
  readonly userNarrowedFrom?: readonly string[] | "any";
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

/**
 * The preferences, or the defaults when the file is damaged. A damaged file
 * is renamed to `<path>.damaged-<timestamp>` (never deleted) so the next
 * write does not replace it, and `notice` says where it went. Preferences
 * only narrow what the distribution allows, so running without them is low
 * risk. `moved` is false when the file could not be moved aside; a caller
 * that is about to write the file must then fail rather than replace it.
 */
export function recoverPreferences(
  path: string,
  now: () => Date = () => new Date(),
): {
  readonly preferences: UserPreferences;
  readonly notice?: string;
  readonly moved: boolean;
  readonly error?: PiShipError;
} {
  try {
    return { preferences: readPreferences(path), moved: true };
  } catch (error) {
    if (!(error instanceof PiShipError)) throw error;
    const stamp = now().toISOString().replace(/[-:.]/g, "");
    let target = `${path}.damaged-${stamp}`;
    for (let n = 2; existsSync(target); n += 1)
      target = `${path}.damaged-${stamp}-${n}`;
    try {
      renameSync(path, target);
      return {
        preferences: EMPTY,
        moved: true,
        notice: `The user preferences file was unreadable, so this run uses the defaults. It was moved aside, not deleted: ${target}`,
      };
    } catch (moveError) {
      // Gone already (another launch moved it): nothing is left to protect.
      if ((moveError as NodeJS.ErrnoException).code === "ENOENT")
        return { preferences: EMPTY, moved: true };
      return {
        preferences: EMPTY,
        moved: false,
        error,
        notice: `The user preferences file is unreadable and could not be moved aside, so this run uses the defaults: ${path}`,
      };
    }
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
  onNotice?: (notice: string) => void,
  /** The installed command, named in the refusals' next step. */
  command?: string,
  /** Who changes the distribution: its administrator, or the user's own piship.yaml. */
  mode: "managed" | "personal" = "managed",
  /** The current sign-in's model entitlement, when it is known. */
  entitledModels?: readonly string[],
): UserPreferences {
  const policy = policyView(access, appTheme);
  const explain = command ? `${command} config explain` : "config explain";
  const personal = mode === "personal";
  const recovered = recoverPreferences(path);
  // Never write over a damaged file that could not be moved aside.
  if (!recovered.moved && recovered.error) throw recovered.error;
  if (recovered.notice) onNotice?.(recovered.notice);
  const current = recovered.preferences;
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
        {
          component: "config",
          userAction: `List only models the distribution allows (${command ? `${command} models` : "the models command"} lists them), ${personal ? "or add them to models.allowed in your piship.yaml" : "or ask your administrator to allow more"}`,
        },
      );
    const next = { ...current, modelsAllowed: list };
    writePreferences(path, next);
    return next;
  }
  const sensitive =
    /^(identity|credential|inference|network|variables|models)(\.|$)/.test(key);
  if (!(CONFIG_KEYS as readonly string[]).includes(key))
    throw new PiShipError(
      "POLICY_DENIED",
      sensitive
        ? `${key} is security-sensitive and cannot be set by a user preference`
        : `Unknown preference ${key}; use one of ${[...CONFIG_KEYS, "models.allowed"].join(", ")}`,
      {
        component: "config",
        ...(sensitive
          ? {
              userAction: personal
                ? `${key} is set in your piship.yaml; ${explain} shows what you can set`
                : `Your administrator sets ${key} in the distribution; ${explain} shows what you can set`,
            }
          : {}),
      },
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
        userAction: personal
          ? `${explain} shows which settings you can change; to change ${key}, edit config.enforced or config.userOverridable in your piship.yaml`
          : `${explain} shows which settings you can change; ask your administrator to change ${key}`,
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
    // Launch would refuse a model the sign-in is not entitled to; say so now.
    const entitled =
      configKey === "model" && entitledModels && policy.allowed.length
        ? resolveEffectiveConfig(access, appTheme, EMPTY, entitledModels)
            .allowedModels
        : undefined;
    if (entitled && !entitled.includes(value))
      throw new PiShipError(
        "MODEL_UNAVAILABLE",
        `Model ${value} is not included in your sign-in's model entitlement`,
        {
          component: "config",
          userAction: `${entitled.length ? `Choose one of: ${entitled.join(", ")}. ` : ""}If your access changed since you signed in, run ${command ? `${command} ` : ""}login, then set it again`,
        },
      );
    const narrowed = current.modelsAllowed;
    if (configKey === "model" && narrowed && !narrowed.includes(value)) {
      const kept = policy.allowed.length
        ? narrowed.filter((item) => policy.allowed.includes(item))
        : narrowed;
      throw new PiShipError(
        "MODEL_DENIED",
        `Model ${value} is excluded by your models.allowed preference`,
        {
          component: "config",
          userAction: `${kept.length ? `Choose one of: ${kept.join(", ")}, or a` : "A"}dd it with ${command ? `${command} ` : ""}config set models.allowed`,
        },
      );
    }
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
  let userNarrowedFrom: readonly string[] | "any" | undefined;
  if (preferences.modelsAllowed) {
    // Users only narrow: without any other restriction their list is the
    // allowlist; otherwise it intersects the enforced, allowed, and entitled set.
    const restricted = sources.length > 1 || policy.allowed.length > 0;
    userNarrowedFrom = restricted ? allowed : "any";
    allowed = restricted
      ? allowed.filter((item) => preferences.modelsAllowed?.includes(item))
      : [...preferences.modelsAllowed];
    sources.push("user narrowing");
    const model = values.model;
    if (
      model !== undefined &&
      !allowed.includes(model) &&
      (userNarrowedFrom === "any" || userNarrowedFrom.includes(model))
    )
      notices.push(
        `Model ${model} is excluded by your models.allowed preference; unset the model preference or add it to models.allowed`,
      );
  }
  const modelsRestricted = policy.allowed.length > 0 || sources.length > 1;
  entries.push({
    key: "models.allowed",
    // An empty list is "none" only when something restricts models.
    value: modelsRestricted ? allowed : "any",
    source: sources.length > 1 ? "intersection" : "distribution-enforced",
    overridable: false,
    note: `${sources.join(" ∩ ")}; users may only narrow`,
  });
  return {
    values,
    allowedModels: allowed,
    modelsRestricted,
    ...(userNarrowedFrom ? { userNarrowedFrom } : {}),
    entries,
    notices,
  };
}
