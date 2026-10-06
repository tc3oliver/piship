// Capability selection: contracts, providers, settings, and model requirements.
import {
  BUILTIN_PROVIDERS,
  CAPABILITY_CONTRACTS,
  type CapabilityConfig,
  type CapabilityModelRequirements,
  type CapabilityName,
  type CapabilityProviderRef,
  PROVIDER_TRUST_CLASSES,
  type ProviderTrustClass,
} from "../governance.js";
import { hasRuntimeReference } from "../variables.js";
import {
  bool,
  conflict,
  fail,
  hasControl,
  isRecord,
  list,
  oneOf,
  optionalRecord,
  plainString,
  positiveInteger,
  record,
  relativePath,
  SECRET_FIELD,
  semver,
} from "./fields.js";
import { CERTIFIED_FIELDS, evidence } from "./resources.js";

/** Version reported for PiShip builtin capability providers. */
export const BUILTIN_PROVIDER_VERSION = "1.0.0";

const CAPABILITY_NAMES = Object.keys(CAPABILITY_CONTRACTS) as CapabilityName[];
const CONTRACT_ID =
  /^piship\.capability\/([a-z][a-z0-9-]*)\/v([1-9][0-9]{0,3})$/;
const PROVIDER_NAME = /^[a-z][a-z0-9-]{0,63}$/;
/** The ID of a declared Pi package, as `resources.packages[].id` spells it. */
const PACKAGE_ID = /^[a-z][a-z0-9-]{0,63}$/;

function contractName(contract: string): string {
  return contract.replace(/\/v[0-9]+$/, "");
}

function parseProvider(
  value: unknown,
  path: string,
  capability: CapabilityName,
  v6: boolean,
): CapabilityProviderRef {
  if (!isRecord(value)) fail(path, "Expected an object");
  const id = plainString(value.id, `${path}.id`, 128);
  const [trust, name, ...rest] = id.split("/");
  if (
    rest.length ||
    trust === undefined ||
    name === undefined ||
    !(PROVIDER_TRUST_CLASSES as readonly string[]).includes(trust) ||
    !PROVIDER_NAME.test(name)
  )
    fail(
      `${path}.id`,
      `Expected <class>/<name> with class ${PROVIDER_TRUST_CLASSES.join(", ")} and a lowercase name`,
    );
  const providerClass = trust as ProviderTrustClass;
  const contract = CAPABILITY_CONTRACTS[capability];
  if (providerClass === "upstream")
    fail(`${path}.id`, "Pi ships no upstream capability providers");
  if (providerClass === "builtin") {
    for (const key of Object.keys(value))
      if (key !== "id")
        fail(
          `${path}.${key}`,
          SECRET_FIELD.test(key)
            ? "Secrets are never declared in piship.yaml"
            : "Builtin providers are defined by PiShip; declare only id",
        );
    const implemented = BUILTIN_PROVIDERS[id];
    if (!implemented)
      fail(
        `${path}.id`,
        `Unknown builtin provider; expected one of ${Object.keys(BUILTIN_PROVIDERS).join(", ")}`,
      );
    if (!implemented.includes(contract))
      conflict(`${path}.id`, `${id} does not implement ${contract}`);
    return {
      id,
      class: providerClass,
      version: BUILTIN_PROVIDER_VERSION,
      implements: [...implemented],
    };
  }
  const certified = providerClass === "certified";
  const item = record(value, path, [
    "id",
    "version",
    "implements",
    "path",
    ...(v6 ? ["package"] : []),
    ...(certified ? CERTIFIED_FIELDS : []),
  ]);
  const version = semver(item.version, `${path}.version`);
  if (item.implements === undefined)
    fail(
      `${path}.implements`,
      "List the capability contracts the provider implements",
    );
  const implemented = list(
    item.implements,
    `${path}.implements`,
    (entry, at) => {
      const text = plainString(entry, at, 128);
      if (!CONTRACT_ID.test(text))
        fail(
          at,
          "Expected a contract ID such as piship.capability/permissions/v1",
        );
      return text;
    },
  );
  if (
    !implemented.some((entry) => contractName(entry) === contractName(contract))
  )
    conflict(
      `${path}.implements`,
      `A ${capability} provider must implement ${contractName(contract)}/v<major>`,
    );
  if (item.package !== undefined) {
    if (item.path !== undefined)
      conflict(
        `${path}.package`,
        "A provider is a ./ path or a Pi package, not both",
      );
    // The package declares the class and, for a certified one, the evidence.
    for (const field of CERTIFIED_FIELDS)
      if (item[field] !== undefined)
        conflict(
          `${path}.${field}`,
          "A package provider takes its review evidence from the package declaration",
        );
    const reference = plainString(item.package, `${path}.package`, 64);
    if (!PACKAGE_ID.test(reference))
      fail(
        `${path}.package`,
        "Expected the ID of a package declared under resources.packages",
      );
    return {
      id,
      class: providerClass,
      version,
      implements: implemented,
      package: reference,
    };
  }
  if (item.path === undefined)
    fail(
      `${path}.path`,
      v6
        ? "Non-builtin providers need a ./ path to their extension or the package that provides it"
        : "Non-builtin providers need a ./ path to their extension",
    );
  return {
    id,
    class: providerClass,
    version,
    implements: implemented,
    path: relativePath(item.path, `${path}.path`),
    ...(certified ? { certified: evidence(item, path, id, version) } : {}),
  };
}

function parseSettings(value: unknown, path: string): Record<string, string> {
  if (value === undefined) return {};
  if (!isRecord(value)) fail(path, "Expected an object");
  const output: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    const at = `${path}.${key}`;
    if (!/^[a-z][A-Za-z0-9]{0,63}$/.test(key))
      fail(at, "Setting names use lowerCamelCase letters and digits");
    if (SECRET_FIELD.test(key))
      fail(at, "Secrets are never declared in piship.yaml");
    if (typeof entry !== "string" || entry.trim() === "")
      fail(at, "Expected a non-empty string");
    if (hasRuntimeReference(entry))
      fail(at, "Runtime references are not allowed in this field");
    if (hasControl(entry, true)) fail(at, "Control characters are not allowed");
    if (entry.length > 8192) fail(at, "Use at most 8192 characters");
    output[key] = entry;
  }
  return output;
}

const MODEL_INPUTS = ["text", "image"] as const;

function parseRequirements(
  value: unknown,
  path: string,
): CapabilityModelRequirements | undefined {
  if (value === undefined) return undefined;
  const item = record(value, path, [
    "tools",
    "structuredOutput",
    "minContextWindow",
    "input",
  ]);
  if (!Object.keys(item).length)
    fail(path, "Declare at least one model requirement or omit the field");
  const input =
    item.input === undefined
      ? undefined
      : list(item.input, `${path}.input`, (entry, at) =>
          oneOf(entry, at, MODEL_INPUTS),
        );
  if (input && !input.length)
    fail(`${path}.input`, "Expected at least one input modality");
  return {
    ...(item.tools === undefined
      ? {}
      : { tools: bool(item.tools, `${path}.tools`, false) }),
    ...(item.structuredOutput === undefined
      ? {}
      : {
          structuredOutput: bool(
            item.structuredOutput,
            `${path}.structuredOutput`,
            false,
          ),
        }),
    ...(item.minContextWindow === undefined
      ? {}
      : {
          minContextWindow: positiveInteger(
            item.minContextWindow,
            `${path}.minContextWindow`,
            1,
            100_000_000,
          ),
        }),
    ...(input ? { input } : {}),
  };
}

export function parseCapabilities(
  value: unknown,
  /** piship/v1alpha6 and later: a provider may be a declared Pi package. */
  v6 = false,
): CapabilityConfig[] {
  const capabilities = optionalRecord(value, "capabilities", CAPABILITY_NAMES);
  return CAPABILITY_NAMES.map((name): CapabilityConfig => {
    const path = `capabilities.${name}`;
    const source = capabilities[name];
    if (source === undefined) {
      if (name === "permissions")
        return {
          name,
          enabled: true,
          provider: parseProvider(
            { id: "builtin/permissions" },
            path,
            name,
            v6,
          ),
          settings: {},
        };
      return { name, enabled: false, settings: {} };
    }
    const item = record(source, path, [
      "enabled",
      "provider",
      "settings",
      "requirements",
    ]);
    if (typeof item.enabled !== "boolean")
      fail(`${path}.enabled`, "Expected true or false");
    let provider: CapabilityProviderRef | undefined;
    if (item.provider !== undefined)
      provider = parseProvider(item.provider, `${path}.provider`, name, v6);
    else if (item.enabled) {
      const builtin = Object.keys(BUILTIN_PROVIDERS).find((id) =>
        BUILTIN_PROVIDERS[id]?.includes(CAPABILITY_CONTRACTS[name]),
      );
      if (!builtin)
        fail(
          `${path}.provider`,
          `No builtin provider implements ${CAPABILITY_CONTRACTS[name]}; declare a provider`,
        );
      provider = parseProvider({ id: builtin }, `${path}.provider`, name, v6);
    }
    const requirements = parseRequirements(
      item.requirements,
      `${path}.requirements`,
    );
    return {
      name,
      enabled: item.enabled,
      ...(provider ? { provider } : {}),
      settings: parseSettings(item.settings, `${path}.settings`),
      ...(requirements ? { requirements } : {}),
    };
  });
}
