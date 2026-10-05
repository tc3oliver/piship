// The piship/v1alpha6 runtime sections: `runtime.tools`, `runtime.cacheWarming`,
// and the `<glob>: <exposure>` maps shared by `runtime.tools.exposure` and
// `mcp.servers.<id>.tools`. Parse level only: precedence between overlapping
// globs is resolved where tools are registered.
import {
  CACHE_WARMING_MODES,
  type CacheWarmingConfig,
  CODEMODE_MODES,
  type RuntimeToolsConfig,
  SEARCH_TOOL_MODES,
  SEARCH_TOOLS,
  type SearchToolsConfig,
  TOOL_EXPOSURES,
  TOOL_SEARCH_MODES,
  type ToolExposure,
  type ToolExposureRule,
} from "../governance.js";
import {
  bool,
  fail,
  isRecord,
  oneOf,
  optionalRecord,
  record,
} from "./fields.js";

/** A tool name, or a glob over tool names with `*`. */
const TOOL_GLOB = /^[A-Za-z0-9_.*-]{1,128}$/;

export function toolGlob(value: string, path: string): string {
  if (!TOOL_GLOB.test(value))
    fail(
      path,
      "Tool globs use letters, digits, _ . - and * (at most 128 characters)",
    );
  return value;
}

export function exposure(value: unknown, path: string): ToolExposure;
export function exposure(
  value: unknown,
  path: string,
  fallback: ToolExposure,
): ToolExposure;
export function exposure(
  value: unknown,
  path: string,
  fallback?: ToolExposure,
): ToolExposure {
  return oneOf(value, path, TOOL_EXPOSURES, fallback);
}

/** A `<glob>: <exposure>` map, in declaration order. */
export function exposureRules(
  value: unknown,
  path: string,
): ToolExposureRule[] {
  if (value === undefined) return [];
  if (!isRecord(value))
    fail(path, "Expected an object mapping tool globs to an exposure");
  return Object.entries(value).map(([pattern, entry]) => ({
    pattern: toolGlob(pattern, `${path}.${pattern}`),
    exposure: exposure(entry, `${path}.${pattern}`),
  }));
}

/** `runtime.tools`; every field is optional and defaults to off. */
export function parseRuntimeTools(value: unknown): RuntimeToolsConfig {
  const tools = optionalRecord(value, "runtime.tools", [
    "codemode",
    "toolSearch",
    "exposure",
  ]);
  return {
    codemode: oneOf(
      tools.codemode,
      "runtime.tools.codemode",
      CODEMODE_MODES,
      "off",
    ),
    toolSearch: oneOf(
      tools.toolSearch,
      "runtime.tools.toolSearch",
      TOOL_SEARCH_MODES,
      "off",
    ),
    exposure: exposureRules(tools.exposure, "runtime.tools.exposure"),
  };
}

/**
 * `runtime.cacheWarming`. An omitted mode is `off` (Pi's own default is
 * `streaming`); an omitted `userOverride` keeps the distribution's mode.
 */
export function parseCacheWarming(value: unknown): CacheWarmingConfig {
  const warming = optionalRecord(value, "runtime.cacheWarming", [
    "mode",
    "userOverride",
  ]);
  return {
    mode: oneOf(
      warming.mode,
      "runtime.cacheWarming.mode",
      CACHE_WARMING_MODES,
      "off",
    ),
    userOverride: bool(
      warming.userOverride,
      "runtime.cacheWarming.userOverride",
      false,
    ),
  };
}

/**
 * `runtime.searchTools`: `mode: bundled` and an optional exact upstream
 * version per tool. Only the versions the manifest declares are kept, so
 * the manifest digest records the declaration, not PiShip's defaults.
 */
export function parseSearchTools(value: unknown): SearchToolsConfig {
  const tools = record(value, "runtime.searchTools", ["mode", ...SEARCH_TOOLS]);
  const mode = oneOf(tools.mode, "runtime.searchTools.mode", SEARCH_TOOL_MODES);
  const versions: { fd?: string; rg?: string } = {};
  for (const tool of SEARCH_TOOLS) {
    const version = tools[tool];
    if (version === undefined) continue;
    if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version))
      fail(
        `runtime.searchTools.${tool}`,
        "Expected an exact upstream release version such as 10.5.0 (quote it in YAML)",
      );
    versions[tool] = version;
  }
  return { mode, ...versions };
}
