import { BUILTIN_DEFAULT_RULE } from "@piship/policy";
import type { ToolExposureRule } from "@piship/schema";
import { describe, expect, it } from "vitest";
import type { GovernanceSession } from "../governance-session.js";
import {
  buildExposureTable,
  DEFAULT_EXPOSURE_CONFIG,
  type ExposureConfig,
  type ExtensionToolInfo,
  exposureConfigOf,
  exposureExtensions,
  mcpToolExposure,
  UNGOVERNED_PI_BASE_TOOLS,
} from "./exposure.js";

interface Fake {
  readonly mode?: "managed" | "personal";
  readonly builtin?: readonly string[];
  /** `<action> <resource>` decided deny. */
  readonly deny?: readonly string[];
  /** `<action> <resource>` decided only by the built-in default. */
  readonly fallback?: readonly string[];
  readonly mcpTools?: readonly { server: string; tool: string }[];
  readonly servers?: readonly {
    id: string;
    exposure?: string;
    toolExposure?: ToolExposureRule[];
  }[];
}

/** The parts of a governance session the exposure table reads. */
function gov(fake: Fake = {}): GovernanceSession {
  return {
    options: { lock: { deployment: { mode: fake.mode ?? "personal" } } },
    loader: { builtin: new Set(fake.builtin ?? []) },
    manifest: { mcp: { mode: "allowlist", servers: fake.servers ?? [] } },
    engine: {
      evaluate: ({
        action,
        resource,
      }: {
        action: string;
        resource: string;
      }) => {
        const key = `${action} ${resource}`;
        return {
          effect: fake.deny?.includes(key) ? "deny" : "ask",
          ruleId: fake.fallback?.includes(key) ? BUILTIN_DEFAULT_RULE : "rule",
        };
      },
    },
    mcp: {
      tools: () =>
        (fake.mcpTools ?? []).map(({ server, tool }) => ({
          name: `mcp__${server}__${tool}`,
          server,
          tool,
        })),
    },
  } as unknown as GovernanceSession;
}

const config = (overrides: Partial<ExposureConfig> = {}): ExposureConfig => ({
  ...DEFAULT_EXPOSURE_CONFIG,
  ...overrides,
});

const extension = (
  exposure?: ExtensionToolInfo["exposure"],
  prepareLoadout = false,
): ExtensionToolInfo => ({
  ...(exposure ? { exposure } : {}),
  prepareLoadout,
  extension: "/ext/index.js",
});

describe("runtime.tools of a launch", () => {
  it("comes from the v1alpha6 lock, and an older lock keeps the v0.8 defaults", () => {
    const runtimeTools = config({ codemode: "only", toolSearch: "on" });
    const withLock = (lock: object) =>
      ({ options: { lock } }) as unknown as GovernanceSession;
    expect(exposureConfigOf(withLock({ runtimeTools }))).toBe(runtimeTools);
    expect(exposureConfigOf(withLock({}))).toEqual(DEFAULT_EXPOSURE_CONFIG);
  });
});

describe("session tool exposure table", () => {
  it("always excludes Pi's ungoverned base tools, and keeps v0.8 tools direct", () => {
    const table = buildExposureTable(gov(), config(), new Map());
    for (const name of UNGOVERNED_PI_BASE_TOOLS)
      expect(table.excluded()).toContain(name);
    for (const name of ["read", "write", "edit", "bash"])
      expect(table.get(name)).toBe("direct");
    // ask_user is PiShip's only while the piship-ask-user builtin is loaded.
    expect(table.get("ask_user")).toBeUndefined();
    expect(
      buildExposureTable(
        gov({ builtin: ["piship-ask-user"] }),
        config(),
        new Map(),
      ).get("ask_user"),
    ).toBe("direct");
    // Codemode and tool search are off: excluded, never activated.
    expect(table.excluded()).toEqual(
      expect.arrayContaining(["codemode", "tool_search"]),
    );
    expect(table.mandatoryActive()).toEqual([]);
  });

  it("hides a tool the policy denies, in any layer, and leaves ask unchanged", () => {
    const table = buildExposureTable(
      gov({
        deny: ["tool.execute bash", "mcp.tool.call docs:drop"],
        mcpTools: [
          { server: "docs", tool: "drop" },
          { server: "docs", tool: "search" },
        ],
      }),
      config(),
      new Map(),
    );
    expect(table.get("bash")).toBe("hidden");
    expect(table.get("mcp__docs__drop")).toBe("hidden");
    expect(table.get("mcp__docs__search")).toBe("direct");
    expect(table.get("read")).toBe("direct");
    expect(table.excluded()).toEqual(
      expect.arrayContaining(["bash", "mcp__docs__drop"]),
    );
  });

  it("resolves MCP tools against their server's rules, most specific first", () => {
    const fake = gov({
      servers: [
        {
          id: "github",
          exposure: "deferred",
          toolExposure: [
            { pattern: "delete_*", exposure: "hidden" },
            { pattern: "delete_draft", exposure: "direct" },
            { pattern: "search_*", exposure: "codemode" },
          ],
        },
      ],
    });
    expect(mcpToolExposure(fake, "github", "delete_repo")).toBe("hidden");
    expect(mcpToolExposure(fake, "github", "delete_draft")).toBe("direct");
    expect(mcpToolExposure(fake, "github", "search_code")).toBe("codemode");
    expect(mcpToolExposure(fake, "github", "get_issue")).toBe("deferred");
    // A project server declares nothing: direct.
    expect(mcpToolExposure(fake, "project", "anything")).toBe("direct");
    expect(exposureExtensions(fake, config()).toolSearch).toBe(true);
  });

  it("refuses an extension tool declared wider than the manifest allows", () => {
    const rules = config({
      exposure: [{ pattern: "company_*", exposure: "deferred" }],
    });
    expect(() =>
      buildExposureTable(
        gov(),
        rules,
        new Map([["company_deploy", extension()]]),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "CONFIG_INVALID",
        message: expect.stringContaining(
          "company_deploy declares exposure direct",
        ),
      }),
    );
    const table = buildExposureTable(
      gov(),
      rules,
      new Map([
        ["company_search", extension("deferred")],
        ["company_hint", extension("hidden")],
        ["other", extension("codemode", true)],
      ]),
    );
    expect(table.get("company_search")).toBe("deferred");
    expect(table.get("other")).toBe("codemode");
    expect(table.prepareLoadoutTools()).toEqual(["other"]);
    expect(table.excluded()).toContain("company_hint");
  });

  it("excludes an extension tool the manifest hides or the policy denies", () => {
    const table = buildExposureTable(
      gov({ deny: ["tool.execute denied_tool"] }),
      config({ exposure: [{ pattern: "secret_*", exposure: "hidden" }] }),
      new Map([
        ["secret_dump", extension()],
        ["denied_tool", extension()],
        ["plain", extension()],
        // PiShip's own tool wins over an extension tool of the same name.
        ["read", extension("hidden")],
      ]),
    );
    expect(table.excluded()).toEqual(
      expect.arrayContaining(["secret_dump", "denied_tool"]),
    );
    expect(table.get("plain")).toBe("direct");
    expect(table.get("read")).toBe("direct");
  });

  it("turns tool search on for a deferred tool, and activates Codemode", () => {
    const table = buildExposureTable(
      gov(),
      config({
        codemode: "on",
        exposure: [{ pattern: "bash", exposure: "deferred" }],
      }),
      new Map(),
    );
    expect(table.codemodeOn).toBe(true);
    expect(table.toolSearchOn).toBe(true);
    expect(table.mandatoryActive()).toEqual(["codemode", "tool_search"]);
    expect(table.get("codemode")).toBe("model-only");
    expect(table.excluded()).not.toContain("codemode");
  });

  it("managed: refuses Codemode when a reachable tool falls back to the built-in default", () => {
    const managed = gov({
      mode: "managed",
      fallback: ["tool.execute bash"],
    });
    expect(() =>
      buildExposureTable(managed, config({ codemode: "on" }), new Map()),
    ).toThrow(expect.objectContaining({ code: "POLICY_DENIED" }));
    // Hidden from scripts by exposure: nothing for Codemode to reach.
    expect(
      buildExposureTable(
        managed,
        config({
          codemode: "on",
          exposure: [{ pattern: "bash", exposure: "hidden" }],
        }),
        new Map(),
      ).codemodeOn,
    ).toBe(true);
    // Personal mode leaves the policy to its owner.
    expect(
      buildExposureTable(
        gov({ fallback: ["tool.execute bash"] }),
        config({ codemode: "on" }),
        new Map(),
      ).codemodeOn,
    ).toBe(true);
  });

  it("keeps Codemode off when the policy denies the codemode tool", () => {
    const table = buildExposureTable(
      gov({ deny: ["tool.execute codemode"] }),
      config({ codemode: "on" }),
      new Map(),
    );
    expect(table.codemodeOn).toBe(false);
    expect(table.excluded()).toContain("codemode");
  });
});
