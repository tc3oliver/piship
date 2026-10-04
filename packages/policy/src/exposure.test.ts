import {
  migrateManifestSource,
  parseManifest,
  type ToolExposureRule,
} from "@piship/schema";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import {
  EXPOSURE_VISIBILITY,
  effectiveExposure,
  globsOverlap,
  overlappingTies,
  resolveExposure,
  specificity,
} from "./exposure.js";

const rules: ToolExposureRule[] = [
  { pattern: "delete_*", exposure: "hidden" },
  { pattern: "delete_draft", exposure: "direct" },
  { pattern: "get_*", exposure: "deferred" },
  { pattern: "*", exposure: "codemode" },
];

describe("tool exposure resolution", () => {
  it("ranks an exact name above every glob, then by literal characters", () => {
    expect(specificity("delete_draft")).toBe(Number.POSITIVE_INFINITY);
    expect(specificity("delete_*")).toBeGreaterThan(specificity("*"));
    expect(specificity("delete_dr*")).toBeGreaterThan(specificity("delete_*"));
  });

  it("applies the most specific matching rule, whatever the order", () => {
    expect(resolveExposure("delete_draft", rules, "direct")).toEqual({
      exposure: "direct",
      rule: "delete_draft",
    });
    expect(resolveExposure("delete_repo", rules, "direct")).toEqual({
      exposure: "hidden",
      rule: "delete_*",
    });
    expect(
      resolveExposure("get_issue", [...rules].reverse(), "direct"),
    ).toEqual({ exposure: "deferred", rule: "get_*" });
    expect(resolveExposure("search", rules, "direct")).toEqual({
      exposure: "codemode",
      rule: "*",
    });
  });

  it("takes the fallback when no rule matches", () => {
    expect(resolveExposure("bash", [], "direct")).toEqual({
      exposure: "direct",
    });
    expect(
      resolveExposure(
        "bash",
        [{ pattern: "git_*", exposure: "hidden" }],
        "deferred",
      ),
    ).toEqual({ exposure: "deferred" });
  });

  it("reports equal-specificity matches as a tie, and a tie is hidden", () => {
    const tied: ToolExposureRule[] = [
      { pattern: "get_*", exposure: "direct" },
      { pattern: "*_lst", exposure: "deferred" },
    ];
    const resolution = resolveExposure("get_lst", tied, "direct");
    expect(resolution).toEqual({ tie: ["get_*", "*_lst"] });
    expect(effectiveExposure(resolution, false)).toBe("hidden");
    // Same literal count, but no name matches both.
    expect(resolveExposure("get_x", tied, "direct")).toEqual({
      exposure: "direct",
      rule: "get_*",
    });
  });

  it("finds statically provable ties, not disjoint or ranked globs", () => {
    expect(
      overlappingTies([
        { pattern: "get_*", exposure: "direct" },
        { pattern: "*_lst", exposure: "deferred" },
        { pattern: "put_*", exposure: "hidden" },
        { pattern: "put_x*", exposure: "direct" },
      ]),
    ).toEqual([
      ["get_*", "*_lst"],
      ["*_lst", "put_*"],
    ]);
    expect(globsOverlap("get_*", "put_*")).toBe(false);
    expect(globsOverlap("a*b", "*")).toBe(true);
    expect(globsOverlap("a*b", "a*c")).toBe(false);
  });

  it("collapses a policy deny to hidden, whatever the rule says", () => {
    expect(effectiveExposure({ exposure: "direct" }, true)).toBe("hidden");
    expect(effectiveExposure({ exposure: "deferred" }, false)).toBe("deferred");
  });

  it("resolves a migrated v1alpha5 tool filter exactly like v0.8's deny-wins filter", () => {
    const source = (tools: string) =>
      [
        "schema: piship/v1alpha5",
        "app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }",
        'runtime: { pi: "1.0.0" }',
        "deployment: { mode: personal }",
        "mcp:",
        "  servers:",
        `    docs: { transport: stdio, module: ./mcp/docs.mjs, tools: ${tools} }`,
        "updates: { channel: stable, channels: [stable] }",
        "",
      ].join("\n");
    const names = ["search", "get_issue", "delete_issue", "other", "get_*"];
    for (const [allow, deny] of [
      [["search", "get_issue"], ["delete_issue"]],
      [[], ["delete_issue", "search"]],
      [["search"], []],
      [[], []],
    ] as [string[], string[]][]) {
      const tools = `{ allow: ${JSON.stringify(allow)}, deny: ${JSON.stringify(deny)} }`;
      const migrated = parseManifest(
        parseYaml(migrateManifestSource(source(tools)).source),
      ).governance?.mcp.servers[0];
      if (!migrated) throw new Error("no server");
      for (const name of names) {
        // v0.8: deny wins; an empty allow list admits every tool not denied.
        const v08 =
          !deny.includes(name) && (!allow.length || allow.includes(name));
        const resolved = effectiveExposure(
          resolveExposure(
            name,
            migrated.toolExposure ?? [],
            migrated.exposure ?? "direct",
          ),
          false,
        );
        expect(resolved !== "hidden", `${tools} ${name}`).toBe(v08);
      }
    }
  });

  it("orders exposures from excluded to always declared", () => {
    const order = Object.entries(EXPOSURE_VISIBILITY)
      .sort(([, a], [, b]) => a - b)
      .map(([name]) => name);
    expect(order).toEqual([
      "hidden",
      "deferred",
      "codemode",
      "model-only",
      "direct",
    ]);
  });
});
