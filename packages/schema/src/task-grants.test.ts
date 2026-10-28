// `policy.taskGrants` (piship/v1alpha5): optional, strict, gated like userAuto.
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseManifest, readManifestDocument } from "./index.js";

type Json = Record<string, unknown>;
const example = (path: string) =>
  readManifestDocument(
    fileURLToPath(new URL(`../../../examples/${path}`, import.meta.url)),
  ) as Json;
const MANAGED = example("demo-company/piship.yaml");
// The example declares taskGrants; these tests start from a manifest without.
delete (MANAGED.policy as Json).taskGrants;

function withGrants(manifest: Json, value: unknown, schema?: string): Json {
  const copy = structuredClone(manifest);
  copy.policy = { ...((copy.policy as Json) ?? {}), taskGrants: value };
  if (schema) copy.schema = schema;
  return copy;
}

const fieldError = (input: Json) => {
  try {
    parseManifest(input);
  } catch (error) {
    return error as { field?: string; message: string };
  }
  throw new Error("the manifest was accepted");
};

describe("policy.taskGrants", () => {
  it("is absent unless declared, which keeps existing locks unchanged", () => {
    expect(parseManifest(MANAGED).governance?.policy).not.toHaveProperty(
      "taskGrants",
    );
  });

  it("keeps only the fields that were declared", () => {
    expect(
      parseManifest(withGrants(MANAGED, { mode: "off" })).governance?.policy
        .taskGrants,
    ).toEqual({ mode: "off" });
    const full = {
      mode: "session",
      maxTtlMinutes: 60,
      actions: ["web.request", "git.push"],
      wildcardHosts: false,
    };
    expect(
      parseManifest(withGrants(MANAGED, full)).governance?.policy.taskGrants,
    ).toEqual(full);
  });

  it("rejects bad values with the field path", () => {
    const cases: [unknown, string][] = [
      [{ mode: "on" }, "policy.taskGrants.mode"],
      [{}, "policy.taskGrants.mode"],
      [
        { mode: "session", maxTtlMinutes: -5 },
        "policy.taskGrants.maxTtlMinutes",
      ],
      [
        { mode: "session", maxTtlMinutes: 0 },
        "policy.taskGrants.maxTtlMinutes",
      ],
      [
        { mode: "session", maxTtlMinutes: 1.5 },
        "policy.taskGrants.maxTtlMinutes",
      ],
      [
        { mode: "session", maxTtlMinutes: 1441 },
        "policy.taskGrants.maxTtlMinutes",
      ],
      [
        { mode: "session", actions: ["not.an.action"] },
        "policy.taskGrants.actions[0]",
      ],
      [{ mode: "session", actions: [] }, "policy.taskGrants.actions"],
      [
        { mode: "session", actions: ["web.request", "web.request"] },
        "policy.taskGrants.actions[1]",
      ],
      [
        { mode: "session", actions: "web.request" },
        "policy.taskGrants.actions",
      ],
      [
        { mode: "session", wildcardHosts: "yes" },
        "policy.taskGrants.wildcardHosts",
      ],
      [{ mode: "session", extra: 1 }, "policy.taskGrants.extra"],
      ["session", "policy.taskGrants"],
    ];
    for (const [value, field] of cases)
      expect(
        fieldError(withGrants(MANAGED, value)),
        JSON.stringify(value),
      ).toMatchObject({
        field,
      });
  });

  it("says how to forbid grants when actions is empty", () => {
    expect(
      fieldError(withGrants(MANAGED, { mode: "session", actions: [] })),
    ).toMatchObject({ message: expect.stringContaining("use mode off") });
  });

  it("accepts wildcardHosts with actions that exclude web.request, where it has no effect", () => {
    expect(
      parseManifest(
        withGrants(MANAGED, {
          mode: "session",
          actions: ["git.push"],
          wildcardHosts: true,
        }),
      ).governance?.policy.taskGrants,
    ).toMatchObject({ wildcardHosts: true });
  });

  it("is accepted in personal mode too", () => {
    expect(
      parseManifest(
        withGrants(example("personal/piship.yaml"), { mode: "session" }),
      ).governance?.policy.taskGrants,
    ).toEqual({ mode: "session" });
  });

  it("locks typed, bounded manifest grant declarations", () => {
    const declared = [
      {
        id: "fix-ci",
        task: "CI repair",
        ttlMinutes: 30,
        scope: {
          paths: [".", "src"],
          commands: ["npm"],
          mcp: [{ server: "gh", tools: ["create_pr"] }],
        },
        inheritToSubagents: true,
      },
    ];
    expect(
      parseManifest(
        withGrants(MANAGED, {
          mode: "session",
          maxTtlMinutes: 45,
          declared,
        }),
      ).governance?.policy.taskGrants?.declared,
    ).toEqual(declared);
  });

  it("refuses grant declarations that escape workspace, exceed TTL, or lack scope", () => {
    const base = {
      id: "ci",
      task: "test",
      ttlMinutes: 10,
      scope: { paths: ["."] },
      inheritToSubagents: true,
    };
    const invalid: [object, string][] = [
      [
        { ...base, scope: { paths: ["../secrets"] } },
        "policy.taskGrants.declared[0].scope.paths[0]",
      ],
      [
        { ...base, scope: { paths: ["src/./lib"] } },
        "policy.taskGrants.declared[0].scope.paths[0]",
      ],
      [
        { ...base, scope: { paths: ["C:/Windows"] } },
        "policy.taskGrants.declared[0].scope.paths[0]",
      ],
      [
        { ...base, scope: { paths: ["src/CON.txt"] } },
        "policy.taskGrants.declared[0].scope.paths[0]",
      ],
      [
        { ...base, scope: { tools: ["write*"] } },
        "policy.taskGrants.declared[0].scope.tools[0]",
      ],
      [
        { ...base, scope: { commands: ["bash"] } },
        "policy.taskGrants.declared[0].scope.commands[0]",
      ],
      [
        { ...base, scope: { mcp: [{ server: "gh", tools: ["*"] }] } },
        "policy.taskGrants.declared[0].scope.mcp[0].tools[0]",
      ],
      [
        { ...base, scope: { paths: ["/etc"] } },
        "policy.taskGrants.declared[0].scope.paths[0]",
      ],
      [
        { ...base, scope: { paths: [".pi/**"] } },
        "policy.taskGrants.declared[0].scope.paths[0]",
      ],
      [{ ...base, ttlMinutes: 50 }, "policy.taskGrants.declared[0].ttlMinutes"],
      [{ ...base, scope: {} }, "policy.taskGrants.declared[0].scope"],
    ];
    for (const [declared, field] of invalid)
      expect(
        fieldError(
          withGrants(MANAGED, {
            mode: "session",
            maxTtlMinutes: 45,
            declared: [declared],
          }),
        ),
      ).toMatchObject({ field });
    expect(
      fieldError(
        withGrants(MANAGED, {
          mode: "off",
          declared: [base],
        }),
      ),
    ).toMatchObject({ field: "policy.taskGrants.mode" });
  });

  it("is an unknown field before piship/v1alpha5", () => {
    const v1alpha3 = withGrants(
      MANAGED,
      { mode: "session" },
      "piship/v1alpha3",
    );
    for (const key of ["updates", "release"]) delete v1alpha3[key];
    expect(fieldError(v1alpha3)).toMatchObject({
      field: "policy.taskGrants",
      message: expect.stringContaining("Unknown field"),
    });
  });
});
