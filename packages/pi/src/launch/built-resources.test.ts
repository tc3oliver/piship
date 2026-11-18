// What a launch checks of the resources it loads: always that each is still a
// regular file the lock lists; their contents only when the lock asks for
// launch verification.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { formatError } from "@piship/contracts";
import {
  extensionLabel,
  extensionLoadErrors,
  resourceLoadAction,
  verifyBuiltResources,
} from "./runtime.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const sha = (content: string) =>
  createHash("sha256").update(content).digest("hex");

function distribution(verifyAtLaunch?: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "piship-built-resources-"));
  roots.push(dir);
  mkdirSync(join(dir, "resources", "skills"), { recursive: true });
  writeFileSync(join(dir, "resources", "AGENTS.md"), "# Instructions\n");
  writeFileSync(join(dir, "resources", "skills", "a.md"), "skill a\n");
  const resources = [
    {
      kind: "instructions",
      path: "AGENTS.md",
      sha256: sha("# Instructions\n"),
    },
    { kind: "skills", path: "skills/a.md", sha256: sha("skill a\n") },
  ];
  const ctx = {
    distributionDir: dir,
    metadata: {
      app: { id: "acmepi" },
      resources,
      ...(verifyAtLaunch === undefined ? {} : { verifyAtLaunch }),
    },
  } as unknown as Parameters<typeof verifyBuiltResources>[0];
  return { dir, ctx };
}

function failure(ctx: Parameters<typeof verifyBuiltResources>[0]): string {
  try {
    verifyBuiltResources(ctx);
  } catch (error) {
    return formatError(error);
  }
  throw new Error("expected a failure");
}

describe.each([
  ["unset", undefined],
  ["false", false],
] as const)("verifyAtLaunch %s", (_name, setting) => {
  it("accepts the resources as installed", () => {
    expect(() => verifyBuiltResources(distribution(setting).ctx)).not.toThrow();
  });

  it("does not read their contents: an edited resource still loads", () => {
    const { dir, ctx } = distribution(setting);
    writeFileSync(join(dir, "resources", "AGENTS.md"), "# Edited\n");
    expect(() => verifyBuiltResources(ctx)).not.toThrow();
  });

  it("still refuses a resource that is gone, or no longer a regular file", () => {
    const { dir, ctx } = distribution(setting);
    rmSync(join(dir, "resources", "skills", "a.md"));
    expect(() => verifyBuiltResources(ctx)).toThrow(
      expect.objectContaining({ code: "INTEGRITY_FAILED" }),
    );
    // A damaged install, not a path the user typed: name the install and the repair.
    const text = failure(ctx);
    expect(text).toContain(`skills/a.md in ${dir} is missing`);
    expect(text).toContain("piship repair acmepi");
    expect(text).not.toMatch(/ENOENT|absolute path/);
    const linked = distribution(setting);
    rmSync(join(linked.dir, "resources", "AGENTS.md"));
    mkdirSync(join(linked.dir, "resources", "AGENTS.md"));
    expect(() => verifyBuiltResources(linked.ctx)).toThrow(
      /AGENTS\.md in .* is not a regular file/,
    );
    const outside = distribution(setting);
    const escaping = {
      ...outside.ctx,
      metadata: {
        ...outside.ctx.metadata,
        resources: [
          { kind: "instructions", path: "../escape.md", sha256: sha("") },
        ],
      },
    } as unknown as Parameters<typeof verifyBuiltResources>[0];
    expect(() => verifyBuiltResources(escaping)).toThrow(
      /Unsafe built resource path/,
    );
  });
});

describe("verifyAtLaunch true", () => {
  it("accepts the resources as installed", () => {
    expect(() => verifyBuiltResources(distribution(true).ctx)).not.toThrow();
  });

  it("hashes each resource against the lock and refuses an edited one", () => {
    const { dir, ctx } = distribution(true);
    writeFileSync(join(dir, "resources", "skills", "a.md"), "skill A edited\n");
    expect(() => verifyBuiltResources(ctx)).toThrow(
      expect.objectContaining({ code: "INTEGRITY_FAILED" }),
    );
    const text = failure(ctx);
    expect(text).toContain(`skills/a.md in ${dir} does not match the lock`);
    expect(text).toContain("piship repair acmepi");
  });
});

describe("resourceLoadAction", () => {
  it("sends the author back to the source and a managed user to the administrator", () => {
    expect(resourceLoadAction("personal")).toMatch(/piship build/);
    expect(resourceLoadAction("managed")).toMatch(/administrator/);
    expect(resourceLoadAction("managed")).not.toMatch(/piship build/);
  });
});

describe("extensionLoadErrors", () => {
  it("names the extension whose factory threw, as the author wrote it", () => {
    const dir = join(tmpdir(), "dist");
    const built = join(dir, "resources", "extensions", "hello.ts");
    expect(
      extensionLoadErrors(
        [{ path: built, error: "Failed to load extension: boom from hello" }],
        dir,
      ),
    ).toBe(
      `Failed to load extension "./${join("extensions", "hello.ts")}": Failed to load extension: boom from hello`,
    );
  });

  it("does not repeat a path the error already names", () => {
    const dir = join(tmpdir(), "dist");
    const built = join(dir, "resources", "extensions", "bad.ts");
    expect(
      extensionLoadErrors(
        [
          {
            path: built,
            error: `Failed to load extension: ${built}:2:2: oops`,
          },
        ],
        dir,
      ),
    ).toBe(
      `Failed to load extension: ./${join("extensions", "bad.ts")}:2:2: oops`,
    );
  });
});

describe("package tool conflicts", () => {
  const dir = join(tmpdir(), "dist");
  const npmFile = join(
    dir,
    "pi-packages",
    "lp1",
    "node_modules",
    "@scope",
    "tools",
    "extensions",
    "a.js",
  );
  const gitFile = join(
    dir,
    "pi-packages",
    "lp2",
    "package",
    "extensions",
    "b.js",
  );
  const conflict = [
    { path: gitFile, error: `Tool "dup_tool" conflicts with ${npmFile}` },
  ];

  it("names both packages, not their built copies", () => {
    expect(extensionLoadErrors(conflict, dir)).toBe(
      'Tool "dup_tool" is registered by both package lp1 (extensions/a.js) and package lp2 (extensions/b.js)',
    );
  });

  it("says to exclude one through that package's extensions filter", () => {
    const action = resourceLoadAction("personal", conflict, dir);
    expect(action).toContain('extensions: ["!extensions/b.js"] on package lp2');
    expect(action).toContain("piship lock");
    expect(resourceLoadAction("managed", conflict, dir)).toMatch(
      /administrator/,
    );
  });

  it("names a distribution's own extension by its declared path", () => {
    const own = join(dir, "resources", "extensions", "x.ts");
    expect(extensionLabel(own, dir)).toBe(`./${join("extensions", "x.ts")}`);
    expect(
      resourceLoadAction(
        "personal",
        [{ path: own, error: `Tool "t" conflicts with ${gitFile}` }],
        dir,
      ),
    ).toContain('extensions: ["!extensions/b.js"] on package lp2');
  });

  it("keeps the generic action for a clash between the distribution's own files", () => {
    const a = join(dir, "resources", "extensions", "a.ts");
    const b = join(dir, "resources", "extensions", "b.ts");
    expect(
      resourceLoadAction(
        "personal",
        [{ path: b, error: `Tool "t" conflicts with ${a}` }],
        dir,
      ),
    ).toMatch(/^Fix the source file/);
  });
});
