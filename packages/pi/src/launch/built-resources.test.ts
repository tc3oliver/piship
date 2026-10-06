// What a launch checks of the resources it loads: always that each is still a
// regular file the lock lists; their contents only when the lock asks for
// launch verification.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyBuiltResources } from "./runtime.js";

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
      resources,
      ...(verifyAtLaunch === undefined ? {} : { verifyAtLaunch }),
    },
  } as unknown as Parameters<typeof verifyBuiltResources>[0];
  return { dir, ctx };
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
    expect(() => verifyBuiltResources(ctx)).toThrow();
    const linked = distribution(setting);
    rmSync(join(linked.dir, "resources", "AGENTS.md"));
    mkdirSync(join(linked.dir, "resources", "AGENTS.md"));
    expect(() => verifyBuiltResources(linked.ctx)).toThrow(
      /not a regular file: AGENTS\.md/,
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
      /Built resource integrity mismatch: skills\/a\.md/,
    );
  });
});
