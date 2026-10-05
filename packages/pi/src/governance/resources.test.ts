// Certified Pi packages at launch: the package's review evidence must match
// what the lock pins, and the package loads only on the Pi versions and
// platforms it was reviewed for, as a certified declared resource does.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ManagedFetch } from "@piship/contracts";
import { resolveLock } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { GovernanceSession } from "../governance-session.js";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const SKILL = "---\nname: cite\ndescription: Cite sources.\n---\nCite.\n";
const TREE = `sha256-${"a".repeat(64)}`;
const OTHER_PLATFORM = process.platform === "win32" ? "linux" : "win32";

async function open(evidence: {
  readonly integrity?: string;
  readonly pi?: readonly string[];
  readonly platforms?: readonly string[];
}) {
  const root = mkdtempSync(join(tmpdir(), "piship-package-certified-"));
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const skill = join(
    distribution,
    "pi-packages",
    "cite",
    "package",
    "skills",
    "cite",
    "SKILL.md",
  );
  mkdirSync(dirname(skill), { recursive: true });
  mkdirSync(workspace, { recursive: true });
  writeFileSync(skill, SKILL);
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      'runtime: { pi: "1.0.3" }',
      "deployment: { mode: personal }",
      "policy:",
      "  id: unit",
      "  version: 1",
      "  default: allow",
      "",
    ].join("\n"),
  );
  const resolved = resolveLock(manifest);
  // The lock and governance manifest a v1alpha6 lock would carry for one
  // vendored certified package.
  const lock = {
    ...resolved,
    packages: [
      {
        id: "cite",
        source: "local",
        class: "certified",
        tree: TREE,
        files: 1,
        resources: [
          {
            kind: "skills",
            path: "skills/cite/SKILL.md",
            sha256: createHash("sha256").update(SKILL).digest("hex"),
          },
        ],
      },
    ],
    governance: {
      ...resolved.governance,
      manifest: {
        ...resolved.governance?.manifest,
        resources: {
          ...resolved.governance?.manifest.resources,
          packages: [
            {
              id: "cite",
              source: "local",
              path: "./packages/cite",
              class: "certified",
              filters: {},
              certified: {
                id: "cite",
                version: "1.0.0",
                source: "https://example.org/cite",
                integrity: evidence.integrity ?? TREE,
                license: "MIT",
                pi: evidence.pi ?? ["1.0.3"],
                platforms: evidence.platforms ?? [],
              },
            },
          ],
        },
      },
    },
  };
  const session = await GovernanceSession.open({
    lock: lock as unknown as Parameters<
      typeof GovernanceSession.open
    >[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd: workspace,
    piVersion: "1.0.3",
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: join(root, "home"),
  });
  sessions.push(session);
  return session.resources.find((item) => item.path.startsWith("packages/"));
}

describe("certified Pi packages at launch", () => {
  it("load when the evidence matches the lock, the running Pi, and the platform", async () => {
    expect(
      await open({ platforms: [process.platform, OTHER_PLATFORM] }),
    ).toMatchObject({ loaded: true, integrity: "verified" });
  });

  it("are not loaded on a Pi version the evidence does not name", async () => {
    const record = await open({ pi: ["9.9.9"] });
    expect(record).toMatchObject({ loaded: false });
    expect(record?.reason).toMatch(
      /certified for Pi 9\.9\.9; running Pi 1\.0\.3/,
    );
  });

  it("are not loaded on a platform the evidence does not name", async () => {
    const record = await open({ platforms: [OTHER_PLATFORM] });
    expect(record).toMatchObject({ loaded: false });
    expect(record?.reason).toMatch(new RegExp(`on ${OTHER_PLATFORM}`));
  });

  it("fail the launch when the evidence does not match the locked tree", async () => {
    await expect(
      open({ integrity: `sha256-${"b".repeat(64)}` }),
    ).rejects.toMatchObject({ code: "INTEGRITY_FAILED" });
  });
});
