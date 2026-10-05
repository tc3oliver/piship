// A capability provider that is a declared Pi package: the package's
// extensions load only through the provider, after its own decision, and the
// capability is effective only while the package matches the lock.
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ManagedFetch } from "@piship/contracts";
import { PI_VERSION, resolveLock } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { capabilityStates } from "./capabilities.js";
import { GovernanceSession } from "../governance-session.js";

const roots: string[] = [];
const sessions: GovernanceSession[] = [];
afterEach(async () => {
  for (const session of sessions.splice(0)) await session.close();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const EXTENSION = "export default function guard() {}\n";
const SKILL =
  "---\nname: guard-help\ndescription: How the guard works.\n---\nHelp.\n";
const TREE = `sha256-${"a".repeat(64)}`;
const CONTRACT = "piship.capability/permissions/v1";
const sha = (text: string) => createHash("sha256").update(text).digest("hex");

interface Options {
  /** Policy rules, as the manifest's `policy.enforced` lines. */
  readonly rules?: readonly string[];
  /** The extension on disk, when it is not the one the lock pins. */
  readonly onDisk?: string;
  readonly enabled?: boolean;
  readonly secondExtension?: boolean;
  readonly reviewedPi?: string;
  readonly reviewedPlatform?: string;
  readonly managed?: boolean;
}

async function open(options: Options = {}) {
  const root = mkdtempSync(join(tmpdir(), "piship-package-provider-"));
  roots.push(root);
  const distribution = join(root, "distribution");
  const workspace = join(root, "workspace");
  const base = join(distribution, "pi-packages", "guard", "package");
  mkdirSync(join(base, "src"), { recursive: true });
  mkdirSync(join(base, "skills", "guard-help"), { recursive: true });
  mkdirSync(workspace, { recursive: true });
  writeFileSync(join(base, "src", "index.ts"), options.onDisk ?? EXTENSION);
  if (options.secondExtension)
    writeFileSync(join(base, "src", "second.ts"), EXTENSION);
  writeFileSync(join(base, "skills", "guard-help", "SKILL.md"), SKILL);
  const manifest = join(distribution, "piship.yaml");
  writeFileSync(
    manifest,
    [
      "schema: piship/v1alpha3",
      "app: { id: unit, name: Unit, command: unit, version: 0.1.0 }",
      `runtime: { pi: "${PI_VERSION}" }`,
      "deployment: { mode: personal }",
      "policy:",
      "  id: unit",
      "  version: 1",
      "  default: allow",
      ...(options.rules?.length ? ["  enforced:", ...options.rules] : []),
      "",
    ].join("\n"),
  );
  const resolved = resolveLock(manifest);
  const evidence = {
    id: "guard",
    version: "1.0.0",
    source: "https://example.org/guard",
    integrity: TREE,
    license: "MIT",
    pi: [options.reviewedPi ?? PI_VERSION],
    platforms: options.reviewedPlatform ? [options.reviewedPlatform] : [],
  };
  const provider = {
    id: "certified/guard",
    class: "certified",
    version: "1.0.0",
    implements: [CONTRACT],
    package: "guard",
  };
  const governance = resolved.governance as NonNullable<
    typeof resolved.governance
  >;
  const lock = {
    ...resolved,
    deployment: {
      ...resolved.deployment,
      mode: options.managed ? "managed" : "personal",
    },
    packages: [
      {
        id: "guard",
        source: "local",
        class: "certified",
        tree: TREE,
        files: 2,
        resources: [
          { kind: "extensions", path: "src/index.ts", sha256: sha(EXTENSION) },
          ...(options.secondExtension
            ? [
                {
                  kind: "extensions",
                  path: "src/second.ts",
                  sha256: sha(EXTENSION),
                },
              ]
            : []),
          {
            kind: "skills",
            path: "skills/guard-help/SKILL.md",
            sha256: sha(SKILL),
          },
        ],
      },
    ],
    governance: {
      ...governance,
      manifest: {
        ...governance.manifest,
        resources: {
          ...governance.manifest.resources,
          packages: [
            {
              id: "guard",
              source: "local",
              path: "./packages/guard",
              class: "certified",
              filters: {},
              certified: evidence,
            },
          ],
        },
        capabilities: governance.manifest.capabilities.map((item) =>
          item.name === "permissions"
            ? { ...item, enabled: options.enabled ?? true, provider }
            : item,
        ),
      },
      providers: [
        {
          capability: "permissions",
          ...provider,
          certified: evidence,
        },
      ],
    },
  };
  const session = await GovernanceSession.open({
    lock: lock as unknown as Parameters<
      typeof GovernanceSession.open
    >[0]["lock"],
    distributionDir: distribution,
    stateDir: join(root, "state"),
    cwd: workspace,
    piVersion: PI_VERSION,
    interactive: false,
    fetch: (() => {
      throw new Error("no network in unit tests");
    }) as unknown as ManagedFetch,
    resolveTemplate: (_key, template) => template,
    homeDir: join(root, "home"),
  });
  sessions.push(session);
  const permissions = session.capabilities.find(
    (item) => item.name === "permissions",
  );
  return {
    session,
    base,
    extensions: session.loader.extensions.map((path) =>
      path
        .slice(base.length + 1)
        .split("\\")
        .join("/"),
    ),
    permissions,
    extensionRecord: session.resources.find(
      (item) => item.path === "packages/guard/src/index.ts",
    ),
    skills: session.loader.skills.length,
  };
}

describe("a package that is the permissions provider", () => {
  it("refuses all sibling extensions if one is denied", async () => {
    const opened = await open({
      secondExtension: true,
      rules: [
        "    - { id: no-second, action: extension.load, resource: 'certified:packages/guard/src/second.ts', effect: deny }",
      ],
    });
    expect(opened.extensions).toEqual([]);
    expect(opened.extensionRecord?.loaded).toBe(false);
    expect(opened.permissions?.axes.effective.value).toBe("no");
  });

  it("reports lock certification in static capability inspection as launch does", async () => {
    const opened = await open({ reviewedPi: "0.0.1" });
    const inspected = capabilityStates(opened.session.options, false).find(
      (item) => item.name === "permissions",
    );
    expect(inspected?.axes.compatible.value).toBe("no");
    expect(inspected?.axes.compatible.reason).toContain("0.0.1");
    expect(opened.extensions).toEqual([]);
    expect(opened.permissions?.axes.effective.value).toBe("no");
  });

  it("reports platform certification consistently during inspection and launch", async () => {
    const opened = await open({ reviewedPlatform: "other-platform" });
    const inspected = capabilityStates(opened.session.options, false).find(
      (item) => item.name === "permissions",
    );
    expect(inspected?.axes.compatible.value).toBe("no");
    expect(inspected?.axes.compatible.reason).toContain("platform");
    expect(opened.extensions).toEqual([]);
  });

  it("fails closed in managed mode when a provider extension is tampered", async () => {
    await expect(
      open({ managed: true, onDisk: "tampered" }),
    ).rejects.toMatchObject({ code: "INTEGRITY_FAILED" });
  });
  it("loads its extension through the provider, and its other files as a package", async () => {
    const opened = await open();
    expect(opened.permissions?.axes.effective.value).toBe("yes");
    expect(opened.permissions?.provider).toBe("certified/guard");
    expect(opened.extensions).toEqual(["src/index.ts"]);
    expect(opened.extensionRecord).toMatchObject({
      kind: "extensions",
      loaded: true,
      integrity: "verified",
      origin: "guard@local",
    });
    expect(opened.skills).toBe(1);
  });

  it("does not load its extension when the policy denies the provider", async () => {
    const opened = await open({
      rules: [
        "    - { id: no-guard, action: provider.load, resource: certified/guard, effect: deny }",
      ],
    });
    expect(opened.permissions?.axes.effective.value).toBe("no");
    expect(opened.permissions?.axes.enabled.reason).toMatch(/no-guard/);
    expect(opened.extensions).toEqual([]);
    expect(opened.extensionRecord).toBeUndefined();
    // The package's other files are not the provider's: they still load.
    expect(opened.skills).toBe(1);
  });

  it("does not load it when the policy denies its extension file, and says so", async () => {
    const opened = await open({
      rules: [
        "    - { id: no-guard-file, action: extension.load, resource: 'certified:packages/guard/src/**', effect: deny }",
      ],
    });
    expect(opened.permissions?.axes.effective.value).toBe("no");
    expect(opened.extensions).toEqual([]);
  });

  it("is not effective, and loads nothing, when the capability is disabled", async () => {
    const opened = await open({ enabled: false });
    expect(opened.permissions?.axes.effective.value).toBe("no");
    expect(opened.extensions).toEqual([]);
  });

  it("is not effective when the extension on disk differs from the lock", async () => {
    const opened = await open({
      onDisk: "export default function evil() {}\n",
    });
    expect(opened.permissions?.axes.resolved.value).toBe("no");
    expect(opened.permissions?.axes.resolved.reason).toMatch(
      /package files do not match the lock/,
    );
    expect(opened.extensions).toEqual([]);
    const notices: string[] = [];
    opened.session.attachNotices((notice) => notices.push(notice));
    expect(notices).toContainEqual(
      expect.stringContaining("provider package files do not match the lock"),
    );
  });
});
