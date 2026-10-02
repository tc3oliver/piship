import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { LATEST_SCHEMA, readManifest } from "@piship/schema";
import {
  checkGovernance,
  checkPiVersion,
  distributionStateDirectory,
  initDistribution,
  lockManifest,
  requireCurrentLock,
  resolveLock,
  runtimeStateDirectory,
} from "./index.js";
const roots: string[] = [];
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "piship-core-"));
  roots.push(dir);
  mkdirSync(join(dir, "resources"));
  writeFileSync(join(dir, "resources", "AGENTS.md"), "first\n");
  const path = join(dir, "piship.yaml");
  writeFileSync(
    path,
    'schema: piship/v1alpha1\napp:\n  id: mypi\n  name: My Pi\n  command: mypi\n  version: 0.1.0\nruntime:\n  pi: "1.0.0"\ndeployment:\n  mode: personal\nresources:\n  instructions:\n    - ./resources/AGENTS.md\n',
  );
  return { dir, path };
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
}, 180000);
describe("distribution core", () => {
  it("keeps state separate by id", () => {
    const home = join(tmpdir(), "state");
    expect(runtimeStateDirectory({ value: "a" }, home)).not.toBe(
      runtimeStateDirectory({ value: "b" }, home),
    );
    expect(distributionStateDirectory({ value: "my-agent" })).toBe(
      ".piship/my-agent",
    );
    expect(() => distributionStateDirectory({ value: "../outside" })).toThrow();
  });
  it("writes a byte-stable lock and detects resource drift", () => {
    const { dir, path } = fixture();
    const lockPath = lockManifest(path);
    const first = readFileSync(lockPath, "utf8");
    lockManifest(path);
    expect(readFileSync(lockPath, "utf8")).toBe(first);
    const lock = requireCurrentLock(path);
    expect(lock.runtime.version).toBe("1.0.0");
    expect(lock.resources[0]?.path).toBe("resources/AGENTS.md");
    expect(first).not.toMatch(/apiKey|password|secret/i);
    writeFileSync(join(dir, "resources", "AGENTS.md"), "changed\n");
    expect(() => requireCurrentLock(path)).toThrow("stale");
    expect(resolveLock(path).resources[0]?.sha256).not.toBe(
      lock.resources[0]?.sha256,
    );
  });
  it("requires a current lock before building", () => {
    const { path } = fixture();
    expect(() => requireCurrentLock(path)).toThrow("Lockfile missing");
    lockManifest(path);
    expect(requireCurrentLock(path).app.id).toBe("mypi");
  });
  it("rejects resource roots and nested symlinks during locking", () => {
    const { dir, path } = fixture();
    writeFileSync(
      path,
      `${readFileSync(path, "utf8")}  skills:\n    - ./resources\n`,
    );
    const external = join(dir, "outside.md");
    writeFileSync(external, "outside\n");
    const nested = join(dir, "resources", "linked.md");
    try {
      symlinkSync(external, nested);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    expect(() => resolveLock(path)).toThrow(
      "Resource symlinks are not allowed",
    );
    rmSync(nested);
    rmSync(join(dir, "resources", "AGENTS.md"));
    symlinkSync(external, join(dir, "resources", "AGENTS.md"));
    expect(() => resolveLock(path)).toThrow(
      "Resource symlinks are not allowed",
    );
    const other = fixture();
    const externalRoot = join(other.dir, "elsewhere");
    mkdirSync(externalRoot);
    writeFileSync(join(externalRoot, "AGENTS.md"), "outside\n");
    rmSync(join(other.dir, "resources"), { recursive: true });
    try {
      symlinkSync(externalRoot, join(other.dir, "resources"), "dir");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    expect(() => resolveLock(other.path)).toThrow(
      "Resource symlinks are not allowed",
    );
  });
});

describe("sandbox adapter locking", () => {
  it("locks a custom sandbox adapter module like other adapters", () => {
    const dir = mkdtempSync(join(tmpdir(), "piship-core-"));
    roots.push(dir);
    mkdirSync(join(dir, "sandbox"));
    writeFileSync(
      join(dir, "sandbox", "acme.mjs"),
      "export default () => ({});\n",
    );
    const path = join(dir, "piship.yaml");
    writeFileSync(
      path,
      'schema: piship/v1alpha3\napp:\n  id: mypi\n  name: My Pi\n  command: mypi\n  version: 0.1.0\nruntime:\n  pi: "1.0.0"\ndeployment:\n  mode: personal\nsandbox:\n  required: true\n  provider: custom\n  adapter: ./sandbox/acme.mjs\n',
    );
    const locked = resolveLock(path).resources.find(
      (item) => item.kind === "adapters",
    );
    expect(locked?.path).toBe("sandbox/acme.mjs");
    writeFileSync(join(dir, "sandbox", "acme.mjs"), "export default 1;\n");
    expect(
      resolveLock(path).resources.find((item) => item.kind === "adapters")
        ?.sha256,
    ).not.toBe(locked?.sha256);
  });
});

describe("init", () => {
  it.each([
    ["personal", false],
    ["managed", true],
  ] as const)(
    "writes a %s manifest on the latest schema that validates and locks",
    (mode, managed) => {
      const root = mkdtempSync(join(tmpdir(), "piship-init-"));
      roots.push(root);
      const path = initDistribution(join(root, `${mode}-agent`), { managed });
      const manifest = readManifest(path);
      expect(manifest.schema).toBe(LATEST_SCHEMA);
      expect(manifest.deployment.mode).toBe(mode);
      checkPiVersion(manifest);
      expect(() => checkGovernance(manifest, path)).not.toThrow();
      expect(manifest.governance).toBeDefined();
      expect(manifest.governance?.sandbox.required).toBe(false);
      const projectTrust = manifest.governance?.policy.projectTrust;
      for (const origin of ["external", "unknown"] as const)
        expect(projectTrust?.[origin].dimensions).toEqual({
          passiveContext: "deny",
          instructions: "deny",
          skills: "deny",
          agents: "deny",
          hooks: "deny",
          extensions: "deny",
          mcp: "deny",
          providers: "deny",
        });
      expect(manifest.lifecycle?.updates).toMatchObject({
        channel: "stable",
        channels: ["stable"],
        rollback: true,
        trust: { keys: [] },
      });
      expect(manifest.lifecycle?.updates.source).toBeUndefined();
      if (managed) {
        expect(manifest.access?.identity.mode).toBe("oidc");
        expect(manifest.governance?.policy.default).toBe("ask");
        expect(manifest.governance?.mcp.mode).toBe("allowlist");
        expect(manifest.governance?.mcp.servers).toEqual([]);
        expect(manifest.governance?.audit.enabled).toBe(true);
        expect(manifest.governance?.resources.declared).toMatchObject([
          { kind: "instructions", class: "company" },
        ]);
      } else {
        expect(manifest.access?.identity.mode).toBe("none");
        expect(manifest.access?.credential.provider).toBe("pi-native");
        expect(manifest.access?.inference.provider).toBe("pi-native");
        expect(manifest.governance?.policy.default).toBe("allow");
        expect(manifest.governance?.mcp.mode).toBe("off");
        expect(manifest.governance?.audit.enabled).toBe(false);
        expect(manifest.governance?.resources.declared).toMatchObject([
          { kind: "instructions", class: "user" },
        ]);
      }
      lockManifest(path);
      const lock = requireCurrentLock(path);
      expect(lock.schema).toBe("piship-lock/v1alpha4");
      expect(lock.manifest.schema).toBe(LATEST_SCHEMA);
      expect(lock.updates?.trust.keys).toEqual([]);
    },
    180000,
  );
});

describe("managed init", () => {
  it("creates a valid managed profile even when the id resembles secret words", () => {
    for (const id of ["acme-agent", "token-agent"]) {
      const root = mkdtempSync(join(tmpdir(), "piship-init-managed-"));
      roots.push(root);
      const manifest = readManifest(
        initDistribution(join(root, id), { managed: true }),
      );
      expect(manifest.deployment.mode).toBe("managed");
      expect(manifest.access?.identity.mode).toBe("oidc");
      expect(
        manifest.access?.variables.every((name) => !/TOKEN/.test(name)),
      ).toBe(true);
    }
  });
});
