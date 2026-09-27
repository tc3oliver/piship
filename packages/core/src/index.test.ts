import { createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildDistribution,
  distributionStateDirectory,
  lockManifest,
  requireCurrentLock,
  resolveLock,
  runtimeStateDirectory,
  verifyPayload,
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
    'schema: piship/v1alpha1\napp:\n  id: mypi\n  name: My Pi\n  command: mypi\n  version: 0.1.0\nruntime:\n  pi: "0.87.1"\ndeployment:\n  mode: personal\nresources:\n  instructions:\n    - ./resources/AGENTS.md\n',
  );
  return { dir, path };
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
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
    expect(lock.runtime.version).toBe("0.87.1");
    expect(lock.resources[0]?.path).toBe("resources/AGENTS.md");
    expect(first).not.toMatch(/apiKey|password|secret/i);
    writeFileSync(join(dir, "resources", "AGENTS.md"), "changed\n");
    expect(() => requireCurrentLock(path)).toThrow("stale");
    expect(resolveLock(path).resources[0]?.sha256).not.toBe(
      lock.resources[0]?.sha256,
    );
  });
  it("builds a branded output only for a current lock", () => {
    const { dir, path } = fixture();
    expect(() => buildDistribution(path, join(dir, "out"))).toThrow(
      "Lockfile missing",
    );
    lockManifest(path);
    const output = buildDistribution(path, join(dir, "out"));
    expect(
      readFileSync(join(output, "resources/resources/AGENTS.md"), "utf8"),
    ).toBe("first\n");
    expect(readFileSync(join(output, "bin/mypi"), "utf8")).toContain(
      "launchPiDistribution",
    );
    expect(readFileSync(join(output, "bin/mypi.cmd"), "utf8")).toContain(
      "node",
    );
    if (process.platform !== "win32")
      expect(statSync(join(output, "bin/mypi")).mode & 0o111).not.toBe(0);
    expect(verifyPayload(output).app.id).toBe("mypi");
    const targetPath = join(output, "metadata", "target.json");
    writeFileSync(
      targetPath,
      JSON.stringify({ platform: "unsupported", arch: "unknown" }),
    );
    const inventoryPath = join(output, "metadata", "inventory.json");
    const inventory = JSON.parse(readFileSync(inventoryPath, "utf8")) as Record<
      string,
      string
    >;
    inventory["metadata/target.json"] = createHash("sha256")
      .update(readFileSync(targetPath))
      .digest("hex");
    writeFileSync(inventoryPath, `${JSON.stringify(inventory, null, 2)}\n`);
    expect(() => verifyPayload(output)).toThrow("does not match this machine");
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
