import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { afterEach, describe, expect, it } from "vitest";
import { hash } from "../digest.js";
import { copyInstalledRuntime, InstalledRuntimeError } from "./compose.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-installed-runtime-"));
  roots.push(dir);
  return dir;
}
function write(root: string, file: string, content: string): void {
  mkdirSync(dirname(join(root, file)), { recursive: true });
  writeFileSync(join(root, file), content);
}

/** An installed composed payload: two runtime files and what a pack adds. */
function installed(): { dir: string; pinned: string } {
  const dir = temp();
  const runtime = { "a.js": hash("a"), "metadata/target.json": hash("{}") };
  write(dir, "a.js", "a");
  write(dir, "metadata/target.json", "{}");
  write(dir, "piship.yaml", "app: x");
  write(dir, "bin/x", "launcher");
  const pinned = `${JSON.stringify(runtime, null, 2)}\n`;
  write(
    dir,
    "metadata/inventory.json",
    JSON.stringify({
      ...runtime,
      "piship.yaml": hash("app: x"),
      "bin/x": hash("launcher"),
    }),
  );
  return { dir, pinned: hash(pinned) };
}

describe("reusing the installed runtime for a pack", () => {
  it("copies the runtime files and leaves the pack's out", () => {
    const { dir, pinned } = installed();
    const into = temp();
    mkdirSync(join(into, "metadata"), { recursive: true });
    expect(Object.keys(copyInstalledRuntime(dir, into, pinned)).sort()).toEqual(
      ["a.js", "metadata/target.json"],
    );
  });

  // Only these failures make an update fetch the runtime; the error type is
  // how the update tells them from a pack digest mismatch or a failed
  // acceptance run, which must not.
  it("fails as an InstalledRuntimeError for another runtime and for a damaged file", () => {
    const { dir, pinned } = installed();
    const into = temp();
    mkdirSync(join(into, "metadata"), { recursive: true });
    expect(() => copyInstalledRuntime(dir, into, "0".repeat(64))).toThrow(
      InstalledRuntimeError,
    );
    write(dir, "a.js", "tampered");
    expect(() => copyInstalledRuntime(dir, into, pinned)).toThrow(
      /do not match their inventory \(a\.js\)/,
    );
    expect(() => copyInstalledRuntime(dir, into, pinned)).toThrow(
      InstalledRuntimeError,
    );
  });

  it("is a PiShipError that other integrity failures are not an instance of", () => {
    const other = new PiShipError("INTEGRITY_FAILED", "Pack install: x");
    expect(other).not.toBeInstanceOf(InstalledRuntimeError);
    expect(new InstalledRuntimeError("x")).toBeInstanceOf(PiShipError);
  });
});
