// The store is a cache an install and an update may use and `doctor` may
// maintain. A launch never opens it, and a release never refers to it.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));

function sources(directory: string): string[] {
  return readdirSync(join(root, directory), { withFileTypes: true }).flatMap(
    (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return sources(path);
      return entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")
        ? [path]
        : [];
    },
  );
}

const STORE =
  /\bPISHIP_STORE|from "[./]*(?:\.\.\/)*(?:\.\/)?store\/|ContentStore|openInstallStore|maintainRuntimeStore|collectStore|verifyStore/;

function mentions(files: string[]): string[] {
  return files.filter((file) =>
    STORE.test(readFileSync(join(root, file), "utf8")),
  );
}

describe("where the file store is used", () => {
  it("is not used by a launch", () => {
    const launch = [
      ...sources("packages/pi/src/launch"),
      ...sources("packages/core/src/branded").filter(
        (file) => !file.endsWith("lifecycle.ts"),
      ),
      "packages/core/src/install/launcher.ts",
      "packages/core/src/install/launcher-source.ts",
      "packages/core/src/launcher-source.ts",
      "packages/core/src/install/runtime-lease.ts",
    ].filter((file) => {
      try {
        readFileSync(join(root, file));
        return true;
      } catch {
        return false;
      }
    });
    expect(launch.length).toBeGreaterThan(5);
    expect(mentions(launch).map((file) => relative(".", file))).toEqual([]);
  });

  it("is not used to build, bundle, or archive a release", () => {
    const authoring = [
      "packages/core/src/build.ts",
      "packages/core/src/bundle.ts",
      "packages/core/src/payload.ts",
      "packages/core/src/archive.ts",
      ...sources("packages/core/src/release").filter(
        (file) => !file.endsWith("verify.ts"),
      ),
    ];
    expect(mentions(authoring)).toEqual([]);
  });

  it("is used by install, update, and doctor, and nowhere else outside its own module", () => {
    const users = mentions([
      ...sources("packages/core/src"),
      ...sources("packages/pi/src"),
      ...sources("packages/cli/src"),
    ]).filter(
      (file) =>
        !file.startsWith(join("packages", "core", "src", "store")) &&
        !file.endsWith(join("install", "store.ts")),
    );
    expect(users.sort()).toEqual(
      [
        "packages/core/src/index.ts",
        "packages/core/src/install/install.ts",
        "packages/core/src/install/index.ts",
        "packages/core/src/release/verify.ts",
        "packages/core/src/update/update.ts",
        "packages/pi/src/commands/doctor.ts",
      ].sort(),
    );
  });
});
