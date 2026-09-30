// The generated launcher, run by Node against stand-in @piship/core and
// @piship/pi packages and the real @piship/contracts: whatever ends the
// launch, the error is printed through the shared redaction.
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { launcherSource } from "./launcher-source.js";

const CONTRACTS = fileURLToPath(new URL("../../contracts", import.meta.url));
// An obvious fake in a bearer shape the redaction knows.
const SECRET = "Bearer piship-fake-launcher-secret-0123456789";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-launcher-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function stub(name: string, source: string): void {
  const directory = join(temp, "node_modules", "@piship", name);
  write(
    join(directory, "package.json"),
    JSON.stringify({
      name: `@piship/${name}`,
      type: "module",
      main: "index.js",
    }),
  );
  write(join(directory, "index.js"), source);
}

/** Run the launcher with `launch` as the body of launchPiDistribution. */
function run(launch: string) {
  write(join(temp, "package.json"), JSON.stringify({ type: "module" }));
  write(join(temp, "bin", "acmepi"), launcherSource());
  stub("core", "export function verifyPayload() { return {}; }\n");
  stub("pi", `export async function launchPiDistribution() {\n${launch}\n}\n`);
  symlinkSync(
    CONTRACTS,
    join(temp, "node_modules", "@piship", "contracts"),
    process.platform === "win32" ? "junction" : "dir",
  );
  return spawnSync(process.execPath, [join(temp, "bin", "acmepi")], {
    encoding: "utf8",
    timeout: 30_000,
  });
}

describe("the generated launcher", () => {
  it("redacts an error the launch throws", () => {
    const result = run(`throw new Error("launch failed: ${SECRET}");`);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("launch failed");
    expect(result.stderr).not.toContain(SECRET);
  });

  it("redacts a rejection no one handles, and exits with status 1", () => {
    const result = run(
      `Promise.reject(new Error("background failure: ${SECRET}"));\nawait new Promise((done) => setTimeout(done, 200));`,
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("background failure");
    expect(result.stderr).not.toContain(SECRET);
    // One redacted message, not Node's stack trace.
    expect(result.stderr).not.toContain("    at ");
  });

  it("redacts an exception thrown from a callback", () => {
    const result = run(
      `setTimeout(() => { throw new Error("callback failure: ${SECRET}"); }, 10);\nawait new Promise((done) => setTimeout(done, 200));`,
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("callback failure");
    expect(result.stderr).not.toContain(SECRET);
    expect(result.stderr).not.toContain("    at ");
  });
});
