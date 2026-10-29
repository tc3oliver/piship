import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PISHIP_VERSION } from "@piship/core";
import { afterAll, describe, expect, it } from "vitest";
import { lifecycleReleases, lifecycleScenario } from "../helpers/lifecycle.js";

const bin = fileURLToPath(
  new URL("../../packages/cli/dist/bin.js", import.meta.url),
);
const out = mkdtempSync(join(tmpdir(), "piship-runtime-e2e-"));
afterAll(() => rmSync(out, { recursive: true, force: true }));

// The test runner points the build input at the repository; the built CLI uses its own.
const env = { ...process.env };
delete env.PISHIP_BUILD_INPUT;
const cli = (...args: string[]) =>
  spawnSync(process.execPath, [bin, ...args], { encoding: "utf8", env });

// The runtime release is built for real (npm, bundler, scans, search tools),
// then checked by the consumer verifier and run through its own piship.mjs.
describe("runtime release", () => {
  it("builds on this host, verifies, and runs its own CLI", () => {
    const built = cli("runtime-release", "--out", out);
    expect(built.status, built.stderr).toBe(0);
    const target = `${process.platform}-${process.arch}`;
    const directory = join(
      out,
      "releases",
      `piship-runtime-${PISHIP_VERSION}-${target}`,
    );
    const verified = cli("verify-release", `${directory}.tar.gz`, "--json");
    expect(verified.status, verified.stderr).toBe(0);
    expect(JSON.parse(verified.stdout)).toMatchObject({
      schema: "piship-runtime/v1",
      pishipVersion: PISHIP_VERSION,
      target,
      qualification: "qualified",
      searchTools: { fd: expect.any(String), rg: expect.any(String) },
    });
    const own = spawnSync(
      process.execPath,
      [join(directory, "payload", "piship.mjs"), "verify-release", directory],
      { encoding: "utf8", env },
    );
    expect(own.status, own.stderr).toBe(0);
  }, 900000);

  it("leaves a distribution release verifying through the same command", async () => {
    const s = await lifecycleScenario("runtime-release");
    const verified = s.cli("verify-release", (await lifecycleReleases()).first);
    expect(verified.status, verified.stderr).toBe(0);
    expect(verified.stdout).toContain("Verified");
  }, 900000);
});
