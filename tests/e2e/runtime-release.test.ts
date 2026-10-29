import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { SEARCH_TOOLS } from "@piship/schema";
import { PI_VERSION, PISHIP_VERSION, SEARCH_TOOL_SPECS } from "@piship/core";
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
      searchTools: Object.fromEntries(
        SEARCH_TOOLS.map((tool) => [
          tool,
          SEARCH_TOOL_SPECS[tool].defaultVersion,
        ]),
      ),
    });
    const folder = cli("verify-release", directory, "--json");
    expect(folder.status, folder.stderr).toBe(0);
    expect(JSON.parse(folder.stdout)).toEqual(JSON.parse(verified.stdout));
    const { pi } = JSON.parse(
      readFileSync(join(directory, "runtime.json"), "utf8"),
    );
    expect(pi.version).toBe(PI_VERSION);
    const exe = process.platform === "win32" ? ".exe" : "";
    for (const tool of ["fd", "rg"])
      expect(
        existsSync(join(directory, "payload", "tools", `${tool}${exe}`)),
      ).toBe(true);
    const own = spawnSync(
      process.execPath,
      [join(directory, "payload", "piship.mjs"), "verify-release", directory],
      { encoding: "utf8", env },
    );
    expect(own.status, own.stderr).toBe(0);
  }, 900000);

  it("binds a pack of the personal example to the built runtime", async () => {
    const target = `${process.platform}-${process.arch}`;
    const archive = join(
      out,
      "releases",
      `piship-runtime-${PISHIP_VERSION}-${target}.tar.gz`,
    );
    const manifest = fileURLToPath(
      new URL("../../examples/personal/piship.yaml", import.meta.url),
    );
    const packed = cli("pack", manifest, "--runtime", archive, "--out", out);
    expect(packed.status, packed.stderr).toBe(0);
    const runtime = JSON.parse(cli("verify-release", archive, "--json").stdout);
    const bound = JSON.parse(
      readFileSync(join(out, "packs", "mypi-1.0.0-pack", "pack.json"), "utf8"),
    );
    expect(bound.targets).toEqual([target]);
    expect(bound.runtime.archives[target]).toMatchObject({
      sha256: readFileSync(`${archive}.sha256`, "utf8").split(/\s+/)[0],
      inventorySha256: runtime.inventory.sha256,
    });
    expect(runtime.searchTools).toEqual(
      Object.fromEntries(
        SEARCH_TOOLS.map((tool) => [
          tool,
          SEARCH_TOOL_SPECS[tool].defaultVersion,
        ]),
      ),
    );
    expect(Object.keys(bound.excluded)).not.toContain(target);
  }, 900000);

  it("leaves a distribution release verifying through the same command", async () => {
    const s = await lifecycleScenario("runtime-release");
    const verified = s.cli("verify-release", (await lifecycleReleases()).first);
    expect(verified.status, verified.stderr).toBe(0);
    const { distribution } = JSON.parse(
      s.cli("verify-release", (await lifecycleReleases()).first, "--json")
        .stdout,
    );
    expect(distribution.id).toBe("acmecode");
    expect(verified.stdout).toContain(`Verified ${distribution.name}`);
  }, 900000);
});
