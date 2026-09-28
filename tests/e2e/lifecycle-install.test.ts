import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lifecycleScenario, target } from "../helpers/lifecycle.js";

// Lifecycle scenario: the consumer verifies the release, installs it with
// the shipped install script, and uses it.
describe("production lifecycle: install (local fixtures)", () => {
  it("verifies and installs a release with the shipped script and launches it", async () => {
    const s = await lifecycleScenario("install");
    // The release wraps exactly the payload `piship build` produces.
    expect(readFileSync(s.releases.releaseInventory)).toEqual(
      readFileSync(s.releases.buildInventory),
    );
    const verified = s.cli("verify-release", s.releases.first, "--json");
    expect(verified.status, verified.stderr).toBe(0);
    expect(JSON.parse(verified.stdout)).toMatchObject({
      distribution: { id: "acmecode", version: "1.0.0" },
      target,
    });

    await s.installFirst();
    const login = await s.run(["login"]);
    expect(login.status, login.stderr).toBe(0);
    const session = await s.run(["--smoke"]);
    expect(session.status, session.stderr).toBe(0);

    // Nothing is published yet: the channel does not exist.
    const empty = await s.run(["update", "--check"]);
    expect(empty.status).toBe(1);
    expect(empty.stderr).toContain("UPDATE_FAILED");

    // The user's personal Pi configuration is never touched.
    expect(existsSync(join(s.home, ".pi"))).toBe(false);
  }, 900000);
});
