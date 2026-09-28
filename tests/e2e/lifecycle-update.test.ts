import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lifecycleScenario } from "../helpers/lifecycle.js";

// Lifecycle scenario: a signed update keeps the session, and replaying older
// signed channel metadata after a newer sequence was seen is refused.
// Uninstalling both retained releases keeps sessions and settings.
describe("production lifecycle: signed update (local fixtures)", () => {
  it("updates through a signed channel, keeps the session, refuses a replayed channel, and uninstalls keeping state", async () => {
    const s = await lifecycleScenario("update");
    await s.installFirst();
    const login = await s.run(["login"]);
    expect(login.status, login.stderr).toBe(0);
    const session = await s.run(["--smoke"]);
    expect(session.status, session.stderr).toBe(0);
    const sessionId = JSON.parse(session.stdout).sessionId;
    s.services.knobs.gatewayMode = "text";
    const model = await s.run(["--smoke-model"]);
    expect(model.status, model.stderr).toBe(0);

    s.publish(1);
    const metadata = join(s.channelDir, "stable.json");
    const signature = `${metadata}.sig`;
    const older = [readFileSync(metadata), readFileSync(signature)] as const;
    const updated = await s.run(["update"]);
    expect(updated.status, updated.stderr).toBe(0);
    expect(updated.stdout).toContain("Updated AcmeCode 1.0.0 -> 1.1.0");
    expect((await s.run(["version"])).stdout).toContain("AcmeCode 1.1.0");
    const resumed = await s.run(["--smoke"]);
    expect(resumed.status, resumed.stderr).toBe(0);
    expect(JSON.parse(resumed.stdout)).toMatchObject({
      sessionId,
      resumed: true,
    });
    const doctor = await s.run(["doctor"]);
    expect(doctor.stdout).toContain("Supply Chain");
    expect(doctor.stdout).toMatch(/release\s+verified/);
    expect(doctor.stdout).toMatch(/rollback\s+1\.0\.0 retained/);

    // After a newer sequence is seen, replaying older signed metadata is refused.
    s.publish(2);
    const newer = await s.run(["update", "--check"]);
    expect(newer.status, newer.stderr).toBe(0);
    writeFileSync(metadata, older[0]);
    writeFileSync(signature, older[1]);
    const replayed = await s.run(["update", "--check"]);
    expect(replayed.status).toBe(1);
    expect(replayed.stderr).toContain("refusing a replayed channel");
    expect((await s.run(["version"])).stdout).toContain("AcmeCode 1.1.0");

    const uninstall = s.cli("uninstall", "acmecode");
    expect(uninstall.status, uninstall.stderr).toBe(0);
    expect(existsSync(s.command)).toBe(false);
    expect(existsSync(join(s.install, "apps", "acmecode"))).toBe(false);
    // Uninstall keeps sessions and settings for a later reinstall.
    expect(
      readdirSync(join(s.state, "acmecode", "sessions")).length,
    ).toBeGreaterThan(0);
    expect(existsSync(join(s.state, "acmecode", "state.json"))).toBe(true);
  }, 900000);
});
