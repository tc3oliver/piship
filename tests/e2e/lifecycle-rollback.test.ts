import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  lifecycleScenario,
  scanDecoded as scan,
} from "../helpers/lifecycle.js";

// Lifecycle scenario: roll back while signed in. Sessions come back,
// credentials are never restored: revoked ones cannot be used or renewed by
// the rolled-back release, signing in again reacquires them, and no secret
// remains in state or in any retained release after logout.
describe("production lifecycle: rollback and credentials (local fixtures)", () => {
  it("rolls back keeping the session, refuses revoked credentials, reacquires, and leaves no secrets", async () => {
    const s = await lifecycleScenario("rollback");
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
    const updated = await s.run(["update"]);
    expect(updated.status, updated.stderr).toBe(0);
    expect(updated.stdout).toContain("Updated AcmeCode 1.0.0 -> 1.1.0");

    const { state } = s.services;
    const secrets = [
      ...state.credentials.keys(),
      ...state.accessTokens.keys(),
      ...state.refreshTokens.keys(),
    ];
    expect(secrets.length).toBeGreaterThan(2);
    const rollback = await s.run(["rollback"]);
    expect(rollback.status, rollback.stderr).toBe(0);
    expect(rollback.stdout).toContain("Rolled back AcmeCode 1.1.0 -> 1.0.0");
    expect((await s.run(["version"])).stdout).toContain("AcmeCode 1.0.0");
    const afterRollback = await s.run(["--smoke"]);
    expect(afterRollback.status, afterRollback.stderr).toBe(0);
    expect(JSON.parse(afterRollback.stdout)).toMatchObject({
      sessionId,
      resumed: true,
    });

    // The company revokes every credential and token server-side, without a
    // local logout: the rolled-back release cannot use or renew them.
    for (const entry of state.credentials.values()) entry.revoked = true;
    state.accessTokens.clear();
    state.refreshTokens.clear();
    const revoked = await s.run(["--smoke-model"]);
    expect(revoked.status).toBe(1);
    expect(revoked.stderr).toMatch(/IDENTITY_|CREDENTIAL_/);
    expect(revoked.stderr).toMatch(/login/);

    // Signing in again works and still resumes the same session.
    const relogin = await s.run(["login"]);
    expect(relogin.status, relogin.stderr).toBe(0);
    const again = await s.run(["--smoke-model"]);
    expect(again.status, again.stderr).toBe(0);
    const continued = await s.run(["--smoke"]);
    expect(continued.status, continued.stderr).toBe(0);
    expect(JSON.parse(continued.stdout)).toMatchObject({
      sessionId,
      resumed: true,
    });
    secrets.push(
      ...state.credentials.keys(),
      ...state.accessTokens.keys(),
      ...state.refreshTokens.keys(),
    );
    const logout = await s.run(["logout"]);
    expect(logout.status, logout.stderr).toBe(0);
    expect((await s.run(["--smoke"])).stderr).toContain("IDENTITY_REQUIRED");
    expect(scan(s.state, secrets)).toEqual([]);
    expect(scan(s.install, secrets)).toEqual([]);
    // The user's personal Pi configuration is never touched.
    expect(existsSync(join(s.home, ".pi"))).toBe(false);
  }, 900000);
});
