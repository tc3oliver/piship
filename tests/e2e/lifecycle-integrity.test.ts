import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lifecycleScenario, target } from "../helpers/lifecycle.js";

// Lifecycle scenario: a signed update is offered, and a tampered archive or
// metadata changed after signing is refused without changing the install.
describe("production lifecycle: update integrity (local fixtures)", () => {
  it("reports a signed update and rejects a tampered archive and forged metadata", async () => {
    const s = await lifecycleScenario("integrity");
    await s.installFirst();

    // Publish 1.1.0 on the signed stable channel.
    s.publish(1);
    const check = await s.run(["update", "--check"]);
    expect(check.status, check.stderr).toBe(0);
    expect(check.stdout).toContain("AcmeCode 1.1.0 is available");
    expect((await s.run(["version"])).stdout).toContain("AcmeCode 1.0.0");

    // A tampered archive with intact metadata is refused and changes nothing.
    const archive = join(s.channelDir, `acmecode-1.1.0-${target}.tar.gz`);
    const good = readFileSync(archive);
    const bad = Buffer.from(good);
    bad[bad.length - 100] = (bad[bad.length - 100] ?? 0) ^ 0xff;
    writeFileSync(archive, bad);
    const tampered = await s.run(["update"]);
    expect(tampered.status).toBe(1);
    expect(tampered.stderr).toContain("INTEGRITY_FAILED");
    expect((await s.run(["version"])).stdout).toContain("AcmeCode 1.0.0");
    writeFileSync(archive, good);

    // Metadata changed after signing is refused as well.
    const metadata = join(s.channelDir, "stable.json");
    const signedMetadata = readFileSync(metadata, "utf8");
    writeFileSync(
      metadata,
      signedMetadata.replace('"sequence": 1', '"sequence": 9'),
    );
    const forged = await s.run(["update"]);
    expect(forged.status).toBe(1);
    expect(forged.stderr).toContain("INTEGRITY_FAILED");
    expect((await s.run(["version"])).stdout).toContain("AcmeCode 1.0.0");
  }, 900000);
});
