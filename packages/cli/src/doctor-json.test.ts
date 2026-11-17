import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// The payload check is covered elsewhere; here only the launch fails.
vi.mock("@piship/core", async (original) => ({
  ...(await original<typeof import("@piship/core")>()),
  verifyPayload: vi.fn(() => ({})),
}));

import { runCli } from "./index.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe("doctor --json", () => {
  it("prints the unhealthy JSON report when the Pi launch fails, and still fails", async () => {
    const artifact = mkdtempSync(join(tmpdir(), "piship-doctor-json-"));
    dirs.push(artifact);
    const app = { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" };
    writeFileSync(join(artifact, "piship.lock"), JSON.stringify({ app }));
    mkdirSync(join(artifact, "bin"));
    const command = join(artifact, "bin", "mypi");
    writeFileSync(
      command,
      '#!/usr/bin/env node\nprocess.stderr.write("Notice: fd not found on PATH and not bundled\\nno model reachable\\n");\nprocess.exit(3);\n',
    );
    chmodSync(command, 0o755);
    const out: string[] = [];
    const err: string[] = [];
    const status = await runCli(["doctor", artifact, "--json"], {
      stdout: (message) => out.push(message),
      stderr: (message) => err.push(message),
    });
    expect(status).toBe(1);
    const report = JSON.parse(out.join("\n"));
    expect(report).toMatchObject({
      distribution: { id: "mypi", version: "1.0.0" },
      healthy: false,
    });
    // The start notice is left out, so the real error leads.
    expect(report.error).toBe("Pi launch failed: no model reachable");
    expect(err.join("\n")).toContain("Pi launch failed");
  });
});
