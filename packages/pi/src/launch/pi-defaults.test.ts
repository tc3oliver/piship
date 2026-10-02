import { SettingsManager } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { applyPiEnvironment, PI_SETTINGS } from "./pi-defaults.js";

describe("Pi defaults", () => {
  it("turns off the version check and telemetry and keeps Pi's agent directory in state", () => {
    const env: NodeJS.ProcessEnv = {};
    applyPiEnvironment("/state/agent", "personal", env);
    expect(env).toEqual({
      PI_SKIP_VERSION_CHECK: "1",
      PI_TELEMETRY: "0",
      PI_CODING_AGENT_DIR: "/state/agent",
    });
  });

  it("takes a managed launch offline", () => {
    const env: NodeJS.ProcessEnv = { PI_OFFLINE: undefined };
    applyPiEnvironment("/state/agent", "managed", env);
    expect(env.PI_OFFLINE).toBe("1");
  });

  it("are read back by Pi's in-memory settings", () => {
    const settings = SettingsManager.inMemory({ ...PI_SETTINGS });
    expect(settings.getEnableInstallTelemetry()).toBe(false);
    expect(settings.getLastChangelogVersion()).toBe(
      PI_SETTINGS.lastChangelogVersion,
    );
    expect(settings.getQuietStartup()).toBe(true);
    expect(settings.getTuiMode()).toBe("regular");
  });
});
