import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SettingsManager } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { applyPiEnvironment, PI_SETTINGS } from "./pi-defaults.js";

const posix = process.platform !== "win32";

function withTemp(run: (root: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "piship-jiti-env-"));
  try {
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("Pi defaults", () => {
  it("turns off the version check and telemetry and keeps Pi's agent directory in state", () => {
    const env: NodeJS.ProcessEnv = {};
    applyPiEnvironment("/state/agent", "personal", false, env);
    expect(env).toEqual({
      PI_SKIP_VERSION_CHECK: "1",
      PI_TELEMETRY: "0",
      PI_CODING_AGENT_DIR: "/state/agent",
      JITI_RESPECT_TMPDIR_ENV: "1",
      JITI_FS_CACHE: "false",
    });
  });

  it("keeps jiti's cache in a directory it creates for this user alone", () => {
    withTemp((root) => {
      const cache = join(root, "jiti");
      const env: NodeJS.ProcessEnv = {};
      applyPiEnvironment("/state/agent", "personal", cache, env);
      expect(env.JITI_FS_CACHE).toBeUndefined();
      if (posix) expect(statSync(cache).mode & 0o777).toBe(0o700);
    });
  });

  it.skipIf(!posix)(
    "turns jiti's cache off, whatever the user set, in a directory others can write or a symlink",
    () => {
      withTemp((root) => {
        const open = join(root, "open");
        mkdirSync(open);
        chmodSync(open, 0o775);
        const env: NodeJS.ProcessEnv = { JITI_FS_CACHE: "true" };
        applyPiEnvironment("/state/agent", "managed", open, env);
        expect(env.JITI_FS_CACHE).toBe("false");

        const linked = join(root, "linked");
        mkdirSync(join(root, "target"), { mode: 0o700 });
        symlinkSync(join(root, "target"), linked);
        const linkedEnv: NodeJS.ProcessEnv = {};
        applyPiEnvironment("/state/agent", "personal", linked, linkedEnv);
        expect(linkedEnv.JITI_FS_CACHE).toBe("false");

        const shared = join(root, "shared");
        mkdirSync(shared);
        chmodSync(shared, 0o777);
        const nested: NodeJS.ProcessEnv = {};
        applyPiEnvironment(
          "/state/agent",
          "personal",
          join(shared, "jiti"),
          nested,
        );
        expect(nested.JITI_FS_CACHE).toBe("false");
      });
    },
  );

  it("takes a managed launch offline", () => {
    const env: NodeJS.ProcessEnv = {
      PI_OFFLINE: undefined,
      CLAUDE_CONFIG_DIR: ".claude",
    };
    applyPiEnvironment("/state/agent", "managed", false, env);
    expect(env.PI_OFFLINE).toBe("1");
    expect(env.CLAUDE_CONFIG_DIR).toBeUndefined();
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
