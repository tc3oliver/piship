import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SettingsManager } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import {
  applyPiEnvironment,
  closeJitiCacheToSandbox,
  jitiCacheDirectory,
  jitiCacheFor,
  ownedPrivately,
  PI_SETTINGS,
  piSettings,
} from "./pi-defaults.js";

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
      // On Windows the rule is "under the user's profile", which the runner's
      // temp may not be: make root the profile.
      const profile = process.env.USERPROFILE;
      process.env.USERPROFILE = root;
      try {
        applyPiEnvironment("/state/agent", "personal", cache, env);
      } finally {
        if (profile === undefined) delete process.env.USERPROFILE;
        else process.env.USERPROFILE = profile;
      }
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

  it("turns jiti's cache off for a lock that verifies at launch", () => {
    expect(jitiCacheFor({ verifyAtLaunch: true })).toBe(false);
    expect(jitiCacheFor({ verifyAtLaunch: false })).toBe(jitiCacheDirectory());
    expect(jitiCacheFor({})).toBe(jitiCacheDirectory());
  });

  it("turns jiti's cache off when the sandbox can write it, not for a per-session temp beside it", () => {
    const real = realpathSync(tmpdir());
    const covered: NodeJS.ProcessEnv = {};
    closeJitiCacheToSandbox([real], covered);
    expect(covered.JITI_FS_CACHE).toBe("false");
    const beside: NodeJS.ProcessEnv = {};
    closeJitiCacheToSandbox(
      [join(real, "piship-sandbox-x", "tmp"), join(real, "jiti-other")],
      beside,
    );
    expect(beside.JITI_FS_CACHE).toBeUndefined();
  });

  it.skipIf(!posix)(
    "turns jiti's cache off before it exists when the temp directory is reached through a symlink",
    () => {
      withTemp((root) => {
        const real = join(root, "real");
        mkdirSync(real);
        const link = join(root, "link");
        symlinkSync(real, link);
        const saved = process.env.TMPDIR;
        process.env.TMPDIR = link;
        try {
          const env: NodeJS.ProcessEnv = {};
          closeJitiCacheToSandbox([realpathSync(real)], env);
          expect(env.JITI_FS_CACHE).toBe("false");
        } finally {
          if (saved === undefined) delete process.env.TMPDIR;
          else process.env.TMPDIR = saved;
        }
      });
    },
  );

  it.skipIf(!posix)(
    "refuses a cache directory whose parent its group can write without the sticky bit",
    () => {
      withTemp((root) => {
        const parent = join(root, "group");
        mkdirSync(parent);
        chmodSync(parent, 0o770);
        expect(ownedPrivately(join(parent, "jiti"))).toBe(false);
        chmodSync(parent, 0o1770);
        expect(ownedPrivately(join(parent, "jiti"))).toBe(true);
      });
    },
  );

  it.skipIf(posix)(
    "keeps jiti's cache on Windows only under the user's own profile",
    () => {
      withTemp((root) => {
        const saved = {
          LOCALAPPDATA: process.env.LOCALAPPDATA,
          USERPROFILE: process.env.USERPROFILE,
        };
        try {
          process.env.LOCALAPPDATA = join(root, "profile", "AppData", "Local");
          process.env.USERPROFILE = join(root, "profile");
          expect(ownedPrivately(join(root, "shared", "jiti"))).toBe(false);
          mkdirSync(join(root, "profile", "Temp"), { recursive: true });
          expect(ownedPrivately(join(root, "profile", "Temp", "jiti"))).toBe(
            true,
          );
        } finally {
          for (const [name, value] of Object.entries(saved))
            if (value === undefined) delete process.env[name];
            else process.env[name] = value;
        }
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

describe("piSettings with app.tui", () => {
  it("keeps PiShip's quiet, regular defaults when app.tui is absent", () => {
    const settings = SettingsManager.inMemory(piSettings("off"));
    expect(settings.getQuietStartup()).toBe(true);
    expect(settings.getTuiMode()).toBe("regular");
  });
  it.each([
    [{ mode: "fullscreen" as const }, "fullscreen", true],
    [{ startup: "header" as const }, "regular", "header"],
    [
      { mode: "fullscreen" as const, startup: "full" as const },
      "fullscreen",
      false,
    ],
  ])("applies %j as Pi reads it", (tui, mode, quiet) => {
    const settings = SettingsManager.inMemory(piSettings("off", tui));
    expect(settings.getTuiMode()).toBe(mode);
    expect(settings.getQuietStartup()).toBe(quiet);
  });
});
