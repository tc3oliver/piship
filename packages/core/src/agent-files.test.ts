// The environment and configuration files a distribution declares for its Pi
// packages: set and written at launch from the lock, kept when the user
// edited them, and a session-wide auto-approval that is taken back.
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { execFile, spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { processHostToken } from "@piship/contracts";
import type { PackageAgentFile } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  agentFileContent,
  agentFileDigest,
  agentFilesLockHooks,
  applyAgentFiles,
  applyPackageEnvironment,
  inspectAgentFiles,
  lockedAgentFiles,
  packageEnvironment,
  sessionAutoApproveTarget,
} from "./agent-files.js";
import type { DistributionLock } from "./lock-schema.js";

const PATH = "extensions/provider/config.json";
let temp: string;
let agentDir: string;

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-agent-files-"));
  agentDir = join(temp, "agent");
  mkdirSync(agentDir, { recursive: true });
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

interface Options {
  readonly mode?: "seed" | "enforce";
  readonly json?: Record<string, unknown>;
  readonly autoApprove?: boolean;
  readonly environment?: Record<string, string | { statePath: string }>;
}

/** The parts of a lock these functions read. */
function lock(options: Options = {}): DistributionLock {
  const file: PackageAgentFile = {
    path: PATH,
    mode: options.mode ?? "seed",
    json: options.json ?? {
      yoloMode: false,
      permission: { "*": "allow", "*.env": "ask" },
    },
  };
  return {
    packages: [
      {
        id: "provider",
        agentFiles: lockedAgentFiles([file]),
        ...(options.environment ? { environment: options.environment } : {}),
      },
      { id: "other", environment: { PI_OTHER_FLAG: "1" } },
    ],
    governance: {
      manifest: {
        resources: {
          packages: [{ id: "provider", agentFiles: [file] }],
        },
        capabilities: [
          {
            name: "permissions",
            enabled: true,
            settings: options.autoApprove
              ? { autoApproveFile: PATH, autoApproveKey: "yoloMode" }
              : {},
          },
        ],
      },
    },
  } as unknown as DistributionLock;
}

const target = () => join(agentDir, ...PATH.split("/"));
const read = () => readFileSync(target(), "utf8");

describe("what is written", () => {
  it("is the declared JSON in its declared key order, with a digest of those bytes", () => {
    const content = agentFileContent({ b: 1, a: { z: 1, y: 2 } });
    expect(content).toBe(
      '{\n  "b": 1,\n  "a": {\n    "z": 1,\n    "y": 2\n  }\n}\n',
    );
    expect(
      lockedAgentFiles([{ path: PATH, mode: "enforce", json: { b: 1 } }]),
    ).toEqual([
      {
        path: PATH,
        mode: "enforce",
        sha256: agentFileDigest(agentFileContent({ b: 1 })),
      },
    ]);
    // A reordering of rules is a different file: the lock records it.
    expect(
      lockedAgentFiles([{ path: PATH, mode: "seed", json: { a: 1, b: 2 } }])[0]
        ?.sha256,
    ).not.toBe(
      lockedAgentFiles([{ path: PATH, mode: "seed", json: { b: 2, a: 1 } }])[0]
        ?.sha256,
    );
  });
});

describe("package environment", () => {
  it("resolves literals and state paths and replaces the shell's value", () => {
    const state = join(temp, "state");
    const declared = lock({
      environment: {
        PI_LENS_HOME: { statePath: "pi-lens/home" },
        PI_BG_FEATURES: "process",
      },
    });
    expect(packageEnvironment(declared, state)).toEqual([
      {
        package: "provider",
        name: "PI_LENS_HOME",
        value: join(state, "pi-lens", "home"),
        declared: { statePath: "pi-lens/home" },
      },
      {
        package: "provider",
        name: "PI_BG_FEATURES",
        value: "process",
        declared: "process",
      },
      {
        package: "other",
        name: "PI_OTHER_FLAG",
        value: "1",
        declared: "1",
      },
    ]);
    const env: NodeJS.ProcessEnv = {
      PI_BG_FEATURES: "process,attribution",
      KEEP: "me",
    };
    applyPackageEnvironment(declared, state, env);
    expect(env).toEqual({
      PI_BG_FEATURES: "process",
      PI_LENS_HOME: join(state, "pi-lens", "home"),
      PI_OTHER_FLAG: "1",
      KEEP: "me",
    });
  });

  it("is a no-op for a lock without packages", () => {
    const env: NodeJS.ProcessEnv = { A: "1" };
    expect(applyPackageEnvironment({}, temp, env)).toEqual([]);
    expect(env).toEqual({ A: "1" });
  });
});

describe("a seed file", () => {
  it("is written once, kept when the user edits it, and replaced by a newer default only while unedited", () => {
    const first = applyAgentFiles(lock(), agentDir);
    expect(first.reports).toEqual([
      { package: "provider", path: PATH, mode: "seed", outcome: "seeded" },
    ]);
    expect(JSON.parse(read()).yoloMode).toBe(false);
    expect(inspectAgentFiles(lock(), agentDir)[0]?.state).toBe("current");

    // The next launch finds what it wrote.
    expect(applyAgentFiles(lock(), agentDir).reports[0]?.outcome).toBe(
      "unchanged",
    );

    // A newer release's default replaces a file nobody edited.
    const newer = lock({
      json: { yoloMode: false, permission: { "*": "ask" } },
    });
    expect(applyAgentFiles(newer, agentDir).reports[0]?.outcome).toBe(
      "updated",
    );
    expect(JSON.parse(read()).permission).toEqual({ "*": "ask" });

    // The user edits it: the next default is not applied, and says so.
    writeFileSync(target(), '{"permission":{"*":"allow"}}\n');
    const newest = lock({ json: { permission: { "*": "deny" } } });
    expect(applyAgentFiles(newest, agentDir).reports[0]?.outcome).toBe("kept");
    expect(read()).toBe('{"permission":{"*":"allow"}}\n');
    expect(inspectAgentFiles(newest, agentDir)[0]?.state).toBe("edited");
  });

  it("keeps a file that was there before PiShip first wrote anything", () => {
    mkdirSync(join(agentDir, "extensions", "provider"), { recursive: true });
    writeFileSync(target(), '{"mine":true}\n');
    expect(applyAgentFiles(lock(), agentDir).reports[0]?.outcome).toBe("kept");
    expect(read()).toBe('{"mine":true}\n');
  });

  it("is written with owner-only permissions", () => {
    applyAgentFiles(lock(), agentDir);
    if (process.platform !== "win32")
      expect(
        // 0600: the bits of group and others are clear.
        statSync(target()).mode & 0o077,
      ).toBe(0);
  });
});

describe("an enforced file", () => {
  it("is rewritten whenever it differs, so a user's edit does not outlive a launch", () => {
    expect(
      applyAgentFiles(lock({ mode: "enforce" }), agentDir).reports[0]?.outcome,
    ).toBe("seeded");
    writeFileSync(target(), '{"permission":{"*":"allow"}}\n');
    expect(
      inspectAgentFiles(lock({ mode: "enforce" }), agentDir)[0]?.state,
    ).toBe("pending");
    expect(
      applyAgentFiles(lock({ mode: "enforce" }), agentDir).reports[0]?.outcome,
    ).toBe("enforced");
    expect(JSON.parse(read()).permission).toEqual({
      "*": "allow",
      "*.env": "ask",
    });
    expect(
      applyAgentFiles(lock({ mode: "enforce" }), agentDir).reports[0]?.outcome,
    ).toBe("unchanged");
  });
});

describe("integrity and links", () => {
  it("refuses a lock whose record of a file disagrees with its manifest", () => {
    const tampered = lock();
    (
      tampered.governance?.manifest.resources.packages?.[0]
        ?.agentFiles?.[0] as { json: unknown }
    ).json = { permission: { "*": "allow", "sudo *": "allow" } };
    expect(() => applyAgentFiles(tampered, agentDir)).toThrow(
      /does not match the manifest/,
    );
    expect(existsSync(target())).toBe(false);
  });

  it.skipIf(process.platform === "win32")(
    "does not write through a link",
    () => {
      mkdirSync(join(agentDir, "extensions"), { recursive: true });
      const elsewhere = join(temp, "elsewhere");
      mkdirSync(elsewhere);
      symlinkSync(elsewhere, join(agentDir, "extensions", "provider"));
      expect(() => applyAgentFiles(lock(), agentDir)).toThrow(/is a link/);
      expect(existsSync(join(elsewhere, "config.json"))).toBe(false);
    },
  );

  it.skipIf(process.platform === "win32")(
    "replaces a link at the file itself instead of following it",
    () => {
      mkdirSync(join(agentDir, "extensions", "provider"), { recursive: true });
      const outside = join(temp, "outside.json");
      writeFileSync(outside, "outside\n");
      symlinkSync(outside, target());
      expect(() => applyAgentFiles(lock(), agentDir)).toThrow(/is a link/);
      expect(readFileSync(outside, "utf8")).toBe("outside\n");
    },
  );

  it.skipIf(process.platform === "win32")(
    "reports a file it cannot read instead of replacing it silently",
    () => {
      applyAgentFiles(lock(), agentDir);
      chmodSync(target(), 0o000);
      try {
        if (process.getuid?.() !== 0)
          expect(() => applyAgentFiles(lock(), agentDir)).toThrow();
      } finally {
        chmodSync(target(), 0o600);
      }
    },
  );
});

describe("a session auto-approval", () => {
  const key = () => JSON.parse(read()).yoloMode;

  it("names its key through the permissions capability, and only then", () => {
    expect(sessionAutoApproveTarget(lock({ autoApprove: true }))).toEqual({
      path: PATH,
      key: "yoloMode",
    });
    expect(sessionAutoApproveTarget(lock())).toBeUndefined();
    expect(sessionAutoApproveTarget({})).toBeUndefined();
  });

  it("is switched on for the launch and taken back when it ends, keeping other edits", () => {
    const declared = lock({ autoApprove: true });
    const session = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    expect(key()).toBe(true);
    // The permission provider's own command changes another setting mid-session.
    const live = JSON.parse(read());
    live.debugLog = true;
    writeFileSync(target(), `${JSON.stringify(live, null, 2)}\n`);
    session.restore();
    expect(key()).toBe(false);
    expect(JSON.parse(read()).debugLog).toBe(true);
    // Idempotent.
    session.restore();
    expect(key()).toBe(false);
    expect(
      JSON.parse(
        readFileSync(join(agentDir, ".piship-agent-files.json"), "utf8"),
      ).override,
    ).toBeUndefined();
  });

  it("is taken back by the next launch when this one never reached its end", () => {
    const declared = lock({ autoApprove: true });
    applyAgentFiles(declared, agentDir, { sessionAutoApprove: true });
    expect(key()).toBe(true);
    const statePath = join(agentDir, ".piship-agent-files.json");
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    state.override.pid = 2147483647;
    writeFileSync(statePath, JSON.stringify(state));
    // Simulate a dead owner; a live owner must never be taken back.
    applyAgentFiles(declared, agentDir);
    expect(key()).toBe(false);
  });

  it("keeps ordinary sessions concurrent but refuses yolo while either is live", () => {
    const declared = lock({ autoApprove: true });
    const first = applyAgentFiles(declared, agentDir, { session: true });
    const second = applyAgentFiles(declared, agentDir, { session: true });
    expect(() =>
      applyAgentFiles(declared, agentDir, { sessionAutoApprove: true }),
    ).toThrow(/permission provider/);
    expect(key()).toBe(false);
    first.restore();
    expect(() =>
      applyAgentFiles(declared, agentDir, { sessionAutoApprove: true }),
    ).toThrow(/permission provider/);
    second.restore();
    const yolo = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    expect(key()).toBe(true);
    expect(() =>
      applyAgentFiles(declared, agentDir, { session: true }),
    ).toThrow(/permission provider/);
    yolo.restore();
    expect(key()).toBe(false);
  });

  it("tells the user what to do when a --yolo session and an ordinary one meet", () => {
    const declared = lock({ autoApprove: true });
    const ordinary = applyAgentFiles(declared, agentDir, { session: true });
    expect(() =>
      applyAgentFiles(declared, agentDir, { sessionAutoApprove: true }),
    ).toThrow(
      expect.objectContaining({
        code: "CONFIG_INVALID",
        userAction: expect.stringContaining("both with --yolo, or neither"),
      }),
    );
    ordinary.restore();
    const yolo = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    expect(() =>
      applyAgentFiles(declared, agentDir, { session: true }),
    ).toThrow(
      expect.objectContaining({
        userAction: expect.stringContaining("both with --yolo, or neither"),
      }),
    );
    yolo.restore();
  });

  it("lets a second --yolo session share the key, and keeps it on until the last one ends", () => {
    const declared = lock({ autoApprove: true });
    const first = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    const second = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    expect(key()).toBe(true);
    // The owner leaves first: the key stays on for the session that remains.
    first.restore();
    expect(key()).toBe(true);
    second.restore();
    expect(key()).toBe(false);
  });

  it("keeps the key on when the session that shares it ends first", () => {
    const declared = lock({ autoApprove: true });
    const first = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    const second = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    second.restore();
    expect(key()).toBe(true);
    first.restore();
    expect(key()).toBe(false);
  });

  it("puts the key back on a shared file that an enforced seed just rewrote", () => {
    const declared = lock({ autoApprove: true, mode: "enforce" });
    const first = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    const second = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    expect(key()).toBe(true);
    second.restore();
    first.restore();
    expect(key()).toBe(false);
  });

  it("says the provider's approvals stay on after /auto off while another --yolo session shares them", () => {
    const declared = lock({ autoApprove: true });
    const first = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    const second = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    expect(first.endAutoApprove?.()).toMatch(/stay on until the other --yolo/);
    expect(key()).toBe(true);
    // The last session that wants it switches it off, with no notice.
    expect(second.endAutoApprove?.()).toBeUndefined();
    expect(key()).toBe(false);
    second.restore();
    first.restore();
    expect(key()).toBe(false);
  });

  it("keeps the session lease after auto off and restores a provider's stale save at exit", () => {
    const declared = lock({ autoApprove: true });
    const yolo = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    yolo.endAutoApprove?.();
    expect(key()).toBe(false);
    expect(() =>
      applyAgentFiles(declared, agentDir, { session: true }),
    ).toThrow(/permission provider/);
    const stale = JSON.parse(read());
    stale.yoloMode = true;
    writeFileSync(target(), JSON.stringify(stale));
    yolo.restore();
    expect(key()).toBe(false);
  });

  it("never follows a tampered stale override outside the declared provider target", () => {
    const declared = lock({ autoApprove: true });
    applyAgentFiles(declared, agentDir);
    const victim = join(temp, "victim.json");
    writeFileSync(victim, JSON.stringify({ yoloMode: true }));
    writeFileSync(
      join(agentDir, ".piship-agent-files.json"),
      JSON.stringify({
        schema: "piship-agent-files/v1",
        files: {},
        override: {
          path: "../victim.json",
          key: "yoloMode",
          hadKey: true,
          original: false,
        },
      }),
    );
    applyAgentFiles(declared, agentDir);
    expect(JSON.parse(readFileSync(victim, "utf8")).yoloMode).toBe(true);
  });

  it("removes a key the file did not have before the session", () => {
    const declared = lock({ autoApprove: true, json: { permission: {} } });
    const session = applyAgentFiles(declared, agentDir, {
      sessionAutoApprove: true,
    });
    expect(JSON.parse(read()).yoloMode).toBe(true);
    session.restore();
    expect(JSON.parse(read())).not.toHaveProperty("yoloMode");
  });

  it("is refused where the distribution declared no key, and for a file that is not JSON", () => {
    expect(() =>
      applyAgentFiles(lock(), agentDir, { sessionAutoApprove: true }),
    ).toThrow(/declares no session auto-approval/);
    applyAgentFiles(lock({ autoApprove: true }), agentDir);
    writeFileSync(target(), "not json");
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        sessionAutoApprove: true,
      }),
    ).toThrow(/not a JSON object/);
  });
});

// Parallel session launches (a subagent's children) share one transaction lock.
describe("parallel session launches", () => {
  const dist = fileURLToPath(
    new URL("../dist/agent-files.js", import.meta.url),
  );
  const child = `
    const [dist, dir, json, start] = process.argv.slice(1);
    const { applyAgentFiles } = await import(dist);
    while (Date.now() < Number(start));
    try {
      const r = applyAgentFiles(JSON.parse(json), dir, { session: true });
      await new Promise((done) => setTimeout(done, 50));
      r.restore();
      console.log("ok");
    } catch (e) { console.log("FAIL " + e.message); }`;
  const run = (json: string, start: number) =>
    new Promise<string>((done) =>
      execFile(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          child,
          dist,
          agentDir,
          json,
          String(start),
        ],
        (_error, stdout, stderr) => done((stdout + stderr).trim()),
      ),
    );
  // A process that holds the lock (live owner) for `ms`, then lets go.
  const holder = async (ms: number) => {
    const guard = join(agentDir, ".piship-agent-files-lock");
    const script = `
      const fs = require("fs");
      fs.mkdirSync(${JSON.stringify(guard)});
      fs.writeFileSync(${JSON.stringify(join(guard, "owner.json"))}, JSON.stringify({ pid: process.pid }));
      console.log("held");
      setTimeout(() => { fs.rmSync(${JSON.stringify(guard)}, { recursive: true }); }, ${ms});`;
    const proc = spawn(process.execPath, ["-e", script]);
    await new Promise((ready) => proc.stdout.once("data", ready));
    return {
      released: new Promise<void>((done) => proc.on("close", () => done())),
    };
  };

  it("all of 8 concurrent launches succeed", async () => {
    const json = JSON.stringify(lock({ autoApprove: true }));
    // every child waits for the same instant, so they all start together
    const start = Date.now() + 1500;
    const out = await Promise.all(
      Array.from({ length: 8 }, () => run(json, start)),
    );
    expect(out).toEqual(Array(8).fill("ok"));
  }, 60_000);

  it("waits for a lock another launch releases within the budget", async () => {
    const { released } = await holder(400);
    const result = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      session: true,
    });
    result.restore();
    await released;
  });

  it("still fails with the busy error once the budget is spent", async () => {
    const { released } = await holder(1500);
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        session: true,
        lockWaitMs: 150,
      }),
    ).toThrow("being changed by another launch");
    await released;
  });

  it("keeps its wait inside the budget, even for a budget shorter than one pause", async () => {
    const { released } = await holder(1500);
    for (const lockWaitMs of [0, 15, 60]) {
      const started = Date.now();
      expect(() =>
        applyAgentFiles(lock({ autoApprove: true }), agentDir, {
          session: true,
          lockWaitMs,
        }),
      ).toThrow("being changed by another launch");
      // One attempt after the last pause, and not a pause past the budget.
      expect(Date.now() - started).toBeLessThan(lockWaitMs + 250);
    }
    await released;
  });

  it("reports the busy lock as the same coded error as before", async () => {
    const { released } = await holder(600);
    let error: unknown;
    try {
      applyAgentFiles(lock({ autoApprove: true }), agentDir);
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({
      name: "PiShipError",
      code: "CONFIG_INVALID",
      message:
        "Package configuration is being changed by another launch; retry when it finishes",
    });
    await released;
  });

  describe("a lock directory that no launch owns", () => {
    const guard = () => join(agentDir, ".piship-agent-files-lock");
    const aged = (path: string, secondsAgo: number) => {
      const when = new Date(Date.now() - secondsAgo * 1000);
      utimesSync(path, when, when);
    };
    const session = () =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        session: true,
        lockWaitMs: 100,
      });

    it("is taken over once it is older than the bound, with no owner record", () => {
      mkdirSync(guard());
      aged(guard(), 30);
      session().restore();
      expect(existsSync(guard())).toBe(false);
    });

    it("is taken over once it is older than the bound, with an owner record nobody can read", () => {
      mkdirSync(guard());
      writeFileSync(join(guard(), "owner.json"), "{ not json");
      aged(guard(), 30);
      session().restore();
      expect(existsSync(guard())).toBe(false);
    });

    it("is left alone while it may still be being written", () => {
      mkdirSync(guard());
      aged(guard(), 2);
      expect(session).toThrow("being changed by another launch");
      expect(existsSync(guard())).toBe(true);
    });

    it("is not taken when its owner record cannot be read for a reason other than absence", () => {
      mkdirSync(guard());
      // Reading a directory fails with EISDIR: not "no owner", but "unknown".
      mkdirSync(join(guard(), "owner.json"));
      aged(guard(), 3600);
      expect(session).toThrow("being changed by another launch");
      expect(existsSync(guard())).toBe(true);
    });

    it("is never taken from a launch that is alive, however old", () => {
      mkdirSync(guard());
      writeFileSync(
        join(guard(), "owner.json"),
        JSON.stringify({ pid: process.pid }),
      );
      aged(guard(), 3600);
      expect(session).toThrow("being changed by another launch");
      expect(existsSync(guard())).toBe(true);
    });
  });

  describe("the lock under failure and interleaving", () => {
    const guard = () => join(agentDir, ".piship-agent-files-lock");
    const ownerOf = () =>
      JSON.parse(readFileSync(join(guard(), "owner.json"), "utf8"));
    const fail = (code: string) =>
      Object.assign(new Error(`${code}: injected`), { code });
    const session = (lockWaitMs = 0) =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        session: true,
        lockWaitMs,
      });
    /** A lock directory as a holder with this owner record would leave it. */
    const holdAs = (owner: Record<string, unknown>) => {
      rmSync(guard(), { recursive: true, force: true });
      mkdirSync(guard());
      writeFileSync(join(guard(), "owner.json"), JSON.stringify(owner));
    };
    afterEach(() => {
      for (const key of Object.keys(agentFilesLockHooks))
        delete (agentFilesLockHooks as Record<string, unknown>)[key];
    });

    it("retries a release whose rename fails, then lets go", () => {
      let failures = 2;
      agentFilesLockHooks.rename = (from, to) => {
        if (from === guard() && failures-- > 0) throw fail("EPERM");
        renameSync(from, to);
      };
      session().restore();
      expect(failures).toBeLessThan(0);
      expect(existsSync(guard())).toBe(false);
    });

    it("removes the lock in place when the rename keeps failing", () => {
      agentFilesLockHooks.rename = (from, to) => {
        if (from === guard()) throw fail("EBUSY");
        renameSync(from, to);
      };
      session().restore();
      expect(existsSync(guard())).toBe(false);
    });

    it("surfaces an error only when the rename and the removal both fail", () => {
      agentFilesLockHooks.rename = (from, to) => {
        if (from === guard()) throw fail("EPERM");
        renameSync(from, to);
      };
      agentFilesLockHooks.rm = (path) => {
        if (path === guard()) throw fail("EBUSY");
        rmSync(path, { recursive: true, force: true });
      };
      expect(() => session()).toThrow("could not be released");
      // What a person is told to delete is there, and is ours.
      expect(ownerOf().pid).toBe(process.pid);
    });

    it("does not remove a lock that is no longer its own when it lets go", () => {
      agentFilesLockHooks.beforeRelease = () =>
        holdAs({ pid: process.pid, token: "another-holder" });
      // (Not restored: restoring needs the lock, which is another's now.)
      session();
      expect(ownerOf().token).toBe("another-holder");
    });

    it("puts back a lock a stalled recovery finds replaced by another holder's", () => {
      holdAs({ pid: 2 ** 22, token: "dead-holder" });
      // The recovery read the dead holder's record, then stalled; meanwhile
      // another launch took the lock.
      agentFilesLockHooks.afterOwnerRead = () =>
        holdAs({ pid: process.pid, token: "new-holder" });
      expect(() => session()).toThrow("being changed by another launch");
      expect(ownerOf().token).toBe("new-holder");
    });

    it("takes the lock of a dead holder whose process ID another process now has", () => {
      holdAs({
        pid: process.pid,
        token: "dead-holder",
        identity: null,
        // The holder started a day before this process did.
        started: Date.now() - 24 * 60 * 60 * 1000,
        host: processHostToken(),
      });
      session().restore();
      expect(existsSync(guard())).toBe(false);
    });

    it("still treats a holder it cannot tell from its record as alive", () => {
      holdAs({ pid: process.pid, token: "holder" });
      expect(() => session()).toThrow("being changed by another launch");
    });

    it("tries a claim again once when its staging directory was swept, then reports busy", () => {
      let sweeps = 1;
      agentFilesLockHooks.rename = (from, to) => {
        if (to === guard() && sweeps-- > 0) {
          rmSync(from, { recursive: true });
          throw fail("ENOENT");
        }
        renameSync(from, to);
      };
      session().restore();
      expect(sweeps).toBeLessThan(0);
      sweeps = 2;
      expect(() => session()).toThrow("being changed by another launch");
      expect(
        readdirSync(agentDir).filter((name) => name.endsWith(".new")),
      ).toEqual([]);
    });
  });

  describe("a recovery directory that no launch finished", () => {
    const recovery = () => join(agentDir, ".piship-agent-files-recovery");
    const age = (path: string, secondsAgo: number) => {
      const when = new Date(Date.now() - secondsAgo * 1000);
      utimesSync(path, when, when);
    };
    const session = () =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        session: true,
        lockWaitMs: 100,
      });

    it("is removed once it is older than the bound, so launches go on", () => {
      mkdirSync(recovery());
      age(recovery(), 30);
      session().restore();
      expect(existsSync(recovery())).toBe(false);
    });

    it("blocks while it may still be in use", () => {
      mkdirSync(recovery());
      age(recovery(), 2);
      expect(session).toThrow("being changed by another launch");
      expect(existsSync(recovery())).toBe(true);
    });
  });

  describe("the lock is never visible half made", () => {
    const names = () => readdirSync(agentDir);

    it("leaves no staging or discarded directory behind after a launch", () => {
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        session: true,
      }).restore();
      expect(names().filter((name) => /\.(new|stale)$/.test(name))).toEqual([]);
      expect(names()).not.toContain(".piship-agent-files-lock");
    });

    it("sweeps what a launch that died while claiming or discarding left", () => {
      const old = [".new", ".stale"].map((suffix) =>
        join(agentDir, `.piship-agent-files-lock.${"a".repeat(8)}${suffix}`),
      );
      for (const path of old) {
        mkdirSync(path);
        utimesSync(path, new Date(1_000), new Date(1_000));
      }
      // A dead holder's lock, so the takeover (which sweeps) runs.
      const guard = join(agentDir, ".piship-agent-files-lock");
      mkdirSync(guard);
      writeFileSync(
        join(guard, "owner.json"),
        JSON.stringify({ pid: 2 ** 22 }),
      );
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        session: true,
      }).restore();
      for (const path of old) expect(existsSync(path)).toBe(false);
    });

    it("never shows another process a lock directory without its owner record", async () => {
      const guard = join(agentDir, ".piship-agent-files-lock");
      const json = JSON.stringify(lock({ autoApprove: true }));
      // A child launches in a loop; this process looks at the lock path as
      // fast as it can. An observed directory that is empty is a lock being
      // filled in place, which a rename-based claim never produces.
      const script = `
        const { applyAgentFiles } = await import(${JSON.stringify(dist)});
        for (let i = 0; i < 300; i += 1)
          applyAgentFiles(JSON.parse(process.argv[1]), ${JSON.stringify(agentDir)}, { session: true }).restore();`;
      const proc = spawn(process.execPath, [
        "--input-type=module",
        "-e",
        script,
        json,
      ]);
      const done = new Promise<void>((finish) =>
        proc.on("close", () => finish()),
      );
      let empty = 0;
      let seen = 0;
      let finished = false;
      void done.then(() => {
        finished = true;
      });
      while (!finished) {
        try {
          if (readdirSync(guard).length === 0) empty += 1;
          seen += 1;
        } catch {
          // not there at this moment
        }
        await new Promise((resume) => setImmediate(resume));
      }
      expect(seen).toBeGreaterThan(0);
      expect(empty).toBe(0);
    }, 60_000);
  });

  it("does not wait for a launch that is not a session", async () => {
    const { released } = await holder(600);
    const started = Date.now();
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir),
    ).toThrow("being changed by another launch");
    expect(Date.now() - started).toBeLessThan(300);
    await released;
  });
});
