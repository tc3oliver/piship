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
import { processHostToken } from "@piship/contracts";
import type { PackageAgentFile } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  agentFileContent,
  agentFileDigest,
  applyAgentFiles,
  applyPackageEnvironment,
  inspectAgentFiles,
  lockedAgentFiles,
  packageEnvironment,
  sessionAutoApproveTarget,
} from "./agent-files.js";
import { agentFilesLockHooks } from "./agent-files-hooks.js";
import type { DistributionLock } from "./lock-schema.js";
import { recordedIdentity, recordedStart } from "./process-identity.js";
import {
  deadPid,
  livePid,
  stopLiveProcesses,
} from "../../../tests/helpers/processes.js";

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

// The override and lease records name their process by the full record (pid,
// host, identity, started), so a killed session's ID being reused does not
// wedge the provider for every later launch, and a foreign host's lease is
// never deleted for lacking a local process.
describe("provider session ownership", () => {
  const key = () => JSON.parse(read()).yoloMode;
  const sidecar = () => join(agentDir, ".piship-agent-files.json");
  const leases = () => join(agentDir, ".piship-provider-sessions");
  const leaseNames = () => (existsSync(leases()) ? readdirSync(leases()) : []);
  const writeOverride = (override: Record<string, unknown>) =>
    writeFileSync(
      sidecar(),
      JSON.stringify({
        schema: "piship-agent-files/v1",
        files: {},
        override,
      }),
    );
  const writeLease = (name: string, lease: Record<string, unknown>) => {
    mkdirSync(leases(), { recursive: true, mode: 0o700 });
    writeFileSync(join(leases(), name), JSON.stringify(lease));
  };
  afterEach(stopLiveProcesses);

  it("records the launch's process in the override and in the lease", () => {
    const session = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    const override = JSON.parse(readFileSync(sidecar(), "utf8")).override;
    expect(override).toMatchObject({
      pid: process.pid,
      host: processHostToken(),
      identity: recordedIdentity(),
      started: recordedStart(),
    });
    expect(
      JSON.parse(readFileSync(join(leases(), override.owner), "utf8")),
    ).toMatchObject({ pid: process.pid, yolo: true });
    session.restore();
  });

  it("reclaims an override whose process ID another process now has", () => {
    applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    // A killed session's ID, reused: the start time the system reports for the
    // process holding it lies clearly after the record, so it is a different
    // process. Without this, every later launch would fail with "another live
    // session owns the permission provider auto-approval".
    const state = JSON.parse(readFileSync(sidecar(), "utf8"));
    const pid = livePid();
    writeOverride({
      ...state.override,
      owner: undefined,
      pid,
      started: Date.now() - 60_000,
    });
    const next = applyAgentFiles(lock({ autoApprove: true }), agentDir);
    expect(key()).toBe(false);
    next.restore();
  });

  it("refuses while the override's process is the same live one", () => {
    applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir),
    ).toThrow(/Another live session owns/);
  });

  it("keeps a foreign host's override instead of clearing it", () => {
    applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    const state = JSON.parse(readFileSync(sidecar(), "utf8"));
    writeOverride({
      ...state.override,
      owner: undefined,
      pid: deadPid(),
      host: "000000000000",
    });
    // Cannot be told: the record stays and blocks, rather than being taken
    // back from a session another host may still be running.
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir),
    ).toThrow(/Another live session owns/);
    expect(key()).toBe(true);
  });

  it("names the sidecar a stuck override must be cleared from", () => {
    // An override naming this process is live, so any launch refuses; what a
    // person is told to clear is the sidecar that holds it.
    writeOverride({
      pid: process.pid,
      host: processHostToken(),
      started: recordedStart(),
      identity: recordedIdentity(),
      path: PATH,
      key: "yoloMode",
      hadKey: true,
      original: false,
    });
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir),
    ).toThrow(
      expect.objectContaining({
        userAction: expect.stringContaining(".piship-agent-files.json"),
      }),
    );
  });

  it("reclaims a legacy pid-only override whose process is dead", () => {
    // A v0.13.0 record: no host, identity or started. A dead ID is proven
    // gone without them; it is not judged dead merely for lacking them.
    applyAgentFiles(lock({ autoApprove: true }), agentDir);
    writeOverride({
      pid: deadPid(),
      path: PATH,
      key: "yoloMode",
      hadKey: true,
      original: false,
    });
    const config = JSON.parse(read());
    writeFileSync(target(), JSON.stringify({ ...config, yoloMode: true }));
    const next = applyAgentFiles(lock({ autoApprove: true }), agentDir);
    expect(key()).toBe(false);
    next.restore();
  });

  it("keeps a legacy pid-only lease whose ID a process still has", () => {
    writeLease("legacy", { pid: livePid(), yolo: false });
    // Unknown, not dead: the lease stays and still conflicts with --yolo.
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir, {
        sessionAutoApprove: true,
      }),
    ).toThrow(/permission provider/);
    expect(leaseNames()).toContain("legacy");
  });

  it("deletes a legacy pid-only lease whose process is gone", () => {
    writeLease("legacy", { pid: deadPid(), yolo: false });
    applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    }).restore();
    expect(leaseNames()).not.toContain("legacy");
  });

  it("never deletes a foreign host's lease, and refuses an ordinary session under it", () => {
    applyAgentFiles(lock({ autoApprove: true }), agentDir);
    writeLease("foreign", {
      pid: deadPid(),
      yolo: true,
      host: "000000000000",
      started: Date.now(),
      identity: null,
    });
    // The lease may be a session another host is running: it stays, and an
    // ordinary launch cannot have the provider its way while a --yolo one may.
    expect(() =>
      applyAgentFiles(lock({ autoApprove: true }), agentDir, { session: true }),
    ).toThrow(/permission provider/);
    expect(leaseNames()).toContain("foreign");
    expect(key()).toBe(false);
  });

  it("shares the key with a foreign host's --yolo lease, as with a local one", () => {
    writeLease("foreign", {
      pid: deadPid(),
      yolo: true,
      host: "000000000000",
      started: Date.now(),
      identity: null,
    });
    // Two --yolo sessions want the same thing; one that cannot be judged dead
    // is one that may be running on the other host.
    applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    expect(key()).toBe(true);
    expect(leaseNames()).toContain("foreign");
  });

  it("deletes a lease whose process ID another live process now has when it would block", () => {
    applyAgentFiles(lock({ autoApprove: true }), agentDir);
    writeLease("recycled", {
      pid: livePid(),
      yolo: true,
      host: processHostToken(),
      started: Date.now() - 60_000,
      // A writer on this platform records its own identity (`ownRecord`): on
      // Linux that is the `boot:ticks` the reused-ID proof compares against,
      // elsewhere `null` and the start time carries the proof. Without it a
      // Linux record with a live ID is a legacy one that cannot be judged gone.
      identity: recordedIdentity(),
    });
    // A killed --yolo session whose ID was reused must not refuse every later
    // ordinary launch: the reliable check runs where the refusal is about to
    // happen, proves the lease is another process's, and clears it.
    const session = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      session: true,
    });
    expect(leaseNames()).not.toContain("recycled");
    session.restore();
  });

  it("keeps a live same-mode lease and does not refuse under it", () => {
    writeLease("other", {
      pid: livePid(),
      yolo: false,
      host: processHostToken(),
      started: Date.now(),
      identity: null,
    });
    // Ordinary sessions coexist: another ordinary lease neither conflicts nor
    // is cleared.
    applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      session: true,
    }).restore();
    expect(leaseNames()).toContain("other");
  });

  it("hands the key to a heir named by its whole record", () => {
    const first = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    const second = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    first.restore();
    expect(key()).toBe(true);
    const override = JSON.parse(readFileSync(sidecar(), "utf8")).override;
    // The heir's lease is this process's own record, so the fields match it.
    expect(override).toMatchObject({
      pid: process.pid,
      host: processHostToken(),
      started: recordedStart(),
    });
    second.restore();
    expect(key()).toBe(false);
  });

  // A `--yolo` session that died without a clean exit leaves a lease naming a
  // process ID another live process may since have taken. The same-mode scan
  // keeps such a lease on the free `liveProcess` check alone and sets `share`,
  // so these pin that a recycled ID is never mistaken for a session to share
  // the provider with: the new launch must end up owning the key itself.
  it("takes its own override, not a shared one, over a recycled same-mode lease", () => {
    writeLease("recycled", {
      pid: livePid(),
      yolo: true,
      host: processHostToken(),
      started: Date.now() - 60_000,
      identity: recordedIdentity(),
    });
    // No override on disk: the dead session's key was never left switched on.
    const session = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    expect(key()).toBe(true);
    // The override is this launch's own process, not a share of the gone one.
    expect(JSON.parse(readFileSync(sidecar(), "utf8")).override).toMatchObject({
      pid: process.pid,
      host: processHostToken(),
    });
    session.restore();
    expect(key()).toBe(false);
  });

  it("reclaims a recycled override and lease left by a dead --yolo session", () => {
    applyAgentFiles(lock({ autoApprove: true }), agentDir);
    const recycled = {
      pid: livePid(),
      host: processHostToken(),
      started: Date.now() - 60_000,
      identity: recordedIdentity(),
    };
    // Both records name the reused ID: the lease (same-mode, so the scan keeps
    // it and sets `share`) and the override the dead session left switched on.
    writeLease("recycled", { ...recycled, yolo: true });
    writeOverride({
      ...recycled,
      path: PATH,
      key: "yoloMode",
      hadKey: true,
      original: false,
    });
    writeFileSync(
      target(),
      JSON.stringify({ ...JSON.parse(read()), yoloMode: true }),
    );
    const session = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    // The dead override was taken back and this launch owns a fresh one, so the
    // key is on for the right process and off again when it ends.
    expect(key()).toBe(true);
    expect(JSON.parse(readFileSync(sidecar(), "utf8")).override).toMatchObject({
      pid: process.pid,
    });
    session.restore();
    expect(key()).toBe(false);
  });

  it("enables its own auto-approval over a recycled ended --yolo lease", () => {
    // `/auto off` then an abnormal exit: the lease stays (`ended`) naming a
    // reused ID. A new --yolo launch must still switch the key on for itself.
    writeLease("ended", {
      pid: livePid(),
      yolo: true,
      ended: true,
      host: processHostToken(),
      started: Date.now() - 60_000,
      identity: recordedIdentity(),
    });
    const session = applyAgentFiles(lock({ autoApprove: true }), agentDir, {
      sessionAutoApprove: true,
      session: true,
    });
    expect(key()).toBe(true);
    expect(JSON.parse(readFileSync(sidecar(), "utf8")).override).toMatchObject({
      pid: process.pid,
    });
    session.restore();
    expect(key()).toBe(false);
  });
});

// Parallel session launches (a subagent's children) share one transaction lock.
describe("parallel session launches", () => {
  // A file: URL, which `import()` takes on every platform (a Windows path
  // such as D:\a\... is read as a URL with the scheme "d:").
  const dist = new URL("../dist/agent-files.js", import.meta.url).href;
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

    it("never moves a lock a stalled recovery finds replaced by another holder's", () => {
      holdAs({ pid: 2 ** 22, token: "dead-holder" });
      const moved: string[] = [];
      agentFilesLockHooks.rename = (from, to) => {
        if (from === guard()) moved.push(from);
        renameSync(from, to);
      };
      // The recovery read the dead holder's record, then stalled; meanwhile
      // another launch took the lock and is running its operation.
      agentFilesLockHooks.afterOwnerRead = () =>
        holdAs({ pid: process.pid, token: "new-holder" });
      expect(() => session()).toThrow("being changed by another launch");
      expect(ownerOf().token).toBe("new-holder");
      // Not renamed away and put back: not touched at all.
      expect(moved).toEqual([]);
    });

    it("marks its recovery directory as in use again before it takes a lock down", () => {
      holdAs({ pid: 2 ** 22, token: "dead-holder" });
      const recovery = join(agentDir, ".piship-agent-files-recovery");
      let idle = Number.NaN;
      // The owner check was slow: the directory looks abandoned by now.
      agentFilesLockHooks.afterOwnerRead = () => {
        const old = new Date(Date.now() - 60_000);
        utimesSync(recovery, old, old);
      };
      agentFilesLockHooks.afterHolderCheck = () => {
        idle = Date.now() - statSync(recovery).mtimeMs;
      };
      session().restore();
      expect(idle).toBeLessThan(5_000);
    });

    it("retries a release when the owner record cannot be read for a moment, and does not leave the lock", () => {
      let moves = 0;
      agentFilesLockHooks.rename = (from, to) => {
        const record = (dir: string) => join(dir, "owner.json");
        if (from === guard()) {
          moves += 1;
          renameSync(from, to);
          if (moves === 1) {
            // A scanner holds the record: it reads as unreadable, not absent.
            renameSync(record(to), `${record(to)}.kept`);
            mkdirSync(record(to));
          }
          return;
        }
        if (to === guard() && from.endsWith(".stale")) {
          // Put back: the scanner has let go by now.
          rmSync(record(from), { recursive: true, force: true });
          renameSync(`${record(from)}.kept`, record(from));
        }
        renameSync(from, to);
      };
      session().restore();
      expect(moves).toBeGreaterThanOrEqual(2);
      expect(existsSync(guard())).toBe(false);
    });

    it("reports a release it cannot do because the owner record stays unreadable", () => {
      agentFilesLockHooks.beforeRelease = () => {
        renameSync(join(guard(), "owner.json"), join(guard(), "kept.json"));
        mkdirSync(join(guard(), "owner.json"));
      };
      expect(() => session()).toThrow("could not be released");
      expect(existsSync(guard())).toBe(true);
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

    it("never takes a foreign host's lock down because no local process has its ID", () => {
      // An agent directory shared across hosts (an NFS home): host A's lock is
      // mid-transaction, and no process on host B has A's ID. A local lookup
      // must not judge A's live lock dead.
      holdAs({
        pid: 2 ** 22,
        token: "foreign-holder",
        identity: null,
        started: Date.now(),
        host: "000000000000",
      });
      expect(() => session()).toThrow("being changed by another launch");
      expect(ownerOf().token).toBe("foreign-holder");
    });

    it("never takes a foreign host's lock down when its ID collides with a live local process", () => {
      const pid = livePid();
      holdAs({
        pid,
        token: "foreign-holder",
        identity: null,
        started: Date.now() - 24 * 60 * 60 * 1000,
        host: "000000000000",
      });
      expect(() => session()).toThrow("being changed by another launch");
      expect(ownerOf().token).toBe("foreign-holder");
    });

    it("never takes a foreign host's lock down when its ID collides with a dead local one", () => {
      holdAs({
        pid: deadPid(),
        token: "foreign-holder",
        identity: null,
        started: Date.now(),
        host: "000000000000",
      });
      expect(() => session()).toThrow("being changed by another launch");
      expect(ownerOf().token).toBe("foreign-holder");
    });

    it("tells a launch that cannot get the lock what to delete", () => {
      holdAs({ pid: process.pid, token: "holder" });
      expect(() => session()).toThrow(
        expect.objectContaining({
          userAction: expect.stringContaining(".piship-agent-files-lock"),
        }),
      );
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

    it("does not replace a fresh recovery directory made while it discarded the old one", () => {
      mkdirSync(recovery());
      age(recovery(), 30);
      let fresh = -1;
      agentFilesLockHooks.rename = (from, to) => {
        renameSync(from, to);
        if (from === recovery()) {
          // The directory moved looks fresh again, and another launch has
          // made a recovery of its own at the path.
          age(to, 0);
          mkdirSync(recovery());
          fresh = statSync(recovery()).ino;
        }
      };
      expect(session).toThrow("being changed by another launch");
      expect(statSync(recovery()).ino).toBe(fresh);
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
      const old = [
        ".piship-agent-files-lock.aaaaaaaa.new",
        ".piship-agent-files-lock.aaaaaaaa.stale",
        ".piship-agent-files-recovery.aaaaaaaa.stale",
      ].map((name) => join(agentDir, name));
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

    /**
     * Whether the directory at `path` was seen empty while it was at `path`.
     * A listing is not a snapshot: a directory opened at the path can be
     * renamed away and emptied (a release) before its entries are read, and
     * then reads as empty although it was never empty at the path. So an
     * empty listing counts only if the path still names that same directory
     * afterwards (same inode and creation time).
     */
    const emptyAtPath = (path: string): boolean => {
      const identity = () => {
        const stat = statSync(path);
        return `${stat.ino}:${stat.birthtimeMs}`;
      };
      try {
        const before = identity();
        if (readdirSync(path).length > 0) return false;
        return identity() === before;
      } catch {
        // not there (any more)
        return false;
      }
    };

    it("tells a directory emptied after it was renamed away from one that is empty at the lock path", () => {
      const path = join(agentDir, "observed");
      mkdirSync(path);
      expect(emptyAtPath(path)).toBe(true);
      writeFileSync(join(path, "owner.json"), "{}");
      expect(emptyAtPath(path)).toBe(false);
      rmSync(path, { recursive: true });
      expect(emptyAtPath(path)).toBe(false);
    });

    it("never shows another process a lock directory without its owner record", async () => {
      const guard = join(agentDir, ".piship-agent-files-lock");
      const json = JSON.stringify(lock({ autoApprove: true }));
      // A child launches in a loop; this process looks at the lock path as
      // fast as it can. A directory seen empty at the path is a lock being
      // filled (or emptied) in place, which a rename-based claim and release
      // never produce; one emptied after it was renamed away is not seen
      // there (see emptyAtPath).
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
          if (emptyAtPath(guard)) empty += 1;
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
