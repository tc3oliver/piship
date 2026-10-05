// The environment and configuration files a distribution declares for its Pi
// packages: set and written at launch from the lock, kept when the user
// edited them, and a session-wide auto-approval that is taken back.
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
    expect(content).toBe('{\n  "b": 1,\n  "a": {\n    "z": 1,\n    "y": 2\n  }\n}\n');
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
    const newer = lock({ json: { yoloMode: false, permission: { "*": "ask" } } });
    expect(applyAgentFiles(newer, agentDir).reports[0]?.outcome).toBe("updated");
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
        require("node:fs").statSync(target()).mode & 0o077,
      ).toBe(0);
  });
});

describe("an enforced file", () => {
  it("is rewritten whenever it differs, so a user's edit does not outlive a launch", () => {
    expect(
      applyAgentFiles(lock({ mode: "enforce" }), agentDir).reports[0]?.outcome,
    ).toBe("seeded");
    writeFileSync(target(), '{"permission":{"*":"allow"}}\n');
    expect(inspectAgentFiles(lock({ mode: "enforce" }), agentDir)[0]?.state).toBe(
      "pending",
    );
    expect(
      applyAgentFiles(lock({ mode: "enforce" }), agentDir).reports[0]?.outcome,
    ).toBe("enforced");
    expect(JSON.parse(read()).permission).toEqual({ "*": "allow", "*.env": "ask" });
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
      JSON.parse(readFileSync(join(agentDir, ".piship-agent-files.json"), "utf8"))
        .override,
    ).toBeUndefined();
  });

  it("is taken back by the next launch when this one never reached its end", () => {
    const declared = lock({ autoApprove: true });
    applyAgentFiles(declared, agentDir, { sessionAutoApprove: true });
    expect(key()).toBe(true);
    // The process was killed: nothing restored. The next launch, without the
    // option, finds the recorded override first.
    applyAgentFiles(declared, agentDir);
    expect(key()).toBe(false);
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
