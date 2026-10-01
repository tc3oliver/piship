// The live probe's negative paths. Each mutant adapter below runs a stand-in
// for the probe child that behaves like a perfect sandbox except for exactly
// one plane, which it crosses (or lies about). The probe must name that plane
// and refuse; the faithful adapter is the control that keeps these from
// passing vacuously.
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { platformInjectedVariables } from "./activate.js";
import type { SandboxAdapter } from "./adapter.js";
import { probeSandbox } from "./probe.js";
import type { SandboxProfile } from "./profile.js";

type Mutant =
  | "faithful"
  | "outside-write"
  | "outside-write-unreported"
  | "outside-write-unseen"
  | "inside-write-denied"
  | "denied-dir-write"
  | "denied-dir-read"
  | "denied-file-read"
  | "configured-read"
  | "external-connect"
  | "loopback-connect"
  | "loopback-connect-unreported"
  | "loopback-connect-unseen"
  | "protected-file-write"
  | "protected-dir-write"
  | "pinned-rename";

// Stands in for the probe child: performs the allowed write for real, does
// what the mutant crosses for real where the host can observe it, and reports
// every other plane as denied.
const STAND_IN = `
const fs = require("node:fs");
const net = require("node:net");
const mutant = process.argv[1];
const c = JSON.parse(process.argv[2]);
const is = (name) => mutant === name;
const connect = (host, port) => new Promise((done) => {
  const socket = net.connect({ host, port });
  socket.once("connect", () => { socket.destroy(); done(true); });
  socket.once("error", () => done(false));
});
(async () => {
  if (!is("inside-write-denied")) fs.writeFileSync(c.insideFile, "probe");
  if (is("outside-write") || is("outside-write-unreported"))
    fs.writeFileSync(c.outsideFile, "probe");
  if (is("denied-dir-write")) fs.writeFileSync(c.deniedDirWriteFile, "probe");
  if (is("protected-file-write")) fs.writeFileSync(c.protectedFile, "changed");
  if (is("protected-dir-write")) fs.writeFileSync(c.protectedDirFile, "probe");
  if (is("pinned-rename")) fs.renameSync(c.pinnedDir, c.pinnedMoved);
  const loopback = is("loopback-connect") || is("loopback-connect-unreported")
    ? await connect("127.0.0.1", c.loopbackPort)
    : false;
  const report = {
    outsideWrite: is("outside-write") || is("outside-write-unseen"),
    insideWrite: !is("inside-write-denied"),
    deniedDirWrite: is("denied-dir-write"),
    deniedDirLeak: is("denied-dir-read") && fs.readdirSync(c.deniedDir).length > 0,
    deniedFileLeak: is("denied-file-read") && fs.readFileSync(c.deniedFile).length > 0,
    configuredLeaks: is("configured-read")
      ? c.configured.filter((p) => fs.readFileSync(p).length > 0)
      : [],
    env: Object.keys(process.env),
    external: is("external-connect"),
    loopback: is("loopback-connect") ? loopback : is("loopback-connect-unseen"),
    protectedFileWrite: is("protected-file-write"),
    protectedDirWrite: is("protected-dir-write"),
    pinnedRename: is("pinned-rename"),
  };
  process.stdout.write(JSON.stringify(report));
})();
`;

/** An adapter that runs the stand-in instead of the probe script. */
function mutantAdapter(
  mutant: Mutant,
  extraEnv: Readonly<Record<string, string>> = {},
): SandboxAdapter {
  return {
    id: "macos-seatbelt",
    available: async () => ({ available: true }),
    wrap: (_profile, command) => {
      const input = command.args[2];
      if (command.args[0] !== "-e" || input === undefined)
        throw new Error("the probe did not ask for its script to be run");
      return {
        file: command.file,
        args: ["-e", STAND_IN, mutant, input],
        cwd: command.cwd,
        env: { ...command.env, ...extraEnv },
      };
    },
  };
}

let root: string;
let configuredSecret: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-probe-")));
  for (const dir of ["workspace", "home", "tmp", "host"])
    mkdirSync(join(root, dir));
  configuredSecret = join(root, "host", "secret");
  writeFileSync(configuredSecret, "configured-secret");
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const profile = (network: "deny" | "allow" = "deny"): SandboxProfile => ({
  workspace: join(root, "workspace"),
  homeDir: join(root, "home"),
  tmpDir: join(root, "tmp"),
  readDeny: [configuredSecret],
  writeAllow: [join(root, "workspace"), join(root, "tmp")],
  readOnly: [],
  writeProtect: { files: [], directories: [] },
  network,
  environmentAllow: ["PATH"],
  warnings: [],
});

// Names a new process gets without its parent passing them: the variables
// macOS sets itself, and on Windows the ones libuv copies into every child
// environment that lacks them. The probe tolerates these as `injected`.
const WINDOWS_REQUIRED = [
  "HOMEDRIVE",
  "HOMEPATH",
  "LOGONSERVER",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  // Windows reports this one with its own casing, and the probe compares
  // names exactly.
  "SystemRoot",
  "TEMP",
  "USERDOMAIN",
  "USERNAME",
  "USERPROFILE",
  "WINDIR",
];
const options = {
  env: { PATH: process.env.PATH ?? "" },
  injected: [
    ...platformInjectedVariables(process.platform),
    ...(process.platform === "win32" ? WINDOWS_REQUIRED : []),
  ],
};

async function refusal(
  mutant: Mutant,
  extraEnv?: Readonly<Record<string, string>>,
): Promise<string> {
  const result = await probeSandbox(
    mutantAdapter(mutant, extraEnv),
    profile(),
    options,
  );
  if (result.ok) throw new Error(`the probe accepted the ${mutant} mutant`);
  return result.reason;
}

describe("probeSandbox control", () => {
  it("accepts a sandbox that holds every plane and claims all of them", async () => {
    const result = await probeSandbox(
      mutantAdapter("faithful"),
      profile(),
      options,
    );
    expect(result).toEqual({
      ok: true,
      planes: [
        "filesystem-read-deny",
        "filesystem-write-allowlist",
        "network-deny",
        "environment-filter",
        "git-control-protection",
      ],
    });
  });
});

describe("probeSandbox write allowlist", () => {
  it("refuses a sandbox that lets a write outside the allowed paths through", async () => {
    expect(await refusal("outside-write")).toContain(
      "a write outside the allowed paths succeeded",
    );
  });

  it("refuses an outside write the child does not report, from the file left on the host", async () => {
    expect(await refusal("outside-write-unreported")).toContain(
      "a write outside the allowed paths succeeded",
    );
  });

  // The write landed somewhere the host cannot see (a sandbox-private
  // overlay, say): the child's own report is still a crossing.
  it("refuses an outside write the child reports but the host cannot see", async () => {
    expect(await refusal("outside-write-unseen")).toContain(
      "a write outside the allowed paths succeeded",
    );
  });

  it("refuses a sandbox that blocks writes inside an allowed path", async () => {
    expect(await refusal("inside-write-denied")).toContain(
      "a write inside an allowed path failed",
    );
  });

  it("refuses a sandbox that lets a denied directory inside an allowed path be written", async () => {
    expect(await refusal("denied-dir-write")).toContain(
      "a write into a denied directory inside an allowed path succeeded",
    );
  });
});

describe("probeSandbox read deny", () => {
  it("refuses a sandbox that lets a denied directory be listed", async () => {
    expect(await refusal("denied-dir-read")).toContain(
      "a denied directory was readable",
    );
  });

  it("refuses a sandbox that lets a denied file be read", async () => {
    expect(await refusal("denied-file-read")).toContain(
      "a denied file was readable",
    );
  });

  it("refuses a sandbox that lets a configured read-denied path be read", async () => {
    expect(await refusal("configured-read")).toContain(
      `configured read-denied path ${configuredSecret} was readable`,
    );
  });
});

describe("probeSandbox environment filter", () => {
  it("refuses a sandbox that passes an unapproved variable to the child", async () => {
    expect(
      await refusal("faithful", { PISHIP_PROBE_UNAPPROVED: "value" }),
    ).toContain(
      "unapproved environment variables reached the child: PISHIP_PROBE_UNAPPROVED",
    );
  });
});

describe("probeSandbox network deny", () => {
  it("refuses a sandbox that lets an external connection through", async () => {
    expect(await refusal("external-connect")).toContain(
      "an external network connection succeeded",
    );
  });

  it("refuses a sandbox that lets the child reach a host loopback listener", async () => {
    expect(await refusal("loopback-connect")).toContain(
      "a connection to a host loopback listener succeeded",
    );
  });

  it("refuses a loopback connection the child does not report, from the listener's own count", async () => {
    expect(await refusal("loopback-connect-unreported")).toContain(
      "a connection to a host loopback listener succeeded",
    );
  });

  // Reached a loopback listener that is not the host's (a private network
  // namespace with its own, say): the child's report still counts.
  it("refuses a loopback connection the child reports but the host listener never saw", async () => {
    expect(await refusal("loopback-connect-unseen")).toContain(
      "a connection to a host loopback listener succeeded",
    );
  });

  it("does not hold an allowed network against the sandbox or claim network-deny", async () => {
    const result = await probeSandbox(
      mutantAdapter("external-connect"),
      profile("allow"),
      options,
    );
    expect(result.ok).toBe(true);
    expect(result.ok && result.planes).not.toContain("network-deny");
  });
});

describe("probeSandbox git control protection", () => {
  for (const [mutant, failure] of [
    [
      "protected-file-write",
      "a protected file inside an allowed path was writable",
    ],
    ["protected-dir-write", "a file could be created in a protected directory"],
    [
      "pinned-rename",
      "the directory holding a protected file could be renamed",
    ],
  ] as const) {
    it(`withholds git-control-protection and warns when ${failure}`, async () => {
      const result = await probeSandbox(
        mutantAdapter(mutant),
        profile(),
        options,
      );
      if (!result.ok) throw new Error(result.reason);
      expect(result.planes).not.toContain("git-control-protection");
      expect(result.warnings).toEqual([expect.stringContaining(failure)]);
    });
  }
});
