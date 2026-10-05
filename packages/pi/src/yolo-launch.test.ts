// `--yolo` as a leading launch option: accepted with the other session
// options in any order, refused where it means nothing, and refused before any
// state exists where the distribution does not allow it.
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import type { DistributionLock } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { preparePiEnvironment } from "./environment.js";
import { launchPiDistribution, PINNED_PI_VERSION } from "./index.js";

let temp: string;
const saved = {
  home: process.env.PISHIP_STATE_HOME,
  agentDir: process.env.PI_CODING_AGENT_DIR,
  stdin: Object.getOwnPropertyDescriptor(process.stdin, "isTTY"),
  stdout: Object.getOwnPropertyDescriptor(process.stdout, "isTTY"),
};
const setTTY = (stream: NodeJS.ReadStream | NodeJS.WriteStream, on: boolean) =>
  Object.defineProperty(stream, "isTTY", { value: on, configurable: true });
const restore = (
  stream: NodeJS.ReadStream | NodeJS.WriteStream,
  descriptor: PropertyDescriptor | undefined,
) => {
  if (descriptor) Object.defineProperty(stream, "isTTY", descriptor);
  else delete (stream as { isTTY?: boolean }).isTTY;
};

beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-yolo-launch-"));
  process.env.PISHIP_STATE_HOME = temp;
  // No terminal: a launch that accepts its options stops at "needs a terminal"
  // instead of starting Pi.
  setTTY(process.stdin, false);
  setTTY(process.stdout, false);
});
afterEach(() => {
  vi.restoreAllMocks();
  if (saved.home === undefined) delete process.env.PISHIP_STATE_HOME;
  else process.env.PISHIP_STATE_HOME = saved.home;
  if (saved.agentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = saved.agentDir;
  restore(process.stdin, saved.stdin);
  restore(process.stdout, saved.stdout);
  rmSync(temp, { recursive: true, force: true });
});

interface Kind {
  readonly mode: "personal" | "managed";
  /** `policy.userAuto`; absent means the manifest does not declare it. */
  readonly userAuto?: "allowed" | "off";
  /** A distribution without governance (piship/v1alpha1 or v1alpha2). */
  readonly ungoverned?: boolean;
}

const metadata = (kind: Kind) =>
  ({
    app: {
      id: "acmecode",
      command: "acmecode",
      name: "AcmeCode",
      version: "1.0.0",
    },
    runtime: {
      package: "@earendil-works/pi-coding-agent",
      version: PINNED_PI_VERSION,
      pishipVersion: "1.0.0",
    },
    deployment: { mode: kind.mode },
    ...(kind.ungoverned
      ? {}
      : {
          governance: {
            manifest: {
              sandbox: {},
              policy: kind.userAuto ? { userAuto: kind.userAuto } : {},
            },
          },
        }),
  }) as unknown as DistributionLock;

const launch = (kind: Kind, args: string[]) => {
  preparePiEnvironment("acmecode");
  return launchPiDistribution({
    distributionDir: temp,
    metadata: metadata(kind),
    args,
  });
};

const failure = (kind: Kind, args: string[]) =>
  launch(kind, args).then(
    () => undefined,
    (error: unknown) => error as PiShipError,
  );

const stateCreated = () => existsSync(join(temp, "acmecode"));
const PERSONAL: Kind = { mode: "personal" };
const MANAGED_ALLOWED: Kind = { mode: "managed", userAuto: "allowed" };

describe("--yolo as a leading option", () => {
  it.each([
    [["--yolo"]],
    [["--yolo", "--new-session"]],
    [["--new-session", "--yolo"]],
    [["--yolo", "--model", "acme/coder"]],
    [["--model", "acme/coder", "--yolo"]],
    [["--new-session", "--yolo", "--model", "acme/coder"]],
  ])("is accepted with the other options: %j", async (args) => {
    for (const kind of [PERSONAL, MANAGED_ALLOWED]) {
      // Accepted means the launch got as far as its terminal check.
      const error = await failure(kind, args);
      expect(error).toBeInstanceOf(PiShipError);
      expect(error?.code).toBe("CONFIG_INVALID");
      expect(error?.message).toContain("needs a terminal");
      expect(stateCreated()).toBe(false);
    }
  });

  it.each([
    [["--yolo", "--version"]],
    [["--yolo", "version"]],
    [["--yolo", "--help"]],
    [["--yolo", "doctor"]],
    [["--yolo", "doctor", "--json"]],
    [["--yolo", "update", "--check"]],
    [["--yolo", "policy", "explain", "tool.execute", "bash"]],
    [["--yolo", "auto", "status"]],
    [["--model", "acme/coder", "--yolo", "doctor"]],
    [["--yolo", "--yolo"]],
  ])("is refused for what it means nothing to: %j", async (args) => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    for (const kind of [PERSONAL, MANAGED_ALLOWED]) {
      const error = await failure(kind, args);
      expect(error).toBeInstanceOf(PiShipError);
      expect(error?.code).toBe("CONFIG_INVALID");
      expect(error?.message).toMatch(
        /^--yolo applies only when a session starts/,
      );
      expect(error?.userAction).toContain("acmecode --yolo");
      expect(log).not.toHaveBeenCalled();
      expect(stateCreated()).toBe(false);
    }
  });

  it("never echoes what follows it, which may hold a secret", async () => {
    const error = await failure(PERSONAL, [
      "--yolo",
      "sandbox",
      "login",
      "hunter2-canary",
    ]);
    expect(error?.code).toBe("CONFIG_INVALID");
    expect(JSON.stringify([error?.message, error?.userAction])).not.toContain(
      "hunter2-canary",
    );
  });

  it("is a leading option only", async () => {
    const error = await failure(PERSONAL, ["--smoke", "--yolo"]);
    expect(error?.message).toMatch(/^Unknown branded command option/);
  });
});

describe("--yolo where the distribution does not allow it", () => {
  it.each([
    ["managed, policy.userAuto absent", { mode: "managed" } as Kind],
    [
      "managed, policy.userAuto off",
      { mode: "managed", userAuto: "off" } as Kind,
    ],
  ])("fails before any state exists: %s", async (_, kind) => {
    // Without a terminal too: the refusal comes first.
    const error = await failure(kind, ["--yolo"]);
    expect(error).toBeInstanceOf(PiShipError);
    expect(error?.code).toBe("POLICY_DENIED");
    expect(error?.message).toContain(
      "this distribution does not allow auto-approval (policy.userAuto is off)",
    );
    expect(error?.userAction).toContain("acmecode");
    expect(stateCreated()).toBe(false);
  });

  it("fails the same way with the other options and --smoke", async () => {
    for (const args of [
      ["--model", "acme/coder", "--yolo"],
      ["--yolo", "--smoke"],
      ["--new-session", "--yolo", "--smoke-model"],
    ]) {
      const error = await failure({ mode: "managed" }, args);
      expect(error?.code).toBe("POLICY_DENIED");
      expect(stateCreated()).toBe(false);
    }
  });

  it("fails for a distribution that declares no policy", async () => {
    for (const mode of ["personal", "managed"] as const) {
      const error = await failure({ mode, ungoverned: true }, ["--yolo"]);
      expect(error?.code).toBe("CONFIG_INVALID");
      expect(error?.message).toContain("declares no policy");
      expect(stateCreated()).toBe(false);
    }
  });
});

describe("--help", () => {
  const help = async (kind: Kind) => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => {
      lines.push(line);
    });
    await launch(kind, ["--help"]);
    return lines.join("\n");
  };

  it("documents --yolo for a personal distribution", async () => {
    const text = await help(PERSONAL);
    expect(text).toContain("[--new-session] [--yolo] [--smoke]");
    expect(text).toContain(
      "--yolo approves every ask without a prompt for this session only, audited; deny still applies",
    );
  });

  it("documents --yolo where a managed distribution allows it", async () => {
    const text = await help(MANAGED_ALLOWED);
    expect(text).toContain("[--yolo]");
    expect(text).toContain(
      "--yolo approves asks from the distribution defaults without a prompt for this session only, audited; deny and enforced rules still apply",
    );
  });

  it("does not offer --yolo where it cannot work", async () => {
    for (const kind of [
      { mode: "managed" } as Kind,
      { mode: "managed", userAuto: "off" } as Kind,
      { mode: "personal", ungoverned: true } as Kind,
    ])
      expect(await help(kind)).not.toContain("--yolo");
  });
});
