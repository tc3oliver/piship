// A problem with the bundled fd or rg is a warning, not a failure: it cannot
// block `--version`, and it is reported without running an unverified
// executable.
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DistributionLock, LockedSearchTools } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { preparePiEnvironment } from "../environment.js";
import { launchPiDistribution, PINNED_PI_VERSION } from "../index.js";
import {
  installSearchTools,
  piToolDirectory,
  searchToolProblemNotice,
} from "./search-tools.js";

const target = `${process.platform}-${process.arch}`;
const exe = process.platform === "win32" ? ".exe" : "";
const codeOf = (error: unknown) =>
  (error as { code?: string } | undefined)?.code;
const sha = (content: string) =>
  `sha256-${createHash("sha256").update(content).digest("hex")}`;

let temp: string;
const saved = {
  home: process.env.PISHIP_STATE_HOME,
  agentDir: process.env.PI_CODING_AGENT_DIR,
};
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-search-launch-"));
  process.env.PISHIP_STATE_HOME = join(temp, "state");
});
afterEach(() => {
  vi.restoreAllMocks();
  if (saved.home === undefined) delete process.env.PISHIP_STATE_HOME;
  else process.env.PISHIP_STATE_HOME = saved.home;
  if (saved.agentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
  else process.env.PI_CODING_AGENT_DIR = saved.agentDir;
  rmSync(temp, { recursive: true, force: true });
});

/**
 * A payload for this platform's target; `lockedAs` is what the lock says the
 * `fd` and `rg` contents are, `files` what the payload holds (`null` leaves
 * a file out).
 */
function payload(
  options: {
    /** The tool the lock lists for another platform only. */
    unlocked?: "fd" | "rg";
    files?: Partial<Record<"fd" | "rg", string | null>>;
    locked?: Partial<Record<"fd" | "rg", string>>;
  } = {},
) {
  const dir = join(temp, "payload");
  mkdirSync(join(dir, "tools"), { recursive: true });
  const tools: Record<string, LockedSearchTools[keyof LockedSearchTools]> = {};
  for (const tool of ["fd", "rg"] as const) {
    const content = `${tool} for ${target}\n`;
    const held = options.files?.[tool];
    if (held !== null) {
      writeFileSync(join(dir, "tools", `${tool}${exe}`), held ?? content);
    }
    tools[tool] = {
      version: "1.0.0",
      source: `https://github.com/upstream/${tool}`,
      targets: {
        [options.unlocked === tool ? "plan9-mips" : target]: {
          url: `https://github.com/upstream/${tool}/${tool}.tar.gz`,
          archive: sha("archive"),
          entry: `${tool}/${tool}${exe}`,
          binary: sha(options.locked?.[tool] ?? content),
          size: content.length,
        },
      },
    };
  }
  return {
    dir,
    lock: { searchTools: tools } as Pick<DistributionLock, "searchTools">,
  };
}

function metadataFor(lock: Pick<DistributionLock, "searchTools">) {
  return {
    app: {
      id: "acmecode",
      command: "acmecode",
      name: "AcmeCode",
      version: "1.2.3",
    },
    runtime: {
      package: "@earendil-works/pi-coding-agent",
      version: PINNED_PI_VERSION,
      pishipVersion: "0.0.0",
    },
    deployment: { mode: "managed" },
    ...lock,
  } as unknown as DistributionLock;
}

async function version(
  lock: Pick<DistributionLock, "searchTools">,
  dir: string,
) {
  const agentDir = preparePiEnvironment("acmecode");
  const out: string[] = [];
  const err: string[] = [];
  vi.spyOn(console, "log").mockImplementation((message) => {
    out.push(String(message));
  });
  vi.spyOn(console, "error").mockImplementation((message) => {
    err.push(String(message));
  });
  await launchPiDistribution({
    distributionDir: dir,
    metadata: metadataFor(lock),
    args: ["--version"],
  });
  return { out: out.join("\n"), err: err.join("\n"), agentDir };
}

describe("--version with a bundled search tool problem", () => {
  it("prints the version and leaves the tool directory alone when the lock has no entry for the target", async () => {
    const { dir, lock } = payload({ unlocked: "rg" });
    const { out, err, agentDir } = await version(lock, dir);
    expect(out).toContain("AcmeCode 1.2.3");
    expect(err).toBe("");
    expect(existsSync(piToolDirectory(agentDir))).toBe(false);
  });

  it("prints the version when a payload executable does not match the lock", async () => {
    const { dir, lock } = payload({ files: { rg: "tampered\n" } });
    const { out, err } = await version(lock, dir);
    expect(out).toContain("AcmeCode 1.2.3");
    expect(err).toBe("");
  });
});

describe("a bundled search tool problem is a warning at start", () => {
  const problems = (
    lock: Pick<DistributionLock, "searchTools">,
    dir: string,
    agentDir: string,
  ) => {
    const found: [string, unknown][] = [];
    const installed = installSearchTools(
      lock,
      dir,
      agentDir,
      target,
      (tool, error) => found.push([tool, error]),
    );
    return { found, installed };
  };

  it("skips a tool the lock has no entry for and still installs the other", () => {
    const { dir, lock } = payload({ unlocked: "rg" });
    const agentDir = join(temp, "agent");
    const { found, installed } = problems(lock, dir, agentDir);
    expect(installed.map((item) => item.tool)).toEqual(["fd"]);
    expect(found.map(([tool]) => tool)).toEqual(["rg"]);
    expect(codeOf(found[0]?.[1])).toBe("LOCK_INVALID");
    expect(existsSync(join(agentDir, "bin", `fd${exe}`))).toBe(true);
  });

  it("skips a tool whose payload file is missing instead of failing with a raw ENOENT", () => {
    const { dir, lock } = payload({ files: { fd: null } });
    const agentDir = join(temp, "agent");
    const { found, installed } = problems(lock, dir, agentDir);
    expect(installed.map((item) => item.tool)).toEqual(["rg"]);
    expect(found.map(([tool]) => tool)).toEqual(["fd"]);
    expect(codeOf(found[0]?.[1])).toBe("ENOENT");
    expect(searchToolProblemNotice("fd", found[0]?.[1])).toMatch(
      /^Warning: the bundled fd is not available \(.*ENOENT.*\)\. This start goes on without it/,
    );
  });

  it("never installs or leaves in place an executable that does not match the lock", () => {
    const { dir, lock } = payload({ files: { rg: "tampered\n" } });
    const agentDir = join(temp, "agent");
    const bin = piToolDirectory(agentDir);
    mkdirSync(bin, { recursive: true });
    // What Pi would run before anything on PATH.
    writeFileSync(join(bin, `rg${exe}`), "an old rg\n", { mode: 0o755 });
    const { found, installed } = problems(lock, dir, agentDir);
    expect(installed.map((item) => item.tool)).toEqual(["fd"]);
    expect(codeOf(found[0]?.[1])).toBe("INTEGRITY_FAILED");
    expect(existsSync(join(bin, `rg${exe}`))).toBe(false);
    expect(searchToolProblemNotice("rg", found[0]?.[1])).toContain(
      "does not match piship.lock, so it was not run or installed",
    );
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "skips both tools when the agent directory is read-only",
    () => {
      const { dir, lock } = payload();
      const agentDir = join(temp, "agent");
      mkdirSync(join(agentDir, "bin"), { recursive: true });
      chmodSync(join(agentDir, "bin"), 0o500);
      try {
        const { found, installed } = problems(lock, dir, agentDir);
        expect(installed).toEqual([]);
        expect(found.map(([tool]) => tool)).toEqual(["fd", "rg"]);
      } finally {
        chmodSync(join(agentDir, "bin"), 0o700);
      }
    },
  );

  it("still throws without a problem handler", () => {
    const { dir, lock } = payload({ files: { fd: null } });
    expect(() =>
      installSearchTools(lock, dir, join(temp, "agent"), target),
    ).toThrow(/ENOENT/);
    expect(readFileSync(join(dir, "tools", `rg${exe}`), "utf8")).toContain(
      "rg",
    );
  });
});
