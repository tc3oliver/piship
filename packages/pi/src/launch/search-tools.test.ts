// Launch-time discovery of bundled fd and rg: the payload's verified
// executables go into Pi's own tool directory (<agent dir>/bin), which Pi
// checks before PATH, with the Linux and Windows file names.
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DistributionLock, LockedSearchTools } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import { piAgentDirectory, preparePiEnvironment } from "../environment.js";
import { supplyChainGroup } from "../doctor/supply-chain.js";
import type { DoctorData } from "../doctor/data.js";
import {
  installSearchTools,
  piToolDirectory,
  searchToolStatus,
} from "./search-tools.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function temp(): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-pi-search-"));
  roots.push(dir);
  return dir;
}
const sha = (content: string) =>
  `sha256-${createHash("sha256").update(content).digest("hex")}`;

/** A payload holding bundled tools for one target, and its lock entries. */
function payload(target: string) {
  const dir = temp();
  const exe = target.startsWith("win32-") ? ".exe" : "";
  const tools: Record<string, LockedSearchTools[keyof LockedSearchTools]> = {};
  mkdirSync(join(dir, "tools"));
  for (const [tool, version] of [
    ["fd", "10.5.0"],
    ["rg", "15.2.0"],
  ] as const) {
    const content = `${tool} ${version} for ${target}\n`;
    writeFileSync(join(dir, "tools", `${tool}${exe}`), content, {
      mode: 0o755,
    });
    tools[tool] = {
      version,
      source: `https://github.com/upstream/${tool}`,
      targets: {
        [target]: {
          url: `https://github.com/upstream/${tool}/${tool}.tar.gz`,
          archive: sha("archive"),
          entry: `${tool}/${tool}${exe}`,
          binary: sha(content),
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

describe("bundled search tools at launch", () => {
  it.each([
    ["linux-x64", ["fd", "rg"]],
    ["win32-x64", ["fd.exe", "rg.exe"]],
  ])("puts the %s executables in Pi's tool directory", (target, names) => {
    const { dir, lock } = payload(target);
    const agentDir = join(temp(), "agent");
    const installed = installSearchTools(lock, dir, agentDir, target);
    expect(installed.map((item) => item.path)).toEqual(
      names.map((name) => join(agentDir, "bin", name)),
    );
    for (const name of names) {
      const path = join(piToolDirectory(agentDir), name);
      expect(readFileSync(path, "utf8")).toBe(
        readFileSync(join(dir, "tools", name), "utf8"),
      );
      if (process.platform !== "win32")
        expect(statSync(path).mode & 0o111).toBe(0o111);
    }
    expect(
      searchToolStatus(lock, agentDir, target).map((item) => item.pinned),
    ).toEqual([true, true]);
  });

  it("replaces a different executable, link, or directory in Pi's tool directory, and keeps an identical copy", () => {
    const target = "linux-x64";
    const { dir, lock } = payload(target);
    const agentDir = join(temp(), "agent");
    const bin = piToolDirectory(agentDir);
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "fd"), "a user's own fd\n", { mode: 0o755 });
    if (process.platform !== "win32")
      symlinkSync("/usr/bin/true", join(bin, "rg"));
    else mkdirSync(join(bin, "rg"));
    expect(
      searchToolStatus(lock, agentDir, target).map((item) => item.pinned),
    ).toEqual([false, false]);
    installSearchTools(lock, dir, agentDir, target);
    expect(readFileSync(join(bin, "fd"), "utf8")).toBe(
      "fd 10.5.0 for linux-x64\n",
    );
    expect(lstatSync(join(bin, "rg")).isFile()).toBe(true);
    const before = statSync(join(bin, "fd")).mtimeMs;
    installSearchTools(lock, dir, agentDir, target);
    expect(statSync(join(bin, "fd")).mtimeMs).toBe(before);
  });

  it("refuses a payload executable that does not match the lock", () => {
    const target = "linux-x64";
    const { dir, lock } = payload(target);
    writeFileSync(join(dir, "tools", "rg"), "tampered\n");
    const agentDir = join(temp(), "agent");
    expect(() => installSearchTools(lock, dir, agentDir, target)).toThrow(
      /does not match piship\.lock/,
    );
    expect(existsSync(join(agentDir, "bin", "rg"))).toBe(false);
  });

  it("does nothing for a distribution without bundled tools", () => {
    const agentDir = join(temp(), "agent");
    expect(installSearchTools({}, temp(), agentDir)).toEqual([]);
    expect(existsSync(join(agentDir, "bin"))).toBe(false);
  });

  it("points Pi's agent directory at the distribution's state", () => {
    const env: NodeJS.ProcessEnv = {};
    const agentDir = preparePiEnvironment("acmecode", env);
    expect(agentDir).toBe(piAgentDirectory("acmecode"));
    expect(env.PI_CODING_AGENT_DIR).toBe(agentDir);
    expect(agentDir.endsWith(join("acmecode", "agent"))).toBe(true);
  });

  it("doctor reports each bundled tool and fails when Pi's copy is not the pinned one", () => {
    const target = `${process.platform}-${process.arch}`;
    const { dir, lock } = payload(target);
    const agentDir = join(temp(), "agent");
    installSearchTools(lock, dir, agentDir, target);
    const lines: string[] = [];
    const out = {
      ok: (label: string, value: string) => lines.push(`ok ${label}: ${value}`),
      warn: (label: string, value: string) =>
        lines.push(`warn ${label}: ${value}`),
      bad: (label: string, value: string) =>
        lines.push(`bad ${label}: ${value}`),
      info: (label: string, value: string) =>
        lines.push(`info ${label}: ${value}`),
    };
    const data = {
      ctx: {
        agentDir,
        metadata: {
          ...lock,
          manifest: { schema: "piship/v1alpha6" },
          schema: "piship-lock/v1alpha6",
        },
      },
    } as unknown as DoctorData;
    supplyChainGroup(data, out);
    expect(lines.filter((line) => line.includes("search tool"))).toEqual([
      "ok search tool fd: 10.5.0 bundled; Pi runs it from its tool directory before PATH",
      "ok search tool rg: 15.2.0 bundled; Pi runs it from its tool directory before PATH",
    ]);
    const exe = process.platform === "win32" ? ".exe" : "";
    writeFileSync(join(agentDir, "bin", `rg${exe}`), "replaced\n");
    lines.length = 0;
    supplyChainGroup(data, out);
    expect(
      lines.find((line) => line.startsWith("bad search tool rg")),
    ).toContain("does not hold the pinned executable");
  });
});
