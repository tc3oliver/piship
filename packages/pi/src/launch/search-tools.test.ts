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
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import type { DistributionLock, LockedSearchTools } from "@piship/core";
import { afterEach, describe, expect, it } from "vitest";
import type { DoctorData } from "../doctor/data.js";
import { supplyChainGroup } from "../doctor/supply-chain.js";
import { piAgentDirectory, preparePiEnvironment } from "../environment.js";
import {
  deferredToolDownloads,
  installSearchTools,
  piToolDirectory,
  searchToolStatus,
  toolsPiWouldDownload,
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
          deployment: { mode: "personal" },
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

describe("the receipt of a verified tool (no hashing at start)", () => {
  it("reads neither executable at a start that finds the receipt's fingerprint", () => {
    const target = "linux-x64";
    const { dir, lock } = payload(target);
    const agentDir = join(temp(), "agent");
    installSearchTools(lock, dir, agentDir, target);
    expect(
      existsSync(join(piToolDirectory(agentDir), ".piship-search-tools.json")),
    ).toBe(true);
    // Break the payload copies: a start that read them would refuse them.
    writeFileSync(join(dir, "tools", "fd"), "tampered\n");
    writeFileSync(join(dir, "tools", "rg"), "tampered\n");
    expect(() => installSearchTools(lock, dir, agentDir, target)).not.toThrow();
    expect(
      searchToolStatus(lock, agentDir, target).map((item) => item.pinned),
    ).toEqual([true, true]);
  });

  it("checks the digest again once an executable is rewritten to the same size", () => {
    const target = "linux-x64";
    const { dir, lock } = payload(target);
    const agentDir = join(temp(), "agent");
    installSearchTools(lock, dir, agentDir, target);
    const path = join(piToolDirectory(agentDir), "fd");
    const before = statSync(path);
    // Same size and, to the millisecond, the same modification time.
    writeFileSync(path, "xx 10.5.0 for linux-x64\n");
    utimesSync(path, before.atime, before.mtime);
    expect(statSync(path).size).toBe(before.size);
    installSearchTools(lock, dir, agentDir, target);
    expect(readFileSync(path, "utf8")).toBe("fd 10.5.0 for linux-x64\n");
  });

  it("verifies a copy that has no receipt and then records it", () => {
    const target = "linux-x64";
    const { dir, lock } = payload(target);
    const agentDir = join(temp(), "agent");
    const bin = piToolDirectory(agentDir);
    mkdirSync(bin, { recursive: true });
    for (const name of ["fd", "rg"])
      writeFileSync(join(bin, name), readFileSync(join(dir, "tools", name)), {
        mode: 0o755,
      });
    const before = statSync(join(bin, "fd")).mtimeMs;
    installSearchTools(lock, dir, agentDir, target);
    expect(statSync(join(bin, "fd")).mtimeMs).toBe(before);
    expect(existsSync(join(bin, ".piship-search-tools.json"))).toBe(true);
  });

  it("ignores a damaged receipt", () => {
    const target = "linux-x64";
    const { dir, lock } = payload(target);
    const agentDir = join(temp(), "agent");
    installSearchTools(lock, dir, agentDir, target);
    writeFileSync(
      join(piToolDirectory(agentDir), ".piship-search-tools.json"),
      "{",
    );
    expect(installSearchTools(lock, dir, agentDir, target)).toHaveLength(2);
  });
});

describe("tools Pi would download at startup", () => {
  /** A PATH directory and an agent directory, with the given executables in each. */
  function layout(
    onPath: Record<string, string>,
    inBin: Record<string, string> = {},
  ) {
    const bin = temp();
    const agentDir = join(temp(), "agent");
    mkdirSync(piToolDirectory(agentDir), { recursive: true });
    for (const [name, mode] of Object.entries(onPath))
      writeFileSync(join(bin, name), "tool\n", {
        mode: Number.parseInt(mode, 8),
      });
    for (const [name, mode] of Object.entries(inBin))
      writeFileSync(join(piToolDirectory(agentDir), name), "tool\n", {
        mode: Number.parseInt(mode, 8),
      });
    return { agentDir, env: { PATH: `${temp()}${delimiter}${bin}` } };
  }

  it("is nothing when each tool is on PATH or in Pi's tool directory, and fdfind counts for fd", () => {
    const both = layout({ fd: "755", rg: "755" });
    expect(toolsPiWouldDownload(both.agentDir, both.env, "linux")).toEqual([]);
    const split = layout({ fdfind: "755" }, { rg: "755" });
    expect(toolsPiWouldDownload(split.agentDir, split.env, "linux")).toEqual(
      [],
    );
  });

  it("names the tools that are in neither place, and does not count a file that cannot run", () => {
    const only = layout({ fd: "755" });
    expect(toolsPiWouldDownload(only.agentDir, only.env, "linux")).toEqual([
      "rg",
    ]);
    const noMode = layout({ fd: "644", rg: "644" });
    if (process.platform !== "win32")
      expect(
        toolsPiWouldDownload(noMode.agentDir, noMode.env, "linux"),
      ).toEqual(["fd", "rg"]);
    const none = layout({});
    expect(toolsPiWouldDownload(none.agentDir, { PATH: "" }, "linux")).toEqual([
      "fd",
      "rg",
    ]);
  });

  it("looks for <name>.exe on Windows, as Pi starts the program with no shell", () => {
    const exe = layout({ "fd.exe": "644", "rg.cmd": "644" });
    const env = { PATH: exe.env.PATH.split(delimiter).join(";") };
    expect(toolsPiWouldDownload(exe.agentDir, env, "win32")).toEqual(["rg"]);
  });

  const personal = { deployment: { mode: "personal" } } as never;
  const lockWith = (extra: object) =>
    ({ ...(personal as object), ...extra }) as never;

  it("is deferred for a personal distribution that bundles nothing", () => {
    const missing = layout({});
    expect(
      deferredToolDownloads(personal, missing.agentDir, missing.env, "linux"),
    ).toEqual(["fd", "rg"]);
  });

  it.each([
    [
      "a distribution that bundles the tools",
      lockWith({ searchTools: {} }),
      {},
    ],
    [
      "a managed launch, which is offline already",
      { deployment: { mode: "managed" } } as never,
      {},
    ],
    ["Pi already offline", personal, { PI_OFFLINE: "1" }],
    [
      "the user's choice to let Pi download",
      personal,
      { PISHIP_ALLOW_TOOL_DOWNLOAD: "1" },
    ],
  ])("is not deferred for %s", (_name, lock, extra) => {
    const missing = layout({});
    expect(
      deferredToolDownloads(
        lock,
        missing.agentDir,
        { ...missing.env, ...extra },
        "linux",
      ),
    ).toEqual([]);
  });

  it("is not deferred when nothing would be downloaded", () => {
    const present = layout({ fd: "755", rg: "755" });
    expect(
      deferredToolDownloads(personal, present.agentDir, present.env, "linux"),
    ).toEqual([]);
  });
});

describe("doctor on a personal distribution with no tools", () => {
  it("warns that a launch will skip the download Pi would wait for", () => {
    const lines: string[] = [];
    const record = (kind: string) => (label: string, value: string) =>
      lines.push(`${kind} ${label}: ${value}`);
    const out = {
      ok: record("ok"),
      warn: record("warn"),
      bad: record("bad"),
      info: record("info"),
    };
    const data = {
      ctx: {
        agentDir: join(temp(), "agent"),
        metadata: {
          deployment: { mode: "personal" },
          manifest: { schema: "piship/v1alpha6" },
          schema: "piship-lock/v1alpha6",
        },
      },
    } as unknown as DoctorData;
    const saved = {
      PATH: process.env.PATH,
      PI_OFFLINE: process.env.PI_OFFLINE,
    };
    process.env.PATH = "";
    delete process.env.PI_OFFLINE;
    try {
      supplyChainGroup(data, out);
    } finally {
      for (const [key, value] of Object.entries(saved))
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
    }
    expect(
      lines.find((line) => line.startsWith("warn search tools")),
    ).toContain("fd and rg not found");
  });
});
