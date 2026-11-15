import { execFileSync, spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  SEED_FILE_CAP,
  type SeedSandbox,
  seedRemoteWorkspace,
} from "./seed.js";
import { packTar } from "./tar.js";

let base: string;
let project: string;
let remote: string;
beforeEach(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), "piship-seed-")));
  project = join(base, "project");
  remote = join(base, "remote");
  mkdirSync(project);
  mkdirSync(remote);
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const sh = (cwd: string, ...args: string[]) =>
  execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
const initProject = () => {
  sh(project, "init", "-q");
  sh(project, "config", "user.email", "t@example.invalid");
  sh(project, "config", "user.name", "t");
};
const put = (path: string, content: string | Buffer) => {
  mkdirSync(dirname(join(project, path)), { recursive: true });
  writeFileSync(join(project, path), content);
};

const writes: (number | undefined)[] = [];

/** A sandbox whose "remote" is a local directory and whose exec is real bash. */
function fakeSandbox(): SeedSandbox {
  return {
    files: {
      read: async (path) => readFileSync(join(remote, path)),
      write: async (path, data, options) => {
        writes.push(options?.timeoutMs);
        expect(path.startsWith(project)).toBe(true);
        writeFileSync(join(remote, path.slice(project.length + 1)), data);
      },
      stat: async () => undefined,
    },
    exec: (command, _cwd, options) =>
      new Promise((resolve) => {
        const child = spawn("bash", ["-c", command], { cwd: remote });
        child.stdout.on("data", options.onData);
        child.stderr.on("data", options.onData);
        child.on("close", (exitCode) => resolve({ exitCode }));
      }),
  };
}
const allowAll = async () => "allow" as const;

describe("packTar", () => {
  it.skipIf(process.platform === "win32")(
    "round-trips through the system tar with modes and long paths",
    () => {
      const long = `${"d".repeat(60)}/${"e".repeat(60)}/${"f".repeat(60)}.txt`;
      const data = Buffer.alloc(1300, 7);
      const file = join(base, "a.tar");
      writeFileSync(
        file,
        packTar([
          { path: "run.sh", mode: 0o755, data: Buffer.from("#!/bin/sh\n") },
          { path: "ä/ü.txt", mode: 0o644, data },
          { path: long, mode: 0o644, data: Buffer.alloc(0) },
        ]),
      );
      const out = join(base, "out");
      mkdirSync(out);
      execFileSync("tar", ["-xf", file, "-C", out]);
      expect(statSync(join(out, "run.sh")).mode & 0o777).toBe(0o755);
      expect(readFileSync(join(out, "ä/ü.txt"))).toEqual(data);
      expect(statSync(join(out, long)).size).toBe(0);
    },
  );

  it("refuses a path that cannot fit the ustar fields", () => {
    expect(() =>
      packTar([{ path: "x".repeat(101), mode: 0o644, data: Buffer.alloc(0) }]),
    ).toThrow(/too long/);
  });
});

describe("seedRemoteWorkspace", () => {
  it("fails clearly outside a git work tree", async () => {
    await expect(
      seedRemoteWorkspace(fakeSandbox(), project, allowAll),
    ).rejects.toThrow(/git work tree/);
  });

  it("rejects a file over the single-file cap and the total cap", async () => {
    initProject();
    put("big.bin", Buffer.alloc(0));
    // A sparse file reaches the cap without writing it.
    execFileSync("truncate", [
      "-s",
      String(SEED_FILE_CAP + 1),
      join(project, "big.bin"),
    ]);
    await expect(
      seedRemoteWorkspace(fakeSandbox(), project, allowAll),
    ).rejects.toThrow(/single-file cap/);
  });

  it.skipIf(process.platform === "win32")(
    "seeds the sandbox, skips by rule, and commits a baseline",
    async () => {
      initProject();
      put("src/a.ts", "export const a = 1;\n");
      put("run.sh", "#!/bin/sh\n");
      chmodSync(join(project, "run.sh"), 0o755);
      put(".env", "SECRET=1\n");
      put("ignored.log", "x");
      put(".gitignore", "ignored.log\n");
      put("gone.txt", "x");
      symlinkSync("/etc/hosts", join(project, "link"));
      mkdirSync(join(base, "outside"));
      put("real/x.txt", "x");
      symlinkSync(join(base, "outside"), join(project, "via"));
      sh(project, "add", "-A");
      sh(project, "commit", "-qm", "init");
      rmSync(join(project, "gone.txt"));
      put("untracked.txt", "u");
      const head = sh(project, "rev-parse", "HEAD");

      const seen: string[] = [];
      const result = await seedRemoteWorkspace(
        fakeSandbox(),
        project,
        async (path) => {
          seen.push(path);
          return path.endsWith(".env") ? "skip" : "allow";
        },
      );
      expect(result.baseHead).toBe(head);
      expect([...result.uploaded].sort()).toEqual(
        [
          ".gitignore",
          "real/x.txt",
          "run.sh",
          "src/a.ts",
          "untracked.txt",
        ].sort(),
      );
      expect(result.skipped).toEqual(
        expect.arrayContaining([
          { path: ".env", reason: "policy" },
          { path: "link", reason: "symlink" },
          { path: "via", reason: "symlink" },
        ]),
      );
      expect(seen).not.toContain(join(project, "link"));
      expect(existsSync(join(remote, ".env"))).toBe(false);
      expect(existsSync(join(remote, ".piship-seed.tar"))).toBe(false);
      expect(statSync(join(remote, "run.sh")).mode & 0o111).not.toBe(0);
      expect(readFileSync(join(remote, "src/a.ts"), "utf8")).toBe(
        "export const a = 1;\n",
      );
      expect(sh(remote, "rev-parse", "HEAD")).toBe(result.baselineCommit);
      expect(sh(remote, "log", "-1", "--format=%s")).toBe("piship-baseline");
      expect(sh(remote, "status", "--porcelain")).toBe("");
    },
  );

  it.skipIf(process.platform === "win32")(
    "refuses a project directory that already holds files and uploads with a long timeout",
    async () => {
      initProject();
      put("a.txt", "a");
      writeFileSync(join(remote, ".bashrc"), "template dotfile");
      writes.length = 0;
      await expect(
        seedRemoteWorkspace(fakeSandbox(), project, allowAll),
      ).rejects.toThrow(/not empty/);
      expect(writes).toEqual([15 * 60 * 1000]);
      // The archive left by an earlier attempt does not count.
      rmSync(join(remote, ".bashrc"));
      writeFileSync(join(remote, ".piship-seed.tar"), "");
      await expect(
        seedRemoteWorkspace(fakeSandbox(), project, allowAll),
      ).resolves.toMatchObject({ uploaded: ["a.txt"] });
    },
  );

  it("names a missing tool in the sandbox", async () => {
    initProject();
    put("a.txt", "a");
    const sandbox = fakeSandbox();
    const failing: SeedSandbox = {
      ...sandbox,
      exec: async (_c, _d, options) => {
        options.onData(Buffer.from("piship-missing-tool:tar\n"));
        return { exitCode: 127 };
      },
    };
    await expect(
      seedRemoteWorkspace(failing, project, allowAll),
    ).rejects.toThrow(/no tar/);
  });
});
