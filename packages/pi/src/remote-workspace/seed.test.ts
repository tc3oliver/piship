import { execFileSync, spawn } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  SEED_FILE_CAP,
  SeedRefused,
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
function fakeSandbox(path = process.env.PATH ?? ""): SeedSandbox {
  return {
    files: {
      read: async (path) =>
        readFileSync(join(remote, path.slice(project.length + 1))),
      write: async (path, data, options) => {
        writes.push(options?.timeoutMs);
        expect(path.startsWith(project)).toBe(true);
        writeFileSync(join(remote, path.slice(project.length + 1)), data);
      },
      stat: async () => undefined,
    },
    exec: (command, _cwd, options) =>
      new Promise((resolve) => {
        const child = spawn("/bin/bash", ["-c", command], {
          cwd: remote,
          env: { ...process.env, PATH: path },
        });
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
});

describe("seedRemoteWorkspace", () => {
  it("fails clearly outside a git work tree", async () => {
    await expect(
      seedRemoteWorkspace(fakeSandbox(), project, allowAll),
    ).rejects.toThrow(/git work tree/);
  });

  it.skipIf(process.platform === "win32")(
    "skips a file over the single-file cap and says how much it uploads",
    async () => {
      initProject();
      put("big.bin", Buffer.alloc(0));
      put("a.txt", "a");
      // A sparse file reaches the cap without writing it.
      const fd = openSync(join(project, "big.bin"), "r+");
      ftruncateSync(fd, SEED_FILE_CAP + 1);
      closeSync(fd);
      const progress: string[] = [];
      const result = await seedRemoteWorkspace(
        fakeSandbox(),
        project,
        allowAll,
        {
          progress: (message) => progress.push(message),
        },
      );
      expect(result.uploaded).toEqual(["a.txt"]);
      expect(result.skipped).toEqual([
        { path: "big.bin", reason: "too-large" },
      ]);
      expect(progress).toEqual([
        "Uploading to the sandbox: 1/1 parts, 0.0 of 0.0 MiB",
      ]);
    },
  );

  it.skipIf(process.platform === "win32")(
    "rejects a project over the total cap, counting only what policy allows",
    async () => {
      initProject();
      put("a.bin", Buffer.alloc(1024));
      put("b.bin", Buffer.alloc(1024));
      const caps = { totalCap: 1500, fileCap: 2048 };
      await expect(
        seedRemoteWorkspace(fakeSandbox(), project, allowAll, { caps }),
      ).rejects.toThrow(/1500 bytes total cap.*\.gitignore/);
      // A skipped file does not count towards it.
      await expect(
        seedRemoteWorkspace(
          fakeSandbox(),
          project,
          async (path) => (path.endsWith("b.bin") ? "skip" : "allow"),
          { caps },
        ),
      ).resolves.toMatchObject({ uploaded: ["a.bin"] });
    },
  );

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

  it.skipIf(process.platform === "win32")(
    "redoes its own unfinished seed but still refuses foreign files, leaving no marker behind",
    async () => {
      initProject();
      put("a.txt", "a");
      // What a seed that died after extracting leaves: files, a repo, the marker.
      writeFileSync(join(remote, ".piship-seed.started"), "");
      writeFileSync(join(remote, "stale.txt"), "stale");
      sh(remote, "init", "-q");
      const result = await seedRemoteWorkspace(
        fakeSandbox(),
        project,
        allowAll,
      );
      expect(result.uploaded).toEqual(["a.txt"]);
      expect(existsSync(join(remote, "stale.txt"))).toBe(false);
      expect(existsSync(join(remote, ".piship-seed.started"))).toBe(false);
      expect(sh(remote, "ls-files")).toBe("a.txt");
      expect(sh(remote, "status", "--porcelain")).toBe("");
    },
  );

  it.skipIf(process.platform === "win32")(
    "names the tool the sandbox lacks, running the real script",
    async () => {
      initProject();
      put("a.txt", "a");
      // A PATH with ls, grep, rm and tar, but no git.
      const bin = join(base, "bin");
      mkdirSync(bin);
      for (const tool of ["ls", "grep", "rm", "tar", "gzip"])
        symlinkSync(
          execFileSync("sh", ["-c", `command -v ${tool}`], {
            encoding: "utf8",
          }).trim(),
          join(bin, tool),
        );
      await expect(
        seedRemoteWorkspace(fakeSandbox(bin), project, allowAll),
      ).rejects.toThrow(/no git/);
    },
  );

  it.skipIf(process.platform === "win32")(
    "names gzip when the sandbox lacks it",
    async () => {
      initProject();
      put("a.txt", "a");
      const bin = join(base, "bin");
      mkdirSync(bin);
      for (const tool of ["ls", "grep", "rm", "tar", "git"])
        symlinkSync(
          execFileSync("sh", ["-c", `command -v ${tool}`], {
            encoding: "utf8",
          }).trim(),
          join(bin, tool),
        );
      await expect(
        seedRemoteWorkspace(fakeSandbox(bin), project, allowAll),
      ).rejects.toThrow(/no gzip/);
    },
  );

  it.skipIf(process.platform === "win32")(
    "uploads bounded gzip parts, and a failure in a later part is cleaned on retry",
    async () => {
      initProject();
      // Two 20 MiB files do not fit one 32 MiB part.
      put("a.bin", Buffer.alloc(20 * 1024 * 1024, 1));
      put("b.bin", Buffer.alloc(20 * 1024 * 1024, 2));
      put("c.txt", "c");
      const sizes: number[] = [];
      const real = fakeSandbox();
      let failSecond = true;
      const sandbox: SeedSandbox = {
        ...real,
        files: {
          ...real.files,
          write: async (path, data, options) => {
            expect([...data.subarray(0, 2)]).toEqual([0x1f, 0x8b]);
            sizes.push(data.length);
            if (sizes.length === 2 && failSecond) {
              failSecond = false;
              throw new Error("the connection dropped");
            }
            await real.files.write(path, data, options);
          },
        },
      };
      await expect(
        seedRemoteWorkspace(sandbox, project, allowAll),
      ).rejects.toThrow(/connection dropped/);
      // Part 1 was extracted and the marker says the seed did not finish.
      expect(existsSync(join(remote, "a.bin"))).toBe(true);
      expect(existsSync(join(remote, ".piship-seed.started"))).toBe(true);
      const progress: string[] = [];
      sizes.length = 0;
      const result = await seedRemoteWorkspace(sandbox, project, allowAll, {
        progress: (message) => progress.push(message),
      });
      expect(sizes).toHaveLength(2);
      for (const bytes of sizes) expect(bytes).toBeLessThan(1024 * 1024);
      expect(progress).toEqual([
        "Uploading to the sandbox: 1/2 parts, 20.0 of 40.0 MiB",
        "Uploading to the sandbox: 2/2 parts, 40.0 of 40.0 MiB",
      ]);
      expect([...result.uploaded].sort()).toEqual(["a.bin", "b.bin", "c.txt"]);
      expect(existsSync(join(remote, ".piship-seed.started"))).toBe(false);
      expect(existsSync(join(remote, ".piship-seed.tar"))).toBe(false);
      expect(sh(remote, "ls-files").split("\n").sort()).toEqual([
        "a.bin",
        "b.bin",
        "c.txt",
      ]);
      expect(sh(remote, "status", "--porcelain")).toBe("");
    },
    30_000,
  );

  it("leaves out a file deleted after it was scanned", async () => {
    initProject();
    put("a.txt", "aaa");
    put("b.txt", "bbb");
    let archive = Buffer.alloc(0);
    const sandbox: SeedSandbox = {
      ...fakeSandbox(),
      files: {
        ...fakeSandbox().files,
        write: async (_path, data) => {
          archive = gunzipSync(data);
        },
      },
      exec: async () => ({ exitCode: 1 }),
    };
    let decided = 0;
    await expect(
      seedRemoteWorkspace(sandbox, project, async () => {
        if (++decided === 2) rmSync(join(project, "a.txt"));
        return "allow";
      }),
    ).rejects.toThrow(/seeding the sandbox failed/);
    expect(archive.includes("bbb")).toBe(true);
    expect(archive.includes("aaa")).toBe(false);
  });

  it.skipIf(process.platform === "win32")(
    "stores LF in the sandbox when the host checks out CRLF, so an LF rewrite changes only its lines",
    async () => {
      // This machine's own git config must not decide the case.
      const global = process.env.GIT_CONFIG_GLOBAL;
      process.env.GIT_CONFIG_GLOBAL = "/dev/null";
      try {
        for (const autocrlf of ["true", "false"]) {
          rmSync(project, { recursive: true, force: true });
          rmSync(remote, { recursive: true, force: true });
          mkdirSync(project);
          mkdirSync(remote);
          initProject();
          sh(project, "config", "core.autocrlf", autocrlf);
          put("a.txt", "one\ntwo\nthree\n");
          sh(project, "add", "-A");
          sh(project, "commit", "-qm", "base");
          rmSync(join(project, "a.txt"));
          sh(project, "checkout", "--", "a.txt");
          await seedRemoteWorkspace(fakeSandbox(), project, allowAll);
          writeFileSync(join(remote, "a.txt"), "ONE\ntwo\nthree\n");
          expect(sh(remote, "diff", "--numstat")).toBe("1\t1\ta.txt");
          expect(
            sh(remote, "config", "--default", "unset", "core.autocrlf"),
          ).toBe(autocrlf === "true" ? "input" : "unset");
        }
      } finally {
        if (global === undefined) delete process.env.GIT_CONFIG_GLOBAL;
        else process.env.GIT_CONFIG_GLOBAL = global;
      }
    },
  );

  it("takes a tracked file's mode from git's index, on any platform", async () => {
    initProject();
    put("gradlew", "#!/bin/sh\n");
    put("plain.txt", "p");
    sh(project, "add", "-A");
    sh(project, "update-index", "--chmod=+x", "gradlew");
    // Whatever the disk says, the index decides a tracked file.
    let archive: Buffer = Buffer.alloc(0);
    const sandbox: SeedSandbox = {
      ...fakeSandbox(),
      files: {
        ...fakeSandbox().files,
        write: async (_path, data) => {
          archive = gunzipSync(data);
        },
      },
      exec: async () => ({ exitCode: 1 }),
    };
    await seedRemoteWorkspace(sandbox, project, allowAll).catch(() => {});
    const mode = (name: string) => {
      const at = archive.indexOf(Buffer.from(name));
      return Number.parseInt(
        archive.subarray(at + 100, at + 107).toString(),
        8,
      );
    };
    expect(mode("gradlew")).toBe(0o755);
    expect(mode("plain.txt")).toBe(0o644);
  });

  it.skipIf(process.platform === "win32")(
    "adds a withheld file to the baseline later without folding in the agent's staged work",
    async () => {
      initProject();
      put("a.txt", "a\n");
      put("ask.txt", "ask\n");
      const sandbox = fakeSandbox();
      const seeded = await seedRemoteWorkspace(
        sandbox,
        project,
        async (path) => (path.endsWith("ask.txt") ? "skip" : "allow"),
      );
      const first = seeded.baselineCommit;
      const lookup = seeded.lookup;
      expect(lookup?.skipped(join(project, "ask.txt"))).toBe("policy");
      // Work the agent did, already staged by a checkpoint.
      writeFileSync(join(remote, "agent.txt"), "work\n");
      sh(remote, "add", "-A");
      await lookup?.adopt(join(project, "ask.txt"));
      expect(seeded.baselineCommit).not.toBe(first);
      expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe("ask\n");
      expect(lookup?.skipped(join(project, "ask.txt"))).toBeUndefined();
      sh(remote, "add", "-A");
      expect(
        sh(remote, "diff", "--cached", "--name-only", seeded.baselineCommit),
      ).toBe("agent.txt");
      writeFileSync(join(remote, "ask.txt"), "changed\n");
      sh(remote, "add", "-A");
      expect(
        sh(remote, "diff", "--cached", "--name-only", seeded.baselineCommit)
          .split("\n")
          .sort(),
      ).toEqual(["agent.txt", "ask.txt"]);
    },
  );

  it.skipIf(process.platform === "win32")(
    "finishes an adopt whose call is cancelled after the upload: the baseline exec ignores the signal",
    async () => {
      initProject();
      put("a.txt", "a\n");
      put("ask.txt", "ask\n");
      const abort = new AbortController();
      const base = fakeSandbox();
      // Esc lands once the file is uploaded; a cancelled exec throws, as the
      // governed sandbox's does.
      const sandbox: SeedSandbox = {
        ...base,
        files: {
          ...base.files,
          write: async (path, data, options) => {
            await base.files.write(path, data, options);
            if (path.endsWith("ask.txt")) abort.abort();
          },
        },
        exec: (command, cwd, options) =>
          options.signal?.aborted
            ? Promise.reject(new Error("aborted"))
            : base.exec(command, cwd, options),
      };
      const seeded = await seedRemoteWorkspace(
        sandbox,
        project,
        async (path) => (path.endsWith("ask.txt") ? "skip" : "allow"),
      );
      await seeded.lookup?.adopt(join(project, "ask.txt"), abort.signal);
      expect(seeded.lookup?.skipped(join(project, "ask.txt"))).toBeUndefined();
      sh(remote, "add", "-A");
      expect(
        sh(remote, "diff", "--cached", "--name-only", seeded.baselineCommit),
      ).toBe("");
    },
  );

  it.skipIf(process.platform === "win32")(
    "sends nothing for an adopt cancelled before the upload, and keeps the file withheld",
    async () => {
      initProject();
      put("a.txt", "a\n");
      put("ask.txt", "ask\n");
      const seeded = await seedRemoteWorkspace(
        fakeSandbox(),
        project,
        async (path) => (path.endsWith("ask.txt") ? "skip" : "allow"),
      );
      const abort = new AbortController();
      abort.abort();
      await expect(
        seeded.lookup?.adopt(join(project, "ask.txt"), abort.signal),
      ).rejects.toThrow();
      expect(existsSync(join(remote, "ask.txt"))).toBe(false);
      expect(seeded.lookup?.skipped(join(project, "ask.txt"))).toBe("policy");
    },
  );

  it.skipIf(process.platform === "win32")(
    "makes the baseline again when an adopt's baseline failed after the upload, so the file never reads as the agent's",
    async () => {
      initProject();
      put("a.txt", "a\n");
      put("ask.txt", "ask\n");
      const base = fakeSandbox();
      let failBaseline = true;
      const sandbox: SeedSandbox = {
        ...base,
        files: {
          ...base.files,
          stat: async (path) =>
            existsSync(join(remote, path.slice(project.length + 1)))
              ? { type: "file", size: 0 }
              : undefined,
        },
        exec: (command, cwd, options) => {
          if (failBaseline && command.includes("piship-baseline.idx")) {
            failBaseline = false;
            return Promise.resolve({ exitCode: 1 });
          }
          return base.exec(command, cwd, options);
        },
      };
      const seeded = await seedRemoteWorkspace(
        sandbox,
        project,
        async (path) => (path.endsWith("ask.txt") ? "skip" : "allow"),
      );
      const first = seeded.baselineCommit;
      await expect(
        seeded.lookup?.adopt(join(project, "ask.txt")),
      ).rejects.toThrow(/copying ask\.txt into the sandbox failed/);
      // The upload landed and its baseline did not, so the upload was removed.
      expect(existsSync(join(remote, "ask.txt"))).toBe(false);
      expect(seeded.baselineCommit).toBe(first);
      expect(seeded.lookup?.skipped(join(project, "ask.txt"))).toBe("policy");
      await seeded.lookup?.adopt(join(project, "ask.txt"));
      expect(seeded.baselineCommit).not.toBe(first);
      expect(seeded.lookup?.skipped(join(project, "ask.txt"))).toBeUndefined();
      sh(remote, "add", "-A");
      expect(
        sh(remote, "diff", "--cached", "--name-only", seeded.baselineCommit),
      ).toBe("");
    },
  );

  it.skipIf(process.platform === "win32")(
    "keeps the agent's own file on a retry after a failed adopt baseline, and never folds host content into it",
    async () => {
      initProject();
      put("a.txt", "a\n");
      put("ask.txt", "host secret\n");
      const base = fakeSandbox();
      let failBaseline = true;
      const sandbox: SeedSandbox = {
        ...base,
        files: {
          ...base.files,
          stat: async (path) =>
            existsSync(join(remote, path.slice(project.length + 1)))
              ? { type: "file", size: 0 }
              : undefined,
        },
        exec: (command, cwd, options) => {
          if (failBaseline && command.includes("piship-baseline.idx")) {
            failBaseline = false;
            return Promise.resolve({ exitCode: 1 });
          }
          return base.exec(command, cwd, options);
        },
      };
      const seeded = await seedRemoteWorkspace(
        sandbox,
        project,
        async (path) => (path.endsWith("ask.txt") ? "skip" : "allow"),
      );
      const first = seeded.baselineCommit;
      await expect(
        seeded.lookup?.adopt(join(project, "ask.txt")),
      ).rejects.toThrow();
      // The agent writes its own file there before the read is retried.
      writeFileSync(join(remote, "ask.txt"), "agent\n");
      await seeded.lookup?.adopt(join(project, "ask.txt"));
      expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe("agent\n");
      // Not baselined: the patch holds the agent's file, never the host's.
      expect(seeded.baselineCommit).toBe(first);
      sh(remote, "add", "-A");
      expect(
        sh(remote, "diff", "--cached", "--name-only", seeded.baselineCommit),
      ).toBe("ask.txt");
      expect(
        sh(remote, "diff", "--cached", seeded.baselineCommit),
      ).not.toContain("host secret");
    },
  );

  it.skipIf(process.platform === "win32")(
    "removes a partly written adopt and treats what is left as its own on the retry",
    async () => {
      initProject();
      put("a.txt", "a\n");
      put("ask.txt", "host secret, all of it\n");
      const base = fakeSandbox();
      let partial = true;
      let removable = true;
      const sandbox: SeedSandbox = {
        ...base,
        files: {
          ...base.files,
          stat: async (path) =>
            existsSync(join(remote, path.slice(project.length + 1)))
              ? { type: "file", size: 0 }
              : undefined,
          // The upload dies halfway, leaving a truncated copy.
          write: async (path, data, options) => {
            if (partial && path.endsWith("ask.txt")) {
              partial = false;
              await base.files.write(path, data.subarray(0, 4), options);
              throw new Error("connection reset");
            }
            await base.files.write(path, data, options);
          },
        },
        // The first clean-up fails too, as on a dropped connection.
        exec: (command, cwd, options) => {
          if (command.startsWith("rm -f") && removable === false)
            return Promise.reject(new Error("connection reset"));
          return base.exec(command, cwd, options);
        },
      };
      const seeded = await seedRemoteWorkspace(
        sandbox,
        project,
        async (path) => (path.endsWith("ask.txt") ? "skip" : "allow"),
      );
      const first = seeded.baselineCommit;
      removable = false;
      await expect(
        seeded.lookup?.adopt(join(project, "ask.txt")),
      ).rejects.toThrow(/connection reset/);
      // The clean-up failed: the truncated copy is still there.
      expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe("host");
      expect(seeded.lookup?.skipped(join(project, "ask.txt"))).toBe("policy");
      removable = true;
      await seeded.lookup?.adopt(join(project, "ask.txt"));
      expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe(
        "host secret, all of it\n",
      );
      expect(seeded.baselineCommit).not.toBe(first);
      sh(remote, "add", "-A");
      expect(
        sh(remote, "diff", "--cached", "--name-only", seeded.baselineCommit),
      ).toBe("");
    },
  );

  it.skipIf(process.platform === "win32")(
    "removes the upload when an adopt fails, so a never-retried file stays out of the patch",
    async () => {
      initProject();
      put("a.txt", "a\n");
      put("ask.txt", "host secret\n");
      const base = fakeSandbox();
      let partial = true;
      const sandbox: SeedSandbox = {
        ...base,
        files: {
          ...base.files,
          write: async (path, data, options) => {
            if (partial && path.endsWith("ask.txt")) {
              partial = false;
              await base.files.write(path, data.subarray(0, 4), options);
              throw new Error("connection reset");
            }
            await base.files.write(path, data, options);
          },
        },
      };
      const seeded = await seedRemoteWorkspace(
        sandbox,
        project,
        async (path) => (path.endsWith("ask.txt") ? "skip" : "allow"),
      );
      await expect(
        seeded.lookup?.adopt(join(project, "ask.txt")),
      ).rejects.toThrow(/connection reset/);
      expect(existsSync(join(remote, "ask.txt"))).toBe(false);
      sh(remote, "add", "-A");
      expect(
        sh(remote, "diff", "--cached", "--name-only", seeded.baselineCommit),
      ).toBe("");
    },
  );

  /** A sandbox with a real stat, and hooks into the adopt's write and execs. */
  const adoptSandbox = (hooks: {
    write?: (data: Buffer) => Promise<"ok" | "partial" | "fail">;
    exec?: (command: string) => Promise<number | "throw" | undefined>;
  }): SeedSandbox => {
    const base = fakeSandbox();
    return {
      ...base,
      files: {
        ...base.files,
        stat: async (path) =>
          existsSync(join(remote, path.slice(project.length + 1)))
            ? { type: "file", size: 0 }
            : undefined,
        read: async (path) => {
          const file = join(remote, path.slice(project.length + 1));
          if (!existsSync(file))
            throw Object.assign(new Error("no such file"), { code: "ENOENT" });
          return readFileSync(file);
        },
        write: async (path, data, options) => {
          const how =
            path.endsWith("ask.txt") && hooks.write
              ? await hooks.write(data)
              : "ok";
          if (how === "fail") throw new Error("connection reset");
          await base.files.write(
            path,
            how === "partial" ? data.subarray(0, 4) : data,
            options,
          );
          if (how === "partial") throw new Error("connection reset");
        },
      },
      exec: async (command, cwd, options) => {
        const answer = await hooks.exec?.(command);
        if (answer === "throw") throw new Error("connection reset");
        if (typeof answer === "number") return { exitCode: answer };
        return base.exec(command, cwd, options);
      },
    };
  };
  const seedWithheld = async (sandbox: SeedSandbox) => {
    initProject();
    put("a.txt", "a\n");
    put("ask.txt", "host secret\n");
    return seedRemoteWorkspace(sandbox, project, async (path) =>
      path.endsWith("ask.txt") ? "skip" : "allow",
    );
  };
  const staged = (baseline: string) => {
    sh(remote, "add", "-A");
    return sh(remote, "diff", "--cached", baseline);
  };

  it.skipIf(process.platform === "win32")(
    "does not overwrite the agent's file made after a failed write was removed",
    async () => {
      let first = true;
      const seeded = await seedWithheld(
        adoptSandbox({
          write: async () => {
            const how = first ? "partial" : "ok";
            first = false;
            return how;
          },
        }),
      );
      await expect(
        seeded.lookup?.adopt(join(project, "ask.txt")),
      ).rejects.toThrow();
      expect(existsSync(join(remote, "ask.txt"))).toBe(false);
      writeFileSync(join(remote, "ask.txt"), "agent\n");
      await seeded.lookup?.adopt(join(project, "ask.txt"));
      expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe("agent\n");
      expect(staged(seeded.baselineCommit)).not.toContain("host secret");
    },
  );

  it.skipIf(process.platform === "win32")(
    "does not delete a file the agent changed while the adopt's baseline was failing",
    async () => {
      const seeded = await seedWithheld(
        adoptSandbox({
          exec: async (command) => {
            if (!command.includes("piship-baseline.idx")) return undefined;
            writeFileSync(join(remote, "ask.txt"), "agent\n");
            return 1;
          },
        }),
      );
      await expect(
        seeded.lookup?.adopt(join(project, "ask.txt")),
      ).rejects.toThrow();
      expect(readFileSync(join(remote, "ask.txt"), "utf8")).toBe("agent\n");
    },
  );

  // Every way an adopt can fail, and what the agent does before the retry:
  // the agent's content is never overwritten or deleted, the withheld host
  // content never enters the patch as an addition, and an untouched file ends
  // up baselined once the faults are gone.
  const matrix = (["ok", "partial", "fail"] as const).flatMap((write) =>
    (["ok", "fail"] as const).flatMap((baseline) =>
      (["ok", "fail"] as const).flatMap((rm) =>
        (["writes", "deletes", "untouched"] as const).map(
          (agent) => [write, baseline, rm, agent] as const,
        ),
      ),
    ),
  );
  it.skipIf(process.platform === "win32").each(matrix)(
    "adopt: write %s, baseline %s, removal %s, agent %s before the retry",
    async (write, baseline, rm, agent) => {
      let faults = true;
      const seeded = await seedWithheld(
        adoptSandbox({
          write: async () => (faults ? write : "ok"),
          exec: async (command) => {
            if (!faults) return undefined;
            if (baseline === "fail" && command.includes("piship-baseline.idx"))
              return 1;
            if (rm === "fail" && command.startsWith("rm -f")) return "throw";
            return undefined;
          },
        }),
      );
      const ask = join(project, "ask.txt");
      const file = join(remote, "ask.txt");
      const hostAdded = () => /^\+host/m.test(staged(seeded.baselineCommit));
      const firstOk = await seeded.lookup?.adopt(ask).then(
        () => true,
        () => false,
      );
      expect(firstOk).toBe(write === "ok" && baseline === "ok");
      // Only a removal that failed can leave a host copy behind.
      if (rm === "ok") expect(hostAdded()).toBe(false);
      if (agent === "writes") writeFileSync(file, "agent\n");
      if (agent === "deletes") rmSync(file, { force: true });
      faults = false;
      await seeded.lookup?.adopt(ask);
      expect(seeded.lookup?.skipped(ask)).toBeUndefined();
      expect(hostAdded()).toBe(false);
      if (agent === "writes")
        expect(readFileSync(file, "utf8")).toBe("agent\n");
      else if (agent === "untouched" || !firstOk) {
        expect(readFileSync(file, "utf8")).toBe("host secret\n");
        expect(staged(seeded.baselineCommit)).toBe("");
      }
    },
  );

  it.skipIf(process.platform === "win32")(
    "overlays over a seeded tree with awkward names, removing only what is neither uploaded nor ignored",
    async () => {
      initProject();
      const awkward = [
        "sp ace.txt",
        "-dash.txt",
        "q'uote.txt",
        "nl\nname.txt",
        "ü/é.txt",
      ];
      for (const name of awkward) put(name, "v1\n");
      put("keep.txt", "k\n");
      put(".gitignore", "node_modules/\n");
      sh(project, "add", "-A");
      sh(project, "commit", "-qm", "init");
      await seedRemoteWorkspace(fakeSandbox(), project, allowAll);
      // What a setup command left, and a stray file that is not ignored.
      mkdirSync(join(remote, "node_modules"));
      writeFileSync(join(remote, "node_modules", "dep.js"), "dep\n");
      writeFileSync(join(remote, "stray.txt"), "stray\n");
      writeFileSync(join(remote, "-stray.txt"), "stray\n");
      writeFileSync(join(remote, "nl\nstray.txt"), "stray\n");
      // The host moved on: two awkward files gone, one changed.
      rmSync(join(project, "-dash.txt"));
      rmSync(join(project, "nl\nname.txt"));
      put("sp ace.txt", "v2\n");
      const result = await seedRemoteWorkspace(
        fakeSandbox(),
        project,
        allowAll,
        {
          mode: "overlay",
        },
      );
      const present = (name: string) => existsSync(join(remote, name));
      expect(present("-dash.txt")).toBe(false);
      expect(present("nl\nname.txt")).toBe(false);
      expect(present("stray.txt")).toBe(false);
      expect(present("-stray.txt")).toBe(false);
      expect(present("nl\nstray.txt")).toBe(false);
      expect(readFileSync(join(remote, "sp ace.txt"), "utf8")).toBe("v2\n");
      expect(
        present("q'uote.txt") && present("ü/é.txt") && present("keep.txt"),
      ).toBe(true);
      expect(readFileSync(join(remote, "node_modules", "dep.js"), "utf8")).toBe(
        "dep\n",
      );
      expect(present(".piship-seed.keep")).toBe(false);
      expect(present(".piship-seed.started")).toBe(false);
      // A fresh baseline: one commit, naming exactly the uploaded files.
      expect(sh(remote, "rev-list", "--count", "HEAD")).toBe("1");
      expect(sh(remote, "rev-parse", "HEAD")).toBe(result.baselineCommit);
      expect(sh(remote, "status", "--porcelain")).toBe("");
      expect(
        execFileSync("git", ["ls-tree", "-r", "-z", "--name-only", "HEAD"], {
          cwd: remote,
          encoding: "utf8",
        })
          .split("\0")
          .filter(Boolean)
          .sort(),
      ).toEqual([...result.uploaded].sort());
    },
  );

  it.skipIf(process.platform === "win32")(
    "resets a sandbox an overlay left half done, and then seeds it as a fresh one",
    async () => {
      initProject();
      put("a.txt", "a\n");
      sh(project, "add", "-A");
      sh(project, "commit", "-qm", "init");
      mkdirSync(join(remote, "node_modules"));
      writeFileSync(join(remote, "left.txt"), "left over\n");
      await expect(
        seedRemoteWorkspace(fakeSandbox(), project, allowAll),
      ).rejects.toThrow(/not empty/);
      await seedRemoteWorkspace(fakeSandbox(), project, allowAll, {
        mode: "reset",
      });
      expect(existsSync(join(remote, "left.txt"))).toBe(false);
      expect(sh(remote, "ls-files")).toBe("a.txt");
    },
  );

  describe.skipIf(process.platform === "win32")("overlay of a snapshot", () => {
    const seedOnce = async () => {
      initProject();
      put("keep.txt", "k\n");
      put("secret.txt", "tracked\n");
      sh(project, "add", "-A");
      sh(project, "commit", "-qm", "init");
      put(".env", "SECRET=1\n"); // untracked, not yet ignored
      await seedRemoteWorkspace(fakeSandbox(), project, allowAll);
      expect(existsSync(join(remote, ".env"))).toBe(true);
    };

    it("removes a file the snapshot's seed uploaded and the new one does not, even when it is now ignored", async () => {
      await seedOnce();
      put(".gitignore", ".env\n");
      await seedRemoteWorkspace(fakeSandbox(), project, allowAll, {
        mode: "overlay",
      });
      expect(existsSync(join(remote, ".env"))).toBe(false);
      expect(existsSync(join(remote, "keep.txt"))).toBe(true);
      expect(sh(remote, "status", "--porcelain")).toBe("");
      expect(existsSync(join(remote, ".git", "piship-uploaded.json"))).toBe(
        true,
      );
    });

    it("removes a tracked file that is now ignored and withheld by a tighter policy", async () => {
      await seedOnce();
      put(".gitignore", "secret.txt\n");
      const decide = async (path: string) =>
        path.endsWith("secret.txt") ? ("skip" as const) : ("allow" as const);
      await seedRemoteWorkspace(fakeSandbox(), project, decide, {
        mode: "overlay",
      });
      expect(existsSync(join(remote, "secret.txt"))).toBe(false);
      expect(existsSync(join(remote, ".env"))).toBe(true);
    });

    it.each([
      ["missing", undefined],
      ["not JSON", "{oops"],
      ["the wrong shape", '{"version":1,"paths":"x"}'],
      ["an unsafe path", '{"version":1,"paths":["../x"]}'],
    ])(
      "refuses an overlay when the list is %s, so the caller resets",
      async (_name, content) => {
        await seedOnce();
        const list = join(remote, ".git", "piship-uploaded.json");
        if (content === undefined) rmSync(list);
        else writeFileSync(list, content);
        const error = await seedRemoteWorkspace(
          fakeSandbox(),
          project,
          allowAll,
          {
            mode: "overlay",
          },
        ).catch((e: unknown) => e);
        expect(error).toBeInstanceOf(Error);
        expect(error).not.toBeInstanceOf(SeedRefused);
        expect(existsSync(join(remote, ".env"))).toBe(true); // untouched until the reset
      },
    );
  });

  it.skipIf(process.platform === "win32")(
    "uploads a file whose name no ustar field holds",
    async () => {
      initProject();
      const name = `${"n".repeat(150)}.txt`;
      put(name, "long\n");
      sh(project, "add", "-A");
      sh(project, "commit", "-qm", "init");
      const result = await seedRemoteWorkspace(
        fakeSandbox(),
        project,
        allowAll,
      );
      expect(result.uploaded).toContain(name);
      expect(readFileSync(join(remote, name), "utf8")).toBe("long\n");
    },
  );
});
