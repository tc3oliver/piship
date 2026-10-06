// A bundled tool swapped for another file while its fingerprint is taken must
// not be recorded as the verified one. The swap happens right after the
// descriptor's content was read, which is where checking the path afterwards
// (the earlier order) would have blessed whatever was found there.
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DistributionLock } from "@piship/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installSearchTools } from "./search-tools.js";

const hook = vi.hoisted(() => ({
  after: undefined as (() => void) | undefined,
  /** Runs after the second `fstat` of a descriptor: the verification is over. */
  verified: undefined as (() => void) | undefined,
  stats: new Map<number, number>(),
}));

vi.mock("node:fs", async (original) => {
  const actual = await original<typeof import("node:fs")>();
  return {
    ...actual,
    fstatSync: ((fd: number, ...rest: unknown[]) => {
      const stat = (actual.fstatSync as (...args: unknown[]) => unknown)(
        fd,
        ...rest,
      );
      const count = (hook.stats.get(fd) ?? 0) + 1;
      hook.stats.set(fd, count);
      if (count === 2 && hook.verified) {
        const run = hook.verified;
        hook.verified = undefined;
        run();
      }
      return stat;
    }) as typeof actual.fstatSync,
    readFileSync: ((target: fs.PathOrFileDescriptor, ...rest: unknown[]) => {
      const data = (actual.readFileSync as (...args: unknown[]) => unknown)(
        target,
        ...rest,
      );
      // A read through a descriptor is the verification's own.
      if (typeof target === "number" && hook.after) {
        const run = hook.after;
        hook.after = undefined;
        run();
      }
      return data;
    }) as typeof actual.readFileSync,
  };
});

const roots: string[] = [];
afterEach(() => {
  hook.after = undefined;
  hook.verified = undefined;
  hook.stats.clear();
  for (const root of roots.splice(0))
    fs.rmSync(root, { recursive: true, force: true });
});

const sha = (content: string) =>
  `sha256-${createHash("sha256").update(content).digest("hex")}`;

function setup() {
  const root = fs.mkdtempSync(join(tmpdir(), "piship-pi-swap-"));
  roots.push(root);
  const target = `${process.platform}-${process.arch}`;
  const exe = process.platform === "win32" ? ".exe" : "";
  const genuine = {
    fd: `fd 10.5.0 for ${target}\n`,
    rg: `rg 15.2.0 for ${target}\n`,
  };
  fs.mkdirSync(join(root, "payload", "tools"), { recursive: true });
  const bin = join(root, "agent", "bin");
  fs.mkdirSync(bin, { recursive: true });
  const tools: Record<string, unknown> = {};
  for (const tool of ["fd", "rg"] as const) {
    fs.writeFileSync(
      join(root, "payload", "tools", `${tool}${exe}`),
      genuine[tool],
      {
        mode: 0o755,
      },
    );
    // Already in place, as after an earlier install: only its receipt is missing.
    fs.writeFileSync(join(bin, `${tool}${exe}`), genuine[tool], {
      mode: 0o755,
    });
    tools[tool] = {
      version: "1",
      source: "https://example.test",
      targets: {
        [target]: {
          url: "https://example.test/archive",
          archive: sha("archive"),
          entry: `${tool}${exe}`,
          binary: sha(genuine[tool]),
          size: genuine[tool].length,
        },
      },
    };
  }
  const lock = { searchTools: tools } as unknown as Pick<
    DistributionLock,
    "searchTools"
  >;
  const run = () =>
    installSearchTools(
      lock,
      join(root, "payload"),
      join(root, "agent"),
      target,
    );
  return { bin, exe, genuine, run, root };
}

describe.runIf(process.platform !== "win32")(
  "a tool that changes while it is verified",
  () => {
    it("is not trusted when another file is swapped in after its content was read: the replaced file's own change time shows it, and the pinned copy is put back", () => {
      const { bin, genuine, run, root } = setup();
      hook.after = () => {
        const evil = join(root, "evil");
        fs.writeFileSync(evil, "evil\n", { mode: 0o755 });
        fs.renameSync(evil, join(bin, "fd"));
      };
      run();
      expect(fs.readFileSync(join(bin, "fd"), "utf8")).toBe(genuine.fd);
      expect(fs.readFileSync(join(bin, "rg"), "utf8")).toBe(genuine.rg);
    });

    it("records the file that was hashed, so one swapped in once the verification is over is not the recorded one and is replaced at the next start", () => {
      const { bin, genuine, run, root } = setup();
      hook.verified = () => {
        const evil = join(root, "evil");
        fs.writeFileSync(evil, "evil\n", { mode: 0o755 });
        fs.renameSync(evil, join(bin, "fd"));
      };
      run();
      // Nothing can tell at this start; the receipt must not name this file.
      expect(fs.readFileSync(join(bin, "fd"), "utf8")).toBe("evil\n");
      run();
      expect(fs.readFileSync(join(bin, "fd"), "utf8")).toBe(genuine.fd);
      expect(fs.readFileSync(join(bin, "rg"), "utf8")).toBe(genuine.rg);
    });

    it("is not recorded when the file is edited in place while it is read, and is restored", () => {
      const { bin, genuine, run } = setup();
      hook.after = () => fs.appendFileSync(join(bin, "rg"), "tampered\n");
      run();
      expect(fs.readFileSync(join(bin, "rg"), "utf8")).toBe(genuine.rg);
      expect(fs.readFileSync(join(bin, "fd"), "utf8")).toBe(genuine.fd);
    });

    it("records a tool nothing touched, and then starts without reading it", () => {
      const { bin, run } = setup();
      run();
      expect(fs.existsSync(join(bin, ".piship-search-tools.json"))).toBe(true);
      let reads = 0;
      hook.after = () => {
        reads += 1;
      };
      run();
      expect(reads).toBe(0);
    });
  },
);
