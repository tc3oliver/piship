import {
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

// Run around the listing's read of a directory: a test swaps it there.
const hook = vi.hoisted(() => ({
  beforeRead: undefined as (() => void) | undefined,
  afterRead: undefined as (() => void) | undefined,
}));
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return {
    ...actual,
    readdir: (async (...args: Parameters<typeof actual.readdir>) => {
      hook.beforeRead?.();
      try {
        return await actual.readdir(...args);
      } finally {
        hook.afterRead?.();
      }
    }) as typeof actual.readdir,
  };
});

const { listDirectory } = await import("./governed-tools.js");

const roots: string[] = [];
afterEach(() => {
  hook.beforeRead = undefined;
  hook.afterRead = undefined;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("listDirectory", () => {
  // Windows will not rename a directory held open; it takes the macOS path.
  it.skipIf(process.platform === "win32")(
    "never lists a directory swapped in after the decision",
    async () => {
      const root = mkdtempSync(join(tmpdir(), "piship-list-"));
      roots.push(root);
      const listed = join(root, "listed");
      const secret = join(root, "secret");
      mkdirSync(listed);
      mkdirSync(secret);
      writeFileSync(join(listed, "a.txt"), "a");
      writeFileSync(join(secret, "id_rsa"), "key");
      const handle = await open(listed, "r");
      try {
        // The path names another directory while it is read.
        hook.beforeRead = () => {
          renameSync(listed, `${listed}.held`);
          symlinkSync(
            secret,
            listed,
            process.platform === "win32" ? "junction" : "dir",
          );
        };
        if (process.platform === "linux") {
          // Read through the descriptor, the swap does not reach it, even
          // when the decided directory is back by the time the path is checked.
          hook.afterRead = () => {
            rmSync(listed, { recursive: true });
            renameSync(`${listed}.held`, listed);
          };
          expect((await listDirectory(handle, listed)).toString()).toBe(
            "a.txt\n",
          );
        } else {
          // Read by path: a swap still in place afterwards is refused, not
          // listed. (Node cannot list by descriptor here, so a swap undone
          // within the read itself is not seen.)
          await expect(listDirectory(handle, listed)).rejects.toThrow(
            /changed while it was being listed/,
          );
        }
      } finally {
        await handle.close();
      }
    },
  );
});
