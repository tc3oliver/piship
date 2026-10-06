// A file that has all the links the file system allows (NTFS: 1023) cannot be
// linked again. The placement must give that file its own copy and go on
// linking the rest, whatever code the platform reports for it.
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const failure = vi.hoisted(() => ({ code: "EMLINK", remaining: 0 }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    link: async (existing: string, created: string) => {
      if (failure.remaining > 0) {
        failure.remaining--;
        throw Object.assign(new Error(`${failure.code}: too many links`), {
          code: failure.code,
        });
      }
      return actual.link(existing, created);
    },
  };
});

const { ContentStore } = await import("./store.js");

const roots: string[] = [];
afterEach(() => {
  failure.remaining = 0;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe.each(["EMLINK", "UNKNOWN"])(
  "a file that cannot take another link (%s)",
  (code) => {
    it("is copied on its own, and the next files are still linked", async () => {
      failure.code = code;
      failure.remaining = 1;
      const home = mkdtempSync(join(tmpdir(), "piship-store-limit-"));
      roots.push(home);
      const store = ContentStore.open(join(home, "store"), {
        primitive: "hardlink",
      });
      if (!store) throw new Error("the store did not open");
      const data = Buffer.from("shared bytes");
      const digest = createHash("sha256").update(data).digest("hex");
      const outputs = ["a", "b", "c"].map((name) =>
        join(home, name, "index.js"),
      );
      for (const output of outputs) {
        mkdirSync(join(output, ".."), { recursive: true });
        expect(
          await store.place({
            path: "node_modules/pkg/index.js",
            data,
            digest,
            output,
            exec: false,
          }),
        ).toBe(true);
      }
      store.end();
      for (const output of outputs)
        expect(readFileSync(output, "utf8")).toBe("shared bytes");
      expect(store.counts.copied).toBe(1);
      expect(store.counts.linked).toBe(2);
      expect(store.counts.declined).toBe(0);
      const object = store.objectPath(digest, false);
      expect(lstatSync(object).nlink).toBe(3);
      expect(lstatSync(outputs[0] as string).ino).not.toBe(
        lstatSync(object).ino,
      );
    });
  },
);
