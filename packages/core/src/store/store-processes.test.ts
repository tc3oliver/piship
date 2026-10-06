// Several processes install from one store at once, as two installs or an
// install and an update of different distributions can: every tree is
// complete and right, every object is intact, and nothing is left behind.
import { spawn } from "node:child_process";
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { verifyStore } from "./collect.js";
import { storeLayout } from "./store.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const STORE = pathToFileURL(
  fileURLToPath(new URL("../../dist/store/store.js", import.meta.url)),
).href;

const CHILD = `
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
const { ContentStore } = await import(process.argv[1]);
const [, , root, primitive, tree, files, distinct] = process.argv;
const store = ContentStore.open(root, { primitive });
const jobs = [];
for (let index = 0; index < Number(files); index += 1) {
  const text = "file " + (index % Number(distinct)) + " ".repeat(index % 5);
  const output = join(tree, "node_modules", "pkg" + (index % 30), "f" + index + ".js");
  mkdirSync(dirname(output), { recursive: true });
  const data = Buffer.from(text);
  jobs.push(store.place({
    path: "node_modules/pkg" + (index % 30) + "/f" + index + ".js",
    data,
    digest: createHash("sha256").update(data).digest("hex"),
    output,
    exec: false,
  }));
}
const placed = (await Promise.all(jobs)).filter(Boolean).length;
store.end();
process.stdout.write(JSON.stringify({ placed, counts: store.counts }));
`;

function child(
  root: string,
  primitive: string,
  tree: string,
  files: number,
  distinct: number,
): Promise<{ placed: number }> {
  return new Promise((resolve, reject) => {
    const process_ = spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        CHILD,
        STORE,
        root,
        primitive,
        tree,
        String(files),
        String(distinct),
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    let err = "";
    process_.stdout.on("data", (chunk) => {
      out += chunk;
    });
    process_.stderr.on("data", (chunk) => {
      err += chunk;
    });
    process_.on("close", (status) =>
      status === 0
        ? resolve(JSON.parse(out) as { placed: number })
        : reject(new Error(`child ${status}: ${err}`)),
    );
  });
}

describe("several installs filling and reading one store", () => {
  it.each(["copy", "hardlink"] as const)(
    "leave every tree right and every object intact (%s)",
    async (primitive) => {
      const home = mkdtempSync(join(tmpdir(), "piship-store-processes-"));
      roots.push(home);
      const root = join(home, "store");
      const files = 240;
      const distinct = 40;
      // Every child is awaited even when one fails, so cleanup never runs
      // under a child that is still writing, and the failure names its stderr.
      const outcomes = await Promise.allSettled(
        [0, 1, 2, 3].map((index) =>
          child(root, primitive, join(home, `tree${index}`), files, distinct),
        ),
      );
      const failure = outcomes.find((outcome) => outcome.status === "rejected");
      if (failure) throw (failure as PromiseRejectedResult).reason;
      const results = outcomes.map(
        (outcome) =>
          (outcome as PromiseFulfilledResult<{ placed: number }>).value,
      );
      expect(results.map((result) => result.placed)).toEqual([
        files,
        files,
        files,
        files,
      ]);
      for (const index of [0, 1, 2, 3])
        for (let file = 0; file < files; file += 1)
          expect(
            readFileSync(
              join(
                home,
                `tree${index}`,
                "node_modules",
                `pkg${file % 30}`,
                `f${file}.js`,
              ),
              "utf8",
            ),
          ).toBe(`file ${file % distinct}${" ".repeat(file % 5)}`);
      const layout = storeLayout(root);
      const verified = verifyStore({ root });
      expect(verified.damaged).toEqual([]);
      expect(verified.checked).toBeLessThanOrEqual(distinct * 5);
      expect(readdirSync(layout.temporary)).toEqual([]);
      expect(readdirSync(layout.inflight)).toEqual([]);
      // Whoever won the race for an object, it is read-only and whole.
      const sample = readdirSync(layout.objects)[0] as string;
      const object = join(
        layout.objects,
        sample,
        readdirSync(join(layout.objects, sample))[0] as string,
      );
      if (process.platform !== "win32")
        expect(statSync(object).mode & 0o222).toBe(0);
    },
    60_000,
  );
});
