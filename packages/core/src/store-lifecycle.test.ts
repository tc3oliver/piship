// The file store through the real install, update, rollback, uninstall, and
// maintenance paths: an installation is whole without it, a release's objects
// are pinned while it is active or the rollback target, an interrupted update
// never damages a live release, and a launch never opens the store.
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  HOST_EVIDENCED,
  ID,
  appsDir,
  installed,
  launch,
  receiptFile,
  rejection,
  useLifecycleHomes,
} from "../../../tests/helpers/lifecycle-faults.js";
import {
  extractArchive,
  maintainRuntimeStore,
  parseObjectName,
  rollbackDistribution,
  storeLayout,
  uninstallDistribution,
  updateDistribution,
  verifyPayload,
  verifyStore,
} from "./index.js";

useLifecycleHomes();

const KEYS = ["PISHIP_STORE", "PISHIP_STORE_HOME"] as const;
let saved: Record<string, string | undefined> = {};
let storeHome = "";
beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  storeHome = join(
    mkdtempSync(join(tmpdir(), "piship-lifecycle-store-")),
    "store",
  );
  process.env.PISHIP_STORE_HOME = storeHome;
  process.env.PISHIP_STORE = "copy";
});
afterEach(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  rmSync(join(storeHome, ".."), { recursive: true, force: true });
});

/** Every file under `directory`. */
function files(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(directory, entry.name))
      : [join(directory, entry.name)],
  );
}
const objects = () => files(storeLayout(storeHome).objects);
const references = () =>
  files(storeLayout(storeHome).refs).map((path) =>
    path.slice(storeHome.length),
  );

/** Make everything the store holds older than the grace period. */
function age(): void {
  const then = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
  for (const path of files(storeHome)) utimesSync(path, then, then);
}

describe.runIf(HOST_EVIDENCED)(
  "the file store in the installation lifecycle",
  () => {
    it("installs a release whole, with its shared files from the store and no reference to it", async () => {
      await installed();
      const tree = join(appsDir(), "1.0.0");
      expect(launch()).toBe("payload 1.0.0");
      verifyPayload(tree);
      // The runtime and dependency files are in the store; the distribution's
      // own files are not.
      const stored = objects().map((path) => readFileSync(path, "utf8"));
      expect(stored).toContain(
        readFileSync(
          join(tree, "node_modules", "alpha", "package.json"),
          "utf8",
        ),
      );
      expect(stored).not.toContain(
        readFileSync(join(tree, "bin", "acmepi"), "utf8"),
      );
      expect(stored.some((text) => text.includes("AcmePi"))).toBe(false);
      expect(references()).toEqual([
        expect.stringMatching(/acmepi.1\.0\.0\.json$/),
      ]);
      // The installed tree is its own files, and the receipt names no store.
      expect(
        lstatSync(join(tree, "node_modules", "alpha", "package.json")).nlink,
      ).toBe(1);
      expect(readFileSync(receiptFile(), "utf8")).not.toContain(storeHome);
    });

    it("installs and launches on a clean machine with an empty, a missing, or an unusable store", async () => {
      // Empty store, offline: the first install of this test is exactly that.
      await installed();
      verifyPayload(join(appsDir(), "1.0.0"));
      expect(launch()).toBe("payload 1.0.0");
      // The store removed after the install: nothing the release runs from.
      rmSync(storeHome, { recursive: true, force: true });
      expect(launch()).toBe("payload 1.0.0");
      verifyPayload(join(appsDir(), "1.0.0"));
    });

    it("installs when the store cannot be used at all", async () => {
      const blocker = join(storeHome, "..", "blocker");
      writeFileSync(blocker, "a file where the store's directory should be");
      process.env.PISHIP_STORE_HOME = join(blocker, "store");
      await installed();
      expect(launch()).toBe("payload 1.0.0");
      verifyPayload(join(appsDir(), "1.0.0"));
      expect(existsSync(join(blocker, "store"))).toBe(false);
    });

    it("does nothing with the store when it is off", async () => {
      process.env.PISHIP_STORE = "off";
      await installed();
      expect(existsSync(storeHome)).toBe(false);
      expect(launch()).toBe("payload 1.0.0");
    });

    it("refuses a value of PISHIP_STORE it does not know", async () => {
      process.env.PISHIP_STORE = "link";
      const error = await rejection(installed());
      expect(error.message).toMatch(/PISHIP_STORE=link is not one of/);
    });

    it("pins the active release and the rollback target, and releases neither to a collection", async () => {
      const { opts } = await installed();
      const update = await updateDistribution(ID, opts);
      expect(update).toMatchObject({ status: "updated", to: "1.1.0" });
      expect(references().sort()).toEqual([
        expect.stringMatching(/acmepi.1\.0\.0\.json$/),
        expect.stringMatching(/acmepi.1\.1\.0\.json$/),
      ]);
      age();
      const before = objects().length;
      // Both are pinned: the active 1.1.0 and the rollback 1.0.0.
      expect(maintainRuntimeStore()?.collected).toMatchObject({
        removedObjects: 0,
        removedReferences: 0,
      });
      expect(objects()).toHaveLength(before);
      const rolledBack = await rollbackDistribution(ID);
      expect(rolledBack).toMatchObject({ from: "1.1.0", to: "1.0.0" });
      age();
      expect(maintainRuntimeStore()?.collected.removedObjects).toBe(0);
      expect(maintainRuntimeStore()?.verified).toMatchObject({ damaged: [] });
      expect(launch()).toBe("payload 1.0.0");
    });

    it("collects the objects of an uninstalled distribution and leaves nothing installed to harm", async () => {
      await installed();
      expect(objects().length).toBeGreaterThan(0);
      uninstallDistribution(ID);
      // Uninstalling does not touch the store; only doctor's collection does.
      expect(objects().length).toBeGreaterThan(0);
      age();
      const result = maintainRuntimeStore()?.collected;
      expect(result?.removedReferences).toBe(1);
      expect(objects()).toEqual([]);
      expect(references()).toEqual([]);
    });

    it("keeps a live release intact when an update is interrupted, and discards only the update's own debris", async () => {
      const { opts } = await installed();
      const error = await rejection(
        updateDistribution(ID, {
          ...opts,
          faults: (phase) => {
            if (phase === "installed") throw new Error("power loss");
          },
        }),
      );
      expect(error.message).toBe("power loss");
      expect(launch()).toBe("payload 1.0.0");
      verifyPayload(join(appsDir(), "1.0.0"));
      // The update died before it recorded 1.1.0: its objects belong to no
      // release, and the live one is unaffected by whatever becomes of them.
      expect(references()).toEqual([
        expect.stringMatching(/acmepi.1\.0\.0\.json$/),
      ]);
      const before = objects();
      age();
      const result = maintainRuntimeStore();
      expect(result?.collected.removedReferences).toBe(0);
      expect(result?.verified).toMatchObject({ damaged: [] });
      expect(objects()).toEqual(before);
      // Every object the active release placed is still there and intact.
      const tree = join(appsDir(), "1.0.0");
      const needed = readFileSync(
        join(tree, "node_modules", "alpha", "package.json"),
        "utf8",
      );
      expect(objects().map((path) => readFileSync(path, "utf8"))).toContain(
        needed,
      );
      // A later update of the same version still succeeds.
      expect(await updateDistribution(ID, opts)).toMatchObject({
        status: "updated",
        to: "1.1.0",
      });
    });

    it("repairs a damaged object from the next install's own bytes, never installing the damaged ones", async () => {
      await installed();
      const [object] = objects();
      if (!object) throw new Error("no object");
      const original = readFileSync(object);
      rmSync(object);
      writeFileSync(object, Buffer.from(original).reverse());
      expect(verifyStore({ root: storeHome }).damaged).toHaveLength(1);
      uninstallDistribution(ID);
      await installed();
      expect(readFileSync(object)).toEqual(original);
      expect(verifyStore({ root: storeHome }).damaged).toEqual([]);
      verifyPayload(join(appsDir(), "1.0.0"));
    });

    it("shares by hard link only when asked, with the objects read-only", async () => {
      process.env.PISHIP_STORE = "hardlink";
      await installed();
      const tree = join(appsDir(), "1.0.0");
      const placed = join(tree, "node_modules", "alpha", "package.json");
      const stats = lstatSync(placed);
      if (stats.nlink > 1) {
        const object = objects().find(
          (path) => lstatSync(path).ino === stats.ino,
        );
        expect(object).toBeDefined();
        if (process.platform !== "win32" && process.getuid?.() !== 0) {
          expect(statSync(placed).mode & 0o222).toBe(0);
          expect(() => writeFileSync(placed, "tampered")).toThrow(
            /EACCES|EPERM/,
          );
        }
      }
      verifyPayload(tree);
      expect(launch()).toBe("payload 1.0.0");
      // Removing the store removes only a name; the installed file stays.
      rmSync(storeHome, { recursive: true, force: true });
      verifyPayload(tree);
      expect(parseObjectName("x")).toBeUndefined();
    });
  },
);
