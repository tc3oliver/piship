import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  KEY_ID,
  personalScenario,
  scan,
  target,
} from "../helpers/lifecycle.js";
import { trapProxy } from "../helpers/trap-proxy.js";

// The shared file store (docs/security.md, "Shared file store") on the
// installed branded command, with real release archives: an install, an
// update, and a rollback that place their runtime and dependency files from a
// store, and the guarantees the store makes about itself.
//
// - A machine with an empty store installs and launches exactly as one with a
//   full store, and with no store at all. The release archive carries no
//   store reference, and neither the installed tree nor the install state
//   names the store, so removing it changes nothing about what runs.
// - Install, update, and launch contact nothing: the scenario's update host
//   sees no request until `update` is asked for, and a proxy that would
//   refuse every outbound request sees none. This is what PiShip does, not a
//   network namespace; "offline" here means that no step needs the network.
// - `doctor` is the only collector. With every store file older than the grace
//   period, it still keeps what the active release and the rollback target
//   pinned, and the installed releases keep launching.
//
// The stand-in for a clean machine is an empty temporary home, state, install
// home, and store, on the runner; it is not a fresh operating system image.

/** Every file under `directory`. */
function files(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? files(join(directory, entry.name))
      : [join(directory, entry.name)],
  );
}

/** The store's file objects. */
const objects = (store: string) => files(join(store, "objects"));

/** The references that name the releases that placed objects. */
const references = (store: string) =>
  files(join(store, "refs")).map((path) =>
    path
      .slice(join(store, "refs").length + 1)
      .split("\\")
      .join("/"),
  );

/** Make every file of the store older than the 24-hour grace period. */
function age(store: string): void {
  const old = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
  for (const path of files(store)) utimesSync(path, old, old);
}

describe("shared file store on the installed command (local fixtures)", () => {
  it("installs, updates, rolls back, and diagnoses with a store, and keeps working with none", async () => {
    const s = await personalScenario("shared-store");
    const proxy = await trapProxy();
    const store = join(s.temp, "store");
    // An empty store directory, as on a machine that never had one.
    mkdirSync(store);
    Object.assign(s.env, {
      PISHIP_STORE: "copy",
      PISHIP_STORE_HOME: store,
      HTTP_PROXY: proxy.url,
      HTTPS_PROXY: proxy.url,
      http_proxy: proxy.url,
      https_proxy: proxy.url,
      NO_PROXY: "127.0.0.1,localhost,::1",
      no_proxy: "127.0.0.1,localhost,::1",
    });

    // Install from the empty store: the script shipped in the release fills it.
    await s.installFirst();
    expect(objects(store).length).toBeGreaterThan(0);
    expect(references(store)).toEqual(["mypi/1.0.0.json"]);
    // Nothing is left in flight, and no temporary remains.
    expect(files(join(store, "inflight"))).toEqual([]);
    expect(files(join(store, "tmp"))).toEqual([]);

    // The installation is whole and names no store: the receipts, the
    // launcher, the command, and every installed file are free of its path.
    expect(scan(s.install, [store])).toEqual([]);
    expect(scan(join(s.temp, "bin"), [store])).toEqual([]);
    const smoke = await s.run(["--smoke"]);
    expect(smoke.status, smoke.stderr).toBe(0);
    const doctor = await s.run(["doctor"]);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
    expect(doctor.stderr).not.toMatch(/damaged/);
    // Install and launch contacted no host: the update host is asked only by `update`.
    expect(s.hostRequests).toEqual([]);
    expect(proxy.hits).toEqual([]);

    // Update and rollback place from the same store and pin both releases.
    s.publish(1);
    const updated = await s.run(["update"]);
    expect(updated.status, updated.stderr).toBe(0);
    expect(updated.stdout).toContain(
      `Updated MyPi 1.0.0 -> 1.1.0 (stable, signed by ${KEY_ID})`,
    );
    expect(references(store).sort()).toEqual([
      "mypi/1.0.0.json",
      "mypi/1.1.0.json",
    ]);
    const objectsAfterUpdate = objects(store).length;
    expect(files(join(store, "inflight"))).toEqual([]);

    // Everything is past the grace period, and only the pinning keeps it. A
    // control proves the collection runs and removes what no release pinned:
    // an object nothing names goes, and every object a release placed stays.
    const planted = createHash("sha256")
      .update("pinned by nothing")
      .digest("hex");
    mkdirSync(join(store, "objects", planted.slice(0, 2)), { recursive: true });
    writeFileSync(
      join(store, "objects", planted.slice(0, 2), planted),
      "pinned by nothing",
    );
    age(store);
    const aged = await s.run(["doctor"]);
    expect(aged.status, aged.stdout + aged.stderr).toBe(0);
    expect(aged.stderr).toMatch(/Removed 1 file store object\b/);
    expect(
      existsSync(join(store, "objects", planted.slice(0, 2), planted)),
    ).toBe(false);
    expect(objects(store)).toHaveLength(objectsAfterUpdate);
    expect(references(store).sort()).toEqual([
      "mypi/1.0.0.json",
      "mypi/1.1.0.json",
    ]);
    const rolledBack = await s.run(["rollback"]);
    expect(rolledBack.status, rolledBack.stderr).toBe(0);
    expect(rolledBack.stdout).toContain("Rolled back MyPi 1.1.0 -> 1.0.0");
    age(store);
    const afterRollback = await s.run(["doctor"]);
    expect(afterRollback.status).toBe(0);
    expect(afterRollback.stderr).not.toMatch(/Removed \d+ file store object/);
    expect(objects(store)).toHaveLength(objectsAfterUpdate);
    expect((await s.run(["--smoke"])).status).toBe(0);
    expect((await s.run(["version"])).stdout).toContain("MyPi 1.0.0");

    // Only the update host's own files were requested, and only by `update`.
    const channelFiles = new Set([
      "root/2.json",
      "stable.json",
      "stable.json.sig",
      `mypi-1.1.0-${target}.tar.gz`,
    ]);
    expect(s.hostRequests.length).toBeGreaterThan(0);
    expect(s.hostRequests.filter((path) => !channelFiles.has(path))).toEqual(
      [],
    );
    expect(proxy.hits).toEqual([]);

    // The store goes away entirely: what is installed neither needs it nor
    // makes a new one, and the diagnostics have nothing to say about it.
    rmSync(store, { recursive: true, force: true });
    const without = await s.run(["--smoke"]);
    expect(without.status, without.stderr).toBe(0);
    const diagnosed = await s.run(["doctor"]);
    expect(diagnosed.status, diagnosed.stdout + diagnosed.stderr).toBe(0);
    expect(diagnosed.stdout).toMatch(/Release\n {2}✓ release\s+verified/);
    expect(existsSync(store)).toBe(false);
    const uninstall = s.cli("uninstall", "mypi");
    expect(uninstall.status, uninstall.stderr).toBe(0);
  }, 900000);

  it("installs and launches when the store cannot be used at all", async () => {
    const s = await personalScenario("shared-store-unusable");
    // A file where the store's directory would be: it cannot be created.
    const store = join(s.temp, "store");
    writeFileSync(store, "not a directory");
    Object.assign(s.env, { PISHIP_STORE: "copy", PISHIP_STORE_HOME: store });
    await s.installFirst();
    const smoke = await s.run(["--smoke"]);
    expect(smoke.status, smoke.stderr).toBe(0);
    const doctor = await s.run(["doctor"]);
    expect(doctor.status, doctor.stdout + doctor.stderr).toBe(0);
    expect(statSync(store).isFile()).toBe(true);
  }, 900000);
});
