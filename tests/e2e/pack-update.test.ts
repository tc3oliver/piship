import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createArchive,
  formatChecksums,
  PISHIP_VERSION,
  payloadInventory,
  RUNTIME_FILES,
} from "@piship/core";
import { afterAll, describe, expect, it } from "vitest";
import { branded } from "../helpers/distribution.js";
import { bootstrapTrust } from "../helpers/update-trust.js";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(repo, "packages/cli/dist/bin.js");
const root = mkdtempSync(join(tmpdir(), "piship-pack-update-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const target = `${process.platform}-${process.arch}`;
const baseEnv: NodeJS.ProcessEnv = {
  ...process.env,
  PISHIP_INSTALL_HOME: join(root, "install"),
  PISHIP_BIN_HOME: join(root, "bin"),
  PISHIP_STATE_HOME: join(root, "state"),
  PISHIP_NO_BROWSER: "1",
};
delete baseEnv.PISHIP_BUILD_INPUT;
let source = join(root, "channel");
const env = (): NodeJS.ProcessEnv => ({
  ...baseEnv,
  MYPI_UPDATE_SOURCE: source,
});
const cli = (...args: string[]) =>
  spawnSync(process.execPath, [bin, ...args], { encoding: "utf8", env: env() });
const ok = (...args: string[]) => {
  const run = cli(...args);
  expect(run.status, `${args.join(" ")}: ${run.stderr}`).toBe(0);
  return run;
};
const command = join(
  root,
  "bin",
  process.platform === "win32" ? "mypi.cmd" : "mypi",
);
const sha = (file: string) =>
  createHash("sha256").update(readFileSync(file)).digest("hex");
const receipt = () =>
  JSON.parse(
    readFileSync(join(root, "install", "receipts", "mypi.json"), "utf8"),
  );
async function launched(): Promise<string> {
  const run = await branded(command, ["version"], { cwd: root, env: env() });
  expect(run.status, run.stderr).toBe(0);
  return /MyPi (\S+)/.exec(run.stdout)?.[1] ?? run.stdout;
}

// The personal example as its owner would ship it: a pinned channel key, at
// three versions.
const key = join(root, "release.pem");
const manifests: Record<string, string> = {};
function prepare(version: string, publicKey: string): void {
  const directory = join(root, "work", version);
  cpSync(join(repo, "examples", "personal"), directory, { recursive: true });
  const file = join(directory, "piship.yaml");
  const patched = readFileSync(file, "utf8")
    .replace(
      "  rollback: true\n",
      `  rollback: true\n${bootstrapTrust({ id: "pack-e2e", publicKey })}`,
    )
    .replace(/^ {2}version: \d+\.\d+\.\d+$/m, `  version: ${version}`);
  expect(patched).toContain(`publicKey: ${publicKey}`);
  writeFileSync(file, patched);
  manifests[version] = file;
}

/** A second, valid runtime for this target: the first with one more file, under another name. */
async function deriveRuntime(archive: string): Promise<string> {
  const name = `${basename(archive, ".tar.gz")}-b`;
  const work = join(root, "derive");
  mkdirSync(work);
  expect(spawnSync("tar", ["-xzf", archive, "-C", work]).status).toBe(0);
  const folder = join(work, name);
  renameSync(join(work, basename(archive, ".tar.gz")), folder);
  const payload = join(folder, "payload");
  writeFileSync(join(payload, "runtime-b.txt"), "the second runtime\n");
  const files = payloadInventory(payload);
  const inventory = join(payload, "metadata", "inventory.json");
  writeFileSync(inventory, `${JSON.stringify(files, null, 2)}\n`);
  const json = join(folder, "runtime.json");
  const metadata = JSON.parse(readFileSync(json, "utf8"));
  metadata.inventory = {
    sha256: sha(inventory),
    files: Object.keys(files).length + 1,
  };
  writeFileSync(json, `${JSON.stringify(metadata, null, 2)}\n`);
  writeFileSync(
    join(folder, "checksums.txt"),
    formatChecksums(folder, [...RUNTIME_FILES]),
  );
  const out = join(root, `${name}.tar.gz`);
  await createArchive(folder, name, out);
  return out;
}

// Real runtime releases, packs, and signed channels: a pack-only change, a
// runtime change, rollbacks over composed installs, and a mixed channel.
describe("update from a signed channel that carries packs", () => {
  let runtimeA = "";
  let runtimeB = "";
  const out = join(root, "out");
  const pack = (version: string) =>
    join(out, "packs", `mypi-${version}-pack.tar.gz`);

  it("builds two runtimes and three packs", async () => {
    runtimeA = join(
      out,
      "releases",
      `piship-runtime-${PISHIP_VERSION}-${target}.tar.gz`,
    );
    ok("runtime-release", "--out", out);
    runtimeB = await deriveRuntime(runtimeA);
    const keygen = ok("keygen", key, "--id", "pack-e2e");
    const publicKey = /Public key: (\S+)/.exec(keygen.stdout)?.[1] as string;
    for (const version of ["1.0.0", "1.1.0", "1.2.0"]) {
      prepare(version, publicKey);
      ok("lock", manifests[version] as string);
    }
    for (const [version, runtime] of [
      ["1.0.0", runtimeA],
      ["1.1.0", runtimeA],
      ["1.2.0", runtimeB],
    ] as const)
      ok(
        "pack",
        manifests[version] as string,
        "--runtime",
        runtime,
        "--out",
        out,
      );
    expect(existsSync(pack("1.2.0"))).toBe(true);
  }, 900000);

  const sign = (channel: string, sequence: number, ...artifacts: string[]) =>
    ok(
      "sign-channel",
      channel,
      ...artifacts,
      "--channel",
      "stable",
      "--key",
      key,
      "--key-id",
      "pack-e2e",
      "--sequence",
      String(sequence),
    );

  it("updates to a newer pack without fetching the runtime it already has", async () => {
    ok("install", pack("1.0.0"), "--runtime", runtimeA);
    expect(await launched()).toBe("1.0.0");
    source = join(root, "channel");
    sign(source, 1, pack("1.1.0"), "--runtime", runtimeA);
    const signed = JSON.parse(
      readFileSync(join(source, "stable.json"), "utf8"),
    );
    expect(signed.releases).toEqual([]);
    expect(signed.packs[0].runtimes[target].sha256).toBe(sha(runtimeA));
    // The runtime is in the channel directory; take it away so that only a
    // reuse of the installed one can succeed.
    rmSync(join(source, basename(runtimeA)));
    const updated = ok("update", "mypi");
    expect(updated.stdout).toContain("1.1.0");
    expect(await launched()).toBe("1.1.0");
    const { release } = receipt().releases[0];
    expect(release.pack.version).toBe("1.1.0");
    expect(release.runtime.archiveSha256).toBe(sha(runtimeA));
    expect(release.archiveSha256).toBeUndefined();
  }, 600000);

  it("rolls back over a composed install, and updates again from the retained pack", async () => {
    ok("rollback", "mypi");
    expect(await launched()).toBe("1.0.0");
    expect(receipt().active).toBe("1.0.0");
    ok("update", "mypi");
    expect(await launched()).toBe("1.1.0");
  }, 600000);

  it("fetches the pinned runtime for a pack that needs another one", async () => {
    sign(source, 2, pack("1.2.0"), "--runtime", runtimeB);
    expect(existsSync(join(source, basename(runtimeB)))).toBe(true);
    ok("update", "mypi");
    expect(await launched()).toBe("1.2.0");
    const current = receipt();
    expect(current.releases[0].release.runtime.archiveSha256).toBe(
      sha(runtimeB),
    );
    expect(existsSync(join(current.payload, "runtime-b.txt"))).toBe(true);
    ok("rollback", "mypi");
    expect(await launched()).toBe("1.1.0");
    expect(existsSync(join(receipt().payload, "runtime-b.txt"))).toBe(false);
  }, 600000);

  it("serves a mixed channel, and rolls a pack install back to a per-target release", async () => {
    ok("uninstall", "mypi");
    const built = ok(
      "release",
      manifests["1.0.0"] as string,
      "--out",
      join(root, "release"),
    );
    const archive = built.stdout.match(/archive\s+(\S+)/)?.[1] as string;
    expect(basename(archive)).toBe(`mypi-1.0.0-${target}.tar.gz`);
    ok("install", archive, "--use-existing-state");
    expect(await launched()).toBe("1.0.0");
    source = join(root, "mixed");
    sign(source, 1, archive, pack("1.1.0"), "--runtime", runtimeA);
    const signed = JSON.parse(
      readFileSync(join(source, "stable.json"), "utf8"),
    );
    expect(
      signed.releases.map((item: { version: string }) => item.version),
    ).toEqual(["1.0.0"]);
    expect(
      signed.packs.map((item: { version: string }) => item.version),
    ).toEqual(["1.1.0"]);
    ok("update", "mypi");
    expect(await launched()).toBe("1.1.0");
    expect(receipt().releases[0].release.pack.version).toBe("1.1.0");
    ok("rollback", "mypi");
    expect(await launched()).toBe("1.0.0");
    const retained = receipt().releases.find(
      (item: { version: string }) => item.version === "1.0.0",
    );
    expect(retained.release.archiveSha256).toBe(sha(archive));
    expect(retained.release.pack).toBeUndefined();
  }, 900000);
});
