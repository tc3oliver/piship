import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PISHIP_VERSION } from "@piship/core";
import { branded } from "../helpers/distribution.js";
import { afterAll, describe, expect, it } from "vitest";

const bin = fileURLToPath(
  new URL("../../packages/cli/dist/bin.js", import.meta.url),
);
const manifest = fileURLToPath(
  new URL("../../examples/personal/piship.yaml", import.meta.url),
);
const root = mkdtempSync(join(tmpdir(), "piship-pack-install-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

const target = `${process.platform}-${process.arch}`;
const env: NodeJS.ProcessEnv = {
  ...process.env,
  PISHIP_INSTALL_HOME: join(root, "install"),
  PISHIP_BIN_HOME: join(root, "bin"),
  PISHIP_STATE_HOME: join(root, "state"),
  PISHIP_NO_BROWSER: "1",
};
delete env.PISHIP_BUILD_INPUT;
const cli = (...args: string[]) =>
  spawnSync(process.execPath, [bin, ...args], { encoding: "utf8", env });
const command = join(
  root,
  "bin",
  process.platform === "win32" ? "mypi.cmd" : "mypi",
);

// A real runtime release and a real pack of the personal example, installed
// into a throwaway home: no registry is used by the install itself.
describe("install from a pack", () => {
  const out = join(root, "out");
  const runtime = join(
    out,
    "releases",
    `piship-runtime-${PISHIP_VERSION}-${target}.tar.gz`,
  );
  const pack = join(out, "packs", "mypi-1.0.0-pack.tar.gz");

  it("builds a runtime and a pack", () => {
    const built = cli("runtime-release", "--out", out);
    expect(built.status, built.stderr).toBe(0);
    const packed = cli("pack", manifest, "--runtime", runtime, "--out", out);
    expect(packed.status, packed.stderr).toBe(0);
    expect(existsSync(pack)).toBe(true);
  }, 900000);

  it("says where the runtime goes when it is not beside the pack", () => {
    const refused = cli("install", pack);
    expect(refused.status).not.toBe(0);
    expect(refused.stderr).toContain("--runtime");
    expect(existsSync(command)).toBe(false);
  });

  it("refuses a pack that does not match the runtime it is given", () => {
    copyFileSync(runtime, join(root, "copy.tar.gz"));
    appendFileSync(join(root, "copy.tar.gz"), "x");
    const refused = cli(
      "install",
      pack,
      "--runtime",
      join(root, "copy.tar.gz"),
    );
    expect(refused.status).not.toBe(0);
    expect(existsSync(command)).toBe(false);
  });

  it("installs, starts, records the pack and runtime, and repairs", async () => {
    const installed = cli("install", pack, "--runtime", runtime);
    expect(installed.status, installed.stderr).toBe(0);
    const version = await branded(command, ["version"], { cwd: root, env });
    expect(version.status, version.stderr).toBe(0);
    expect(version.stdout).toContain("MyPi 1.0.0");
    const receipt = JSON.parse(
      readFileSync(join(root, "install", "receipts", "mypi.json"), "utf8"),
    );
    const { release } = receipt.releases[0];
    expect(release.pack.version).toBe("1.0.0");
    expect(release.runtime.pishipVersion).toBe(PISHIP_VERSION);
    expect(release.archiveSha256).toBeUndefined();
    expect(release.runtime.archiveSha256).toMatch(/^[0-9a-f]{64}$/);

    const intact = cli("repair", "mypi", pack, "--runtime", runtime);
    expect(intact.status, intact.stderr).toBe(0);
    expect(intact.stdout).toContain("intact");
    appendFileSync(join(receipt.releases[0].payload, "piship.yaml"), "\n# x\n");
    const repaired = cli("repair", "mypi", pack, "--runtime", runtime);
    expect(repaired.status, repaired.stderr).toBe(0);
    expect(repaired.stdout).toContain("Repaired mypi 1.0.0");
  }, 300000);

  it.runIf(process.platform !== "win32")(
    "installs through the pack's own install.sh, which checks the runtime digest first",
    async () => {
      expect(cli("uninstall", "mypi").status).toBe(0);
      const unpacked = join(root, "unpacked");
      mkdirSync(unpacked);
      expect(spawnSync("tar", ["-xzf", pack, "-C", unpacked]).status).toBe(0);
      const folder = join(unpacked, "mypi-1.0.0-pack");
      const script = join(folder, "install.sh");
      const tampered = spawnSync("sh", [script, "--use-existing-state"], {
        encoding: "utf8",
        env: { ...env, PISHIP_RUNTIME_ARCHIVE: join(root, "copy.tar.gz") },
      });
      expect(tampered.status).not.toBe(0);
      expect(tampered.stderr).toContain("pins");
      expect(existsSync(command)).toBe(false);
      copyFileSync(runtime, join(unpacked, basename(runtime)));
      const installed = spawnSync("sh", [script, "--use-existing-state"], {
        encoding: "utf8",
        env,
      });
      expect(installed.status, installed.stderr).toBe(0);
      const version = await branded(command, ["version"], { cwd: root, env });
      expect(version.status, version.stderr).toBe(0);
      expect(version.stdout).toContain("MyPi 1.0.0");
    },
    300000,
  );
});
