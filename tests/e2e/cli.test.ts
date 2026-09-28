import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const temporary: string[] = [];
function cli(...args: string[]) {
  return spawnSync(process.execPath, [bin, ...args], {
    cwd: root,
    encoding: "utf8",
  });
}
function createAmbientResources(root: string): void {
  const homes = [
    join(root, "state", "mypi", "agent"),
    join(root, "home", ".pi", "agent"),
    join(root, ".pi"),
  ];
  for (const home of homes) {
    const skill = join(home, "skills", "ambient");
    mkdirSync(skill, { recursive: true });
    writeFileSync(
      join(skill, "SKILL.md"),
      "---\nname: ambient\ndescription: Must not load\n---\n",
    );
    for (const [directory, filename, content] of [
      ["extensions", "ambient.ts", "export default function ambient() {}\n"],
      ["prompts", "ambient.md", "Ambient prompt\n"],
      ["themes", "ambient.json", "{}\n"],
    ] as const) {
      mkdirSync(join(home, directory), { recursive: true });
      writeFileSync(join(home, directory, filename), content);
    }
    writeFileSync(join(home, "AGENTS.md"), "Ambient instructions\n");
  }
  for (const skill of [
    join(root, "home", ".agents", "skills", "ambient"),
    join(root, ".agents", "skills", "ambient"),
  ]) {
    mkdirSync(skill, { recursive: true });
    writeFileSync(
      join(skill, "SKILL.md"),
      "---\nname: ambient\ndescription: Must not load\n---\n",
    );
  }
  writeFileSync(join(root, "AGENTS.md"), "Ambient project instructions\n");
}
afterEach(() => {
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);
describe("CLI", () => {
  it("prints help/version and requires init target", () => {
    expect(cli("--help").stdout).toContain("Usage: piship <command>");
    expect(cli("--version").stdout.trim()).toBe("0.1.0");
    expect(cli("init").status).toBe(2);
  });
  it("initializes a valid personal distribution", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-init-"));
    temporary.push(temp);
    const manifest = join(temp, "new-agent", "piship.yaml");
    expect(cli("init", join(temp, "new-agent")).status).toBe(0);
    expect(cli("validate", manifest).status).toBe(0);
    expect(cli("lock", manifest).status).toBe(0);
    expect(cli("inspect", manifest).stdout).toContain('"id": "new-agent"');
  });
  it("installs a relocated payload, resumes Pi, diagnoses tampering, and removes only owned files", () => {
    const qualification = process.env.PISHIP_E2E_QUALIFICATION === "1";
    const temp = mkdtempSync(join(tmpdir(), "piship-install-"));
    temporary.push(temp);
    const example = join(temp, "example");
    cpSync(join(root, "examples/personal"), example, { recursive: true });
    const manifest = join(example, "piship.yaml");
    expect(cli("validate", manifest).stdout).toContain("Manifest is valid.");
    expect(cli("lock", manifest).status).toBe(0);
    const originalLock = readFileSync(join(example, "piship.lock"), "utf8");
    expect(originalLock).toContain("resources/extensions/demo/helper.ts");
    expect(cli("lock", manifest).status).toBe(0);
    expect(readFileSync(join(example, "piship.lock"), "utf8")).toBe(
      originalLock,
    );
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PISHIP_INSTALL_HOME: join(temp, "install's"),
      PISHIP_BIN_HOME: join(temp, "bin"),
      PISHIP_STATE_HOME: join(temp, "state"),
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
      PISHIP_DEBUG_TIMING: "1",
    };
    delete env.PISHIP_BUILD_INPUT;
    const localCli = (...args: string[]) =>
      spawnSync(process.execPath, [bin, ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
    const acceptance = spawnSync(process.execPath, [bin, "test", manifest], {
      cwd: temp,
      env: { ...env, PISHIP_STATE_HOME: join(temp, "acceptance-state") },
      encoding: "utf8",
    });
    expect(acceptance.status, acceptance.stderr).toBe(0);
    expect(acceptance.stdout).toContain("Personal acceptance passed");
    process.stderr.write(acceptance.stderr);
    const built = join(temp, "dist", "mypi");
    expect(
      readFileSync(join(built, "resources", "resources", "AGENTS.md"), "utf8"),
    ).toContain("MyPi");
    expect(readFileSync(join(built, "bin", "mypi"), "utf8")).toContain(
      "launchPiDistribution",
    );
    expect(readFileSync(join(built, "bin", "mypi.cmd"), "utf8")).toContain(
      "node",
    );
    if (process.platform !== "win32")
      expect(statSync(join(built, "bin", "mypi")).mode & 0o111).not.toBe(0);
    const firstInventory = readFileSync(
      join(built, "metadata", "inventory.json"),
    );
    const spare = join(temp, "spare-build");
    if (qualification) {
      renameSync(built, spare);
      const secondBuild = localCli("build", manifest);
      expect(secondBuild.status, secondBuild.stderr).toBe(0);
      process.stderr.write(secondBuild.stderr);
      expect(readFileSync(join(built, "metadata", "inventory.json"))).toEqual(
        firstInventory,
      );
    }
    const helper = join(
      example,
      "resources",
      "extensions",
      "demo",
      "helper.ts",
    );
    const originalHelper = readFileSync(helper);
    writeFileSync(helper, 'export const helper = "changed";\n');
    expect(localCli("build", manifest).stderr).toContain("stale");
    expect(localCli("lock", manifest).status).toBe(0);
    expect(readFileSync(join(example, "piship.lock"), "utf8")).not.toBe(
      originalLock,
    );
    writeFileSync(helper, originalHelper);
    expect(localCli("lock", manifest).status).toBe(0);
    const relocated = join(temp, "relocated");
    renameSync(built, relocated);
    let manager = join(relocated, "piship.mjs");
    const command = (...args: string[]) =>
      spawnSync(process.execPath, [manager, ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
    const installed = command("install", relocated);
    expect(installed.status, installed.stderr).toBe(0);
    process.stderr.write(installed.stderr);
    expect(command("install", relocated).stderr).toContain("collision");
    rmSync(relocated, { recursive: true, force: true });
    rmSync(example, { recursive: true, force: true });
    manager = join(temp, "install's", "apps", "mypi", "1.0.0", "piship.mjs");
    expect(command("inspect", "mypi").status).toBe(0);
    createAmbientResources(temp);
    const installedCommand = join(
      temp,
      "bin",
      process.platform === "win32" ? "mypi.cmd" : "mypi",
    );
    const launch = () =>
      process.platform === "win32"
        ? spawnSync(
            "cmd.exe",
            ["/d", "/s", "/c", `call "${installedCommand}" --smoke`],
            {
              cwd: temp,
              env,
              encoding: "utf8",
              windowsVerbatimArguments: true,
            },
          )
        : spawnSync(installedCommand, ["--smoke"], {
            cwd: temp,
            env,
            encoding: "utf8",
          });
    const first = launch();
    expect(first.status, first.stderr).toBe(0);
    expect(first.stderr).toContain("verifyPayload:");
    console.info(first.stderr.trim());
    const brandedVersion =
      process.platform === "win32"
        ? spawnSync(
            "cmd.exe",
            ["/d", "/s", "/c", `call "${installedCommand}" --version`],
            {
              cwd: temp,
              env,
              encoding: "utf8",
              windowsVerbatimArguments: true,
            },
          )
        : spawnSync(installedCommand, ["--version"], {
            cwd: temp,
            env,
            encoding: "utf8",
          });
    expect(brandedVersion.status, brandedVersion.stderr).toBe(0);
    expect(brandedVersion.stdout).toContain("MyPi 1.0.0");
    expect(brandedVersion.stdout).toContain("PiShip 0.1.0");
    expect(brandedVersion.stdout).toContain("Pi 0.87.1 by Earendil Works");
    const brandedHelp =
      process.platform === "win32"
        ? spawnSync(
            "cmd.exe",
            ["/d", "/s", "/c", `call "${installedCommand}" --help`],
            {
              cwd: temp,
              env,
              encoding: "utf8",
              windowsVerbatimArguments: true,
            },
          )
        : spawnSync(installedCommand, ["--help"], {
            cwd: temp,
            env,
            encoding: "utf8",
          });
    expect(brandedHelp.status, brandedHelp.stderr).toBe(0);
    expect(brandedHelp.stdout).toContain("MyPi personal distribution");
    const firstResult = JSON.parse(first.stdout) as {
      sessionId: string;
      resumed: boolean;
      safeTool: string;
      extensionPaths: string[];
      instructions: string[];
      agentDir: string;
    };
    expect(firstResult).toMatchObject({
      resumed: false,
      safeTool: "read",
      skills: ["demo-skill"],
      extensions: 1,
      prompts: ["demo"],
      themes: ["mypi"],
    });
    expect(firstResult.agentDir).toContain(join(temp, "state", "mypi"));
    const physicalTemp = realpathSync(temp);
    expect(firstResult.instructions).toEqual([
      join(
        physicalTemp,
        "install's",
        "apps",
        "mypi",
        "1.0.0",
        "resources",
        "resources",
        "AGENTS.md",
      ),
    ]);
    expect(firstResult.extensionPaths).toEqual([
      join(
        physicalTemp,
        "install's",
        "apps",
        "mypi",
        "1.0.0",
        "resources",
        "resources",
        "extensions",
        "demo",
      ),
    ]);
    expect(existsSync(join(temp, "home", ".pi", "agent", "auth.json"))).toBe(
      false,
    );
    const second = launch();
    expect(second.status, second.stderr).toBe(0);
    expect(JSON.parse(second.stdout)).toMatchObject({
      sessionId: firstResult.sessionId,
      resumed: true,
      skills: ["demo-skill"],
      extensions: 1,
      prompts: ["demo"],
      themes: ["mypi"],
    });
    expect(command("doctor", "mypi").status).toBe(0);
    const relocatedBuilder = (...args: string[]) =>
      spawnSync(process.execPath, [join(spare, "piship.mjs"), ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
    if (qualification) {
      const otherRoot = join(temp, "other-agent");
      const otherManifest = join(otherRoot, "piship.yaml");
      expect(relocatedBuilder("init", otherRoot).status).toBe(0);
      expect(relocatedBuilder("lock", otherManifest).status).toBe(0);
      const otherBuild = relocatedBuilder("build", otherManifest);
      expect(otherBuild.status, otherBuild.stderr).toBe(0);
      process.stderr.write(otherBuild.stderr);
      expect(command("install", join(temp, "dist", "other-agent")).status).toBe(
        0,
      );
    }
    const otherLauncher = join(
      temp,
      "bin",
      process.platform === "win32" ? "other-agent.cmd" : "other-agent",
    );
    const launchOther = () =>
      process.platform === "win32"
        ? spawnSync(
            "cmd.exe",
            ["/d", "/s", "/c", `call "${otherLauncher}" --smoke`],
            {
              cwd: temp,
              env,
              encoding: "utf8",
              windowsVerbatimArguments: true,
            },
          )
        : spawnSync(otherLauncher, ["--smoke"], {
            cwd: temp,
            env,
            encoding: "utf8",
          });
    if (qualification) {
      const otherLaunch = launchOther();
      expect(otherLaunch.status, otherLaunch.stderr).toBe(0);
      expect(JSON.parse(otherLaunch.stdout)).toMatchObject({
        skills: [],
        extensions: 0,
      });
      expect(existsSync(join(temp, "state", "other-agent"))).toBe(true);
      expect(launch().status).toBe(0);
    }
    expect(existsSync(join(temp, "state", "mypi"))).toBe(true);
    expect(command("doctor", "mypi").status).toBe(0);
    const payload = join(temp, "install's", "apps", "mypi", "1.0.0");
    expect(readFileSync(join(payload, "piship.lock"), "utf8")).toBe(
      originalLock,
    );
    expect(
      JSON.parse(
        readFileSync(join(payload, "metadata", "inventory.json"), "utf8"),
      )["piship.lock"],
    ).toMatch(/^[a-f0-9]{64}$/);
    expect(existsSync(join(payload, "metadata", "distribution.json"))).toBe(
      false,
    );
    const resource = join(payload, "resources", "resources", "AGENTS.md");
    const original = readFileSync(resource);
    writeFileSync(resource, "tampered\n");
    expect(command("doctor", "mypi").stderr).toContain("integrity mismatch");
    writeFileSync(resource, original);
    for (const path of [
      join(payload, "piship.lock"),
      join(payload, "piship.yaml"),
      join(
        payload,
        "node_modules",
        "@earendil-works",
        "pi-coding-agent",
        "dist",
        "index.js",
      ),
    ]) {
      const content = readFileSync(path);
      writeFileSync(
        path,
        Buffer.concat([content, Buffer.from("\n// altered\n")]),
      );
      expect(command("doctor", "mypi").stderr).toContain("integrity mismatch");
      if (path === join(payload, "piship.lock"))
        expect(launch().stderr).toContain("integrity mismatch");
      writeFileSync(path, content);
    }
    const targetPath = join(payload, "metadata", "target.json");
    const inventoryPath = join(payload, "metadata", "inventory.json");
    const originalTarget = readFileSync(targetPath);
    const originalInventory = readFileSync(inventoryPath);
    writeFileSync(
      targetPath,
      JSON.stringify({ platform: "unsupported", arch: "unknown" }),
    );
    const changedInventory = JSON.parse(originalInventory.toString()) as Record<
      string,
      string
    >;
    changedInventory["metadata/target.json"] = createHash("sha256")
      .update(readFileSync(targetPath))
      .digest("hex");
    writeFileSync(
      inventoryPath,
      `${JSON.stringify(changedInventory, null, 2)}\n`,
    );
    expect(command("doctor", "mypi").stderr).toContain(
      "does not match this machine",
    );
    writeFileSync(targetPath, originalTarget);
    writeFileSync(inventoryPath, originalInventory);
    expect(command("uninstall", "mypi").status).toBe(0);
    expect(existsSync(payload)).toBe(false);
    expect(existsSync(installedCommand)).toBe(false);
    expect(existsSync(join(temp, "state", "mypi"))).toBe(true);
    if (qualification) {
      expect(existsSync(otherLauncher)).toBe(true);
      expect(launchOther().status).toBe(0);
      expect(relocatedBuilder("uninstall", "other-agent").status).toBe(0);
      expect(relocatedBuilder("purge", "other-agent", "--yes").status).toBe(0);
      expect(existsSync(join(temp, "state", "mypi"))).toBe(true);
      const movedEnv = {
        ...env,
        PISHIP_INSTALL_HOME: join(temp, "moved-install"),
        PISHIP_BIN_HOME: join(temp, "moved-bin"),
      };
      const movedCommand = (...args: string[]) =>
        spawnSync(process.execPath, [join(spare, "piship.mjs"), ...args], {
          cwd: temp,
          env: movedEnv,
          encoding: "utf8",
        });
      expect(movedCommand("install", spare).stderr).toContain(
        "State already exists",
      );
      expect(
        movedCommand("install", spare, "--use-existing-state").status,
      ).toBe(0);
      const movedLauncher = join(
        temp,
        "moved-bin",
        process.platform === "win32" ? "mypi.cmd" : "mypi",
      );
      const resumed =
        process.platform === "win32"
          ? spawnSync(
              "cmd.exe",
              ["/d", "/s", "/c", `call "${movedLauncher}" --smoke`],
              {
                cwd: temp,
                env: movedEnv,
                encoding: "utf8",
                windowsVerbatimArguments: true,
              },
            )
          : spawnSync(movedLauncher, ["--smoke"], {
              cwd: temp,
              env: movedEnv,
              encoding: "utf8",
            });
      expect(resumed.status, resumed.stderr).toBe(0);
      expect(JSON.parse(resumed.stdout)).toMatchObject({
        sessionId: firstResult.sessionId,
        resumed: true,
      });
      expect(movedCommand("uninstall", "mypi").status).toBe(0);
      expect(movedCommand("purge", "mypi").status).toBe(1);
      expect(movedCommand("purge", "mypi", "--yes").status).toBe(0);
    } else {
      expect(localCli("purge", "mypi").status).toBe(1);
      expect(localCli("purge", "mypi", "--yes").status).toBe(0);
    }
    expect(existsSync(join(temp, "state", "mypi"))).toBe(false);
  }, 360000);
  it("rejects managed v1alpha1 manifests before lock or build output", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-managed-"));
    temporary.push(temp);
    const manifest = join(temp, "piship.yaml");
    writeFileSync(
      manifest,
      readFileSync(join(root, "examples/personal/piship.yaml"), "utf8")
        .replace("id: mypi", "id: managedblocked")
        .replace("command: mypi", "command: managedblocked")
        .replace("mode: personal", "mode: managed"),
    );
    for (const command of ["validate", "lock", "build"]) {
      const result = cli(command, manifest);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("deployment.mode");
      expect(result.stderr).toContain(
        "managed requires schema piship/v1alpha2",
      );
    }
    expect(existsSync(join(temp, "piship.lock"))).toBe(false);
    expect(existsSync(join(root, "dist/managedblocked"))).toBe(false);
  });
  it("fails validate like lock when a certified digest does not match", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-certified-"));
    temporary.push(temp);
    const example = join(temp, "demo-company");
    cpSync(join(root, "examples/demo-company"), example, { recursive: true });
    rmSync(join(example, "piship.lock"), { force: true });
    const manifest = join(example, "piship.yaml");
    const original = readFileSync(manifest, "utf8");
    const reviewed = /integrity: (sha256-[0-9a-f]{64})/.exec(original)?.[1];
    expect(reviewed).toBeDefined();
    const tampered = `sha256-${"0".repeat(64)}`;
    writeFileSync(manifest, original.replace(`${reviewed}`, tampered));
    for (const command of ["validate", "lock"]) {
      const result = cli(command, manifest);
      expect(result.status, command).toBe(1);
      expect(result.stderr).toContain("resources.skills.certified");
      expect(result.stderr).toContain("Integrity mismatch");
      expect(result.stderr).toContain("re-review it and update the integrity");
      expect(result.stdout).not.toContain("Manifest is valid");
    }
    expect(existsSync(join(example, "piship.lock"))).toBe(false);
    writeFileSync(manifest, original);
    expect(cli("validate", manifest).status).toBe(0);
    expect(existsSync(join(example, "piship.lock"))).toBe(false);
  });
  it("reports invalid Pi, missing resources, and YAML errors without a stack trace", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-errors-"));
    temporary.push(temp);
    const example = join(temp, "personal");
    cpSync(join(root, "examples/personal"), example, { recursive: true });
    const manifest = join(example, "piship.yaml");
    const original = readFileSync(manifest, "utf8");
    writeFileSync(manifest, original.replace('"0.87.1"', '"0.88.0"'));
    expect(cli("validate", manifest).stderr).toContain(
      "Pinned runtime: 0.87.1",
    );
    writeFileSync(
      manifest,
      original.replace("./resources/AGENTS.md", "./resources/missing.md"),
    );
    expect(cli("validate", manifest).stderr).toContain(
      "missing resource at resources.instructions",
    );
    writeFileSync(manifest, "app: [broken\n");
    const parsed = cli("validate", manifest);
    expect(parsed.status).toBe(1);
    expect(parsed.stderr).toContain("YAML parse failure");
    expect(parsed.stderr).not.toContain("at runCli");
  });
});
