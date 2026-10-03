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
import { PISHIP_VERSION } from "@piship/core";
import { LATEST_SCHEMA } from "@piship/schema";
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
    expect(cli("--version").stdout.trim()).toBe(PISHIP_VERSION);
    expect(cli("init").status).toBe(2);
  });
  it.each([
    ["personal", []],
    ["managed", ["--managed"]],
  ])(
    "initializes a valid %s distribution on the latest schema",
    (mode, flags) => {
      const temp = mkdtempSync(join(tmpdir(), "piship-init-"));
      temporary.push(temp);
      const manifest = join(temp, "new-agent", "piship.yaml");
      expect(cli("init", join(temp, "new-agent"), ...flags).status).toBe(0);
      expect(readFileSync(manifest, "utf8")).toMatch(
        new RegExp(`^schema: ${LATEST_SCHEMA}\n`),
      );
      const validated = cli("validate", manifest);
      expect(validated.status, validated.stderr).toBe(0);
      expect(validated.stdout).toContain(
        `Schema ${LATEST_SCHEMA}, mode ${mode}.`,
      );
      const locked = cli("lock", manifest);
      expect(locked.status, locked.stderr).toBe(0);
      const lock = JSON.parse(
        readFileSync(join(temp, "new-agent", "piship.lock"), "utf8"),
      ) as {
        schema: string;
        manifest: { schema: string };
        governance?: unknown;
        updates?: { trust: { keys: unknown[] }; source?: string };
      };
      expect(lock.schema).toBe("piship-lock/v1alpha4");
      expect(lock.manifest.schema).toBe(LATEST_SCHEMA);
      expect(lock.governance).toBeDefined();
      expect(lock.updates?.trust.keys).toEqual([]);
      expect(lock.updates?.source).toBeUndefined();
      expect(cli("migrate", manifest).stdout).toContain(
        `Already ${LATEST_SCHEMA}`,
      );
      expect(cli("inspect", manifest, "--json").stdout).toContain(
        '"id": "new-agent"',
      );
    },
    180000,
  );
  it("diffs the locks of two builds of a distribution", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-diff-"));
    temporary.push(temp);
    const before = join(temp, "before");
    const after = join(temp, "after");
    for (const target of [before, after])
      cpSync(join(root, "examples/demo-company"), target, { recursive: true });
    const manifest = join(after, "piship.yaml");
    const source = readFileSync(manifest, "utf8");
    const bumped = source.replace(
      /^ {2}version: 1\.0\.0$/m,
      "  version: 1.1.0",
    );
    expect(bumped).not.toBe(source);
    writeFileSync(manifest, bumped);
    writeFileSync(
      join(after, "resources", "AGENTS.md"),
      `${readFileSync(join(after, "resources", "AGENTS.md"), "utf8")}\nChanged.\n`,
    );
    for (const target of [before, after])
      expect(cli("lock", join(target, "piship.yaml")).status).toBe(0);
    const beforeLock = join(before, "piship.lock");
    const afterLock = join(after, "piship.lock");
    const text = cli("diff", beforeLock, afterLock);
    expect(text.status, text.stderr).toBe(0);
    expect(text.stdout).toContain("acmecode 1.0.0 -> 1.1.0");
    expect(text.stdout).toContain("resources/AGENTS.md");
    const json = cli("diff", beforeLock, afterLock, "--json");
    expect(json.status, json.stderr).toBe(0);
    const report = JSON.parse(json.stdout) as {
      schema: string;
      before: { id: string; version: string };
      after: { id: string; version: string };
      risk: string;
      changes: { area: string; kind: string; item: string }[];
    };
    expect(report.schema).toBe("piship-diff/v1");
    expect(report.before).toMatchObject({ id: "acmecode", version: "1.0.0" });
    expect(report.after).toMatchObject({ id: "acmecode", version: "1.1.0" });
    expect(report.risk).not.toBe("none");
    expect(report.changes).toContainEqual(
      expect.objectContaining({
        kind: "changed",
        item: expect.stringContaining("resources/AGENTS.md"),
      }),
    );
    const same = cli("diff", beforeLock, beforeLock, "--json");
    expect(same.status).toBe(0);
    expect(JSON.parse(same.stdout)).toMatchObject({
      risk: "none",
      changes: [],
    });
    // Manifests resolve through their current lock.
    expect(cli("diff", join(before, "piship.yaml"), manifest).stdout).toContain(
      "1.0.0 -> 1.1.0",
    );
    expect(cli("diff", beforeLock).status).toBe(2);
    expect(cli("diff", beforeLock, afterLock, "--yaml").status).toBe(2);
  }, 180000);
  it("dev validates, builds from source, and launches the isolated command headlessly", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-dev-"));
    temporary.push(temp);
    const manifest = join(temp, "dev-agent", "piship.yaml");
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PISHIP_STATE_HOME: join(temp, "state"),
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
    };
    delete env.PISHIP_BUILD_INPUT;
    const dev = (...args: string[]) =>
      spawnSync(process.execPath, [bin, ...args], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
    expect(dev("init", join(temp, "dev-agent")).status).toBe(0);
    expect(dev("dev", manifest, "--unknown").status).toBe(2);
    // The lock is validated first: without it nothing is built or launched.
    const unlocked = dev("dev", manifest, "--smoke");
    expect(unlocked.status).toBe(1);
    expect(unlocked.stderr).toContain("Lockfile missing");
    expect(existsSync(join(temp, "dist", "dev-agent"))).toBe(false);
    expect(dev("lock", manifest).status).toBe(0);
    // Ambient Pi and workspace resources must not reach the isolated launch.
    createAmbientResources(temp);
    const result = dev("dev", manifest, "--smoke");
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      skills: [],
      extensions: 0,
    });
    expect(
      existsSync(join(temp, "dist", "dev-agent", "metadata", "inventory.json")),
    ).toBe(true);
    expect(existsSync(join(temp, "state", "dev-agent"))).toBe(true);
    // A resource change after locking is caught before anything launches.
    writeFileSync(join(temp, "dev-agent", "resources", "AGENTS.md"), "edit\n");
    const stale = dev("dev", manifest, "--smoke");
    expect(stale.status).toBe(1);
    expect(stale.stderr).toContain("Lockfile is stale");
  }, 360000);
  it("installs after piship test without --use-existing-state, and only once", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-first-run-"));
    temporary.push(temp);
    const directory = join(temp, "first-run");
    const manifest = join(directory, "piship.yaml");
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PISHIP_STATE_HOME: join(temp, "state"),
      PISHIP_INSTALL_HOME: join(temp, "install"),
      PISHIP_BIN_HOME: join(temp, "bin"),
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
    };
    delete env.PISHIP_BUILD_INPUT;
    const run = (...args: string[]) =>
      spawnSync(process.execPath, args, { cwd: temp, env, encoding: "utf8" });
    // The documented first run: init, lock, build, test, install.
    expect(run(bin, "init", directory, "--personal").status).toBe(0);
    expect(run(bin, "lock", manifest).status).toBe(0);
    const built = run(bin, "build", manifest);
    expect(built.status, built.stderr).toBe(0);
    expect(built.stdout).toContain(`Next: piship test ${manifest}`);
    const tested = run(bin, "test", manifest);
    expect(tested.status, tested.stderr).toBe(0);
    expect(existsSync(join(temp, "state", "first-run"))).toBe(true);
    const payload = join(temp, "dist", "first-run");
    const manager = join(payload, "piship.mjs");
    const installed = run(manager, "install", payload);
    expect(installed.status, installed.stderr).toBe(0);
    // Once installed, the state is the install's: after an uninstall it is
    // pre-existing state like any other and must be adopted explicitly.
    expect(run(manager, "uninstall", "first-run").status).toBe(0);
    const again = run(manager, "install", payload);
    expect(again.status).toBe(1);
    expect(again.stderr).toContain("State already exists");
    expect(
      run(manager, "install", payload, "--use-existing-state").status,
    ).toBe(0);
  }, 360000);
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
    expect(brandedVersion.stdout).toContain(`PiShip ${PISHIP_VERSION}`);
    expect(brandedVersion.stdout).toContain("Pi 1.0.0 by Earendil Works");
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
    // Pi-native sign-in happens inside the session: branded login and
    // logout would always refuse, so help never advertises them.
    expect(brandedHelp.stdout).not.toMatch(/(^|\s)log(in|out)(\s|$)/m);
    expect(brandedHelp.stdout).toContain(
      "start mypi, then use /login and /logout, and /model",
    );
    expect(brandedHelp.stdout).toContain("doctor [--json] | models | version");
    expect(brandedHelp.stdout).toContain("config explain [--json]");
    expect(brandedHelp.stdout).toContain("update [--channel <name>]");
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
      // The installed manager removes its own install and state.
      const otherManager = spawnSync(
        process.execPath,
        [
          join(temp, "install's", "apps", "other-agent", "1.0.0", "piship.mjs"),
          "uninstall",
          "other-agent",
          "--purge",
          "--yes",
        ],
        { cwd: temp, env, encoding: "utf8" },
      );
      expect(otherManager.status, otherManager.stderr).toBe(0);
      expect(existsSync(otherLauncher)).toBe(false);
      expect(existsSync(join(temp, "state", "other-agent"))).toBe(false);
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
      const movedManager = (...args: string[]) =>
        spawnSync(
          process.execPath,
          [
            join(temp, "moved-install", "apps", "mypi", "1.0.0", "piship.mjs"),
            ...args,
          ],
          { cwd: temp, env: movedEnv, encoding: "utf8" },
        );
      expect(movedManager("uninstall", "mypi", "--purge").status).toBe(1);
      expect(existsSync(movedLauncher)).toBe(true);
      const removed = movedManager("uninstall", "mypi", "--purge", "--yes");
      expect(removed.status, removed.stderr).toBe(0);
      expect(existsSync(movedLauncher)).toBe(false);
      expect(existsSync(join(temp, "moved-install", "apps", "mypi"))).toBe(
        false,
      );
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
      [
        "schema: piship/v1alpha1",
        "app:",
        "  id: managedblocked",
        "  name: Managed Blocked",
        "  command: managedblocked",
        "  version: 1.0.0",
        "runtime:",
        '  pi: "1.0.0"',
        "deployment:",
        "  mode: managed",
        "",
      ].join("\n"),
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
  }, 180000);
  it("rejects secret-looking values and fields without echoing them", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-secret-"));
    temporary.push(temp);
    const example = join(temp, "demo-company");
    cpSync(join(root, "examples/demo-company"), example, { recursive: true });
    const manifest = join(example, "piship.yaml");
    const original = readFileSync(manifest, "utf8");
    const token = ["ghp", "Z9y8X7w6V5u4T3s2R1q0"].join("_");
    writeFileSync(
      manifest,
      original.replace(
        "banner: AcmeCode managed demo distribution (fictional)",
        `banner: ${token}`,
      ),
    );
    const banner = cli("validate", manifest);
    expect(banner.status).toBe(1);
    expect(banner.stderr).toContain("app.banner");
    expect(banner.stderr).toContain("looks like secret material");
    expect(banner.stderr).not.toContain(token);
    writeFileSync(
      manifest,
      original.replace(
        "  liveCatalog: true\n",
        "  liveCatalog: true\n  apiKey: plain-value-123\n",
      ),
    );
    const field = cli("validate", manifest);
    expect(field.status).toBe(1);
    expect(field.stderr).toContain("inference.apiKey");
    expect(field.stderr).toContain(
      "Unknown field; secrets are not allowed in piship.yaml",
    );
    expect(field.stderr).not.toContain("plain-value-123");
    expect(field.stderr).not.toContain("REDACTED");
  });
  it("reports invalid Pi, missing resources, and YAML errors without a stack trace", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-errors-"));
    temporary.push(temp);
    const example = join(temp, "personal");
    cpSync(join(root, "examples/personal"), example, { recursive: true });
    const manifest = join(example, "piship.yaml");
    const original = readFileSync(manifest, "utf8");
    writeFileSync(manifest, original.replace('"1.0.0"', '"0.88.0"'));
    expect(cli("validate", manifest).stderr).toContain("Pinned runtime: 1.0.0");
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
