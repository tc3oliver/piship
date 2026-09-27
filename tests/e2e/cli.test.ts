import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
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
});
describe("CLI", () => {
  it("prints help/version and rejects placeholders", () => {
    expect(cli("--help").stdout).toContain("Usage: piship <command>");
    expect(cli("--version").stdout.trim()).toBe("0.0.0");
    expect(cli("init").status).toBe(2);
  });
  it("validates, locks, builds and starts real Pi without a model call", () => {
    const temp = mkdtempSync(join(tmpdir(), "piship-e2e-"));
    temporary.push(temp);
    const example = join(temp, "personal");
    cpSync(join(root, "examples/personal"), example, { recursive: true });
    const manifest = join(example, "piship.yaml");
    expect(cli("validate", manifest).stdout).toContain("Manifest is valid.");
    expect(cli("lock", manifest).status).toBe(0);
    const lock = readFileSync(join(example, "piship.lock"), "utf8");
    expect(lock).toContain("resources/extensions/demo/index.ts");
    expect(lock).toContain("resources/extensions/demo/helper.ts");
    const lockedHelper = JSON.parse(lock).resources.find(
      (item: { path: string; sha256: string }) =>
        item.path === "resources/extensions/demo/helper.ts",
    ) as { sha256: string } | undefined;
    expect(lockedHelper?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(cli("lock", manifest).status).toBe(0);
    expect(readFileSync(join(example, "piship.lock"), "utf8")).toBe(lock);
    expect(cli("build", manifest).status).toBe(0);
    const command = join(root, "dist/mypi/bin/mypi");
    expect(existsSync(command)).toBe(true);
    createAmbientResources(temp);
    const env = {
      ...process.env,
      PISHIP_STATE_HOME: join(temp, "state"),
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
      PI_CODING_AGENT_DIR: join(temp, "hostile-pi"),
    };
    const launch =
      process.platform === "win32"
        ? spawnSync("cmd.exe", ["/d", "/s", "/c", `${command}.cmd --smoke`], {
            cwd: temp,
            env,
            encoding: "utf8",
          })
        : spawnSync(command, ["--smoke"], { cwd: temp, env, encoding: "utf8" });
    expect(launch.status, launch.stderr).toBe(0);
    const result = JSON.parse(launch.stdout.trim()) as {
      initialized: boolean;
      piVersion: string;
      agentDir: string;
      skills: string[];
      extensions: number;
      extensionPaths: string[];
      prompts: string[];
      themes: string[];
      instructions: string[];
    };
    expect(result).toMatchObject({
      initialized: true,
      piVersion: "0.87.1",
      skills: ["demo-skill"],
      extensions: 1,
      prompts: ["demo"],
      themes: [],
    });
    expect(result.agentDir).toContain(join(temp, "state", "mypi"));
    expect(result.instructions).toEqual([
      join(root, "dist/mypi/resources/resources/AGENTS.md"),
    ]);
    expect(result.extensionPaths).toEqual([
      join(root, "dist/mypi/resources/resources/extensions/demo"),
    ]);
    expect(existsSync(join(temp, "home", ".pi", "agent", "auth.json"))).toBe(
      false,
    );
    writeFileSync(
      join(example, "resources", "extensions", "demo", "helper.ts"),
      'export const helper = "changed";\n',
    );
    expect(cli("build", manifest).stderr).toContain("stale");
    expect(cli("lock", manifest).status).toBe(0);
    const updated = readFileSync(join(example, "piship.lock"), "utf8");
    expect(updated).not.toBe(lock);
  });
  it("rejects managed manifests before lock or build output", () => {
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
      expect(result.stderr).toContain("managed is not runnable");
    }
    expect(existsSync(join(temp, "piship.lock"))).toBe(false);
    expect(existsSync(join(root, "dist/managedblocked"))).toBe(false);
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
