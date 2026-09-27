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
    expect(cli("lock", manifest).status).toBe(0);
    expect(readFileSync(join(example, "piship.lock"), "utf8")).toBe(lock);
    expect(cli("build", manifest).status).toBe(0);
    const command = join(root, "dist/mypi/bin/mypi");
    expect(existsSync(command)).toBe(true);
    for (const skillPath of [
      join(temp, "home", ".pi", "agent", "skills", "ambient"),
      join(temp, ".pi", "skills", "ambient"),
    ]) {
      mkdirSync(skillPath, { recursive: true });
      writeFileSync(
        join(skillPath, "SKILL.md"),
        "---\nname: ambient\ndescription: Must not load\n---\n",
      );
    }
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
      prompts: string[];
      instructions: string[];
    };
    expect(result).toMatchObject({
      initialized: true,
      piVersion: "0.87.1",
      skills: ["demo-skill"],
      extensions: 1,
      prompts: ["demo"],
    });
    expect(result.agentDir).toContain(join(temp, "state", "mypi"));
    expect(result.instructions).toHaveLength(1);
    expect(result.skills).not.toContain("ambient");
    expect(existsSync(join(temp, "home", ".pi", "agent", "auth.json"))).toBe(
      false,
    );
    writeFileSync(join(example, "resources", "AGENTS.md"), "changed\n");
    expect(cli("build", manifest).stderr).toContain("stale");
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
      "Pinned candidate: 0.87.1",
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
