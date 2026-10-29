import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, launcher } from "../helpers/distribution.js";

// A real command decided by a rule of the piship.routine pack, not by a rule
// the test wrote: the demo in Build mode with its manifest untouched
// otherwise, a sandboxed `git status`, and the audit log naming the rule.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const temporary: string[] = [];
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

describe.skipIf(process.platform === "win32")("the routine pack", () => {
  it("decides a sandboxed git status by its own rule", async () => {
    const services = await startLocalServices();
    closers.push(() => services.close());
    const temp = realpathSync(
      mkdtempSync(join(tmpdir(), "piship-routine-e2e-")),
    );
    temporary.push(temp);
    const directory = join(temp, "distribution");
    cpSync(join(root, "examples", "demo-company"), directory, {
      recursive: true,
    });
    const manifest = join(directory, "piship.yaml");
    const source = readFileSync(manifest, "utf8")
      .replace(
        "provider: system",
        "provider: file\n    acknowledgePlaintext: true",
      )
      .replace("127.0.0.1:8765", "127.0.0.1")
      .replace("defaultMode: plan", "defaultMode: build");
    if (!source.includes("defaultMode: build") || source.includes("acme.shell"))
      throw new Error("demo manifest patch did not apply");
    writeFileSync(manifest, source);
    const home = join(temp, "home");
    mkdirSync(home, { recursive: true });
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...services.env(),
      PISHIP_STATE_HOME: join(temp, "state"),
      PISHIP_NO_BROWSER: "1",
      HOME: home,
    };
    delete env.PISHIP_BUILD_INPUT;
    delete env.PISHIP_SANDBOX_ADAPTER;
    for (const step of ["lock", "build"]) {
      const done = spawnSync(process.execPath, [bin, step, manifest], {
        cwd: temp,
        env,
        encoding: "utf8",
      });
      expect(done.status, done.stderr).toBe(0);
    }
    const command = launcher(join(temp, "dist", "acmecode"), "acmecode");
    const project = join(temp, "project");
    mkdirSync(project, { recursive: true });
    const init = spawnSync("git", ["init", "-q"], { cwd: project });
    expect(init.status, String(init.stderr)).toBe(0);
    const login = await branded(command, ["login"], {
      cwd: project,
      env,
      approve: (url: string) => services.approve(url),
    });
    expect(login.status, login.stderr).toBe(0);

    services.knobs.gatewayMode = "script";
    services.knobs.toolScript = [
      { name: "bash", arguments: { command: "git status" } },
    ];
    services.state.toolResults = [];
    const run = await branded(command, ["--smoke-model"], {
      cwd: project,
      env,
      timeoutMs: 120_000,
    });
    expect(run.status, run.stderr).toBe(0);
    expect(services.state.toolResults[0]).toMatch(/On branch|No commits yet/);
    const events = readFileSync(
      join(temp, "state", "acmecode", "logs", "audit.jsonl"),
      "utf8",
    )
      .split("\n")
      .filter(Boolean)
      .map(
        (line) =>
          JSON.parse(line) as {
            event: string;
            resource?: string;
            rule?: string;
          },
      );
    expect(
      events
        .filter(
          (event) =>
            event.event === "tool.allowed" && event.resource === "bash",
        )
        .map((event) => event.rule)
        .sort(),
    ).toEqual(["acme.tools", "piship.routine.git.read.git-status"]);
  }, 300000);
});
