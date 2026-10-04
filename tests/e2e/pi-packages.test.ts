// Pi packages end to end, without the network: a local package and a git
// package (a local bare repository behind git's own insteadOf mapping, so the
// declared repository stays an https URL) are locked, vendored by the build
// under pi-packages/<id>, installed, and loaded file by file at launch. Pi's
// package manager installs nothing.
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PINNED_PI_VERSION } from "@piship/pi";
import { afterEach, describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
const REPOSITORY = "https://git.example.test/platform/pi-review";
const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0))
    rmSync(path, { recursive: true, force: true });
}, 180000);

function write(base: string, files: Record<string, string>): void {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(base, path)), { recursive: true });
    writeFileSync(join(base, path), content);
  }
}

function run(
  command: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
) {
  return process.platform === "win32" && command.endsWith(".cmd")
    ? spawnSync(
        "cmd.exe",
        ["/d", "/s", "/c", `call "${command}" ${args.join(" ")}`],
        {
          cwd,
          env,
          encoding: "utf8",
          windowsVerbatimArguments: true,
        },
      )
    : spawnSync(command, args, { cwd, env, encoding: "utf8" });
}

/**
 * `piship lock` refuses to resolve packages with npm older than 11: npm 10
 * (bundled with Node 22) runs a git dependency's `prepare` despite
 * `--ignore-scripts`. This test locks through the CLI, so it needs a real
 * npm 11 and is skipped, with that reason, where npm is older. CI installs
 * npm 11, so there a missing npm 11 fails the test instead of skipping it.
 */
const NPM_MAJOR = Number(
  /^(\d+)\./.exec(
    spawnSync("npm", ["--version"], {
      encoding: "utf8",
      shell: process.platform === "win32",
    }).stdout ?? "",
  )?.[1] ?? 0,
);

describe("Pi packages", () => {
  it("a local and a git package are locked, vendored, installed, and loaded per file", (context) => {
    const reason = `npm ${NPM_MAJOR} cannot lock Pi packages; piship lock requires npm 11 or later`;
    if (process.env.CI) expect(NPM_MAJOR, reason).toBeGreaterThanOrEqual(11);
    context.skip(NPM_MAJOR < 11, reason);
    const temp = mkdtempSync(join(tmpdir(), "piship-e2e-packages-"));
    temporary.push(temp);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PISHIP_INSTALL_HOME: join(temp, "install"),
      PISHIP_BIN_HOME: join(temp, "bin"),
      PISHIP_STATE_HOME: join(temp, "state"),
      HOME: join(temp, "home"),
      USERPROFILE: join(temp, "home"),
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: `url.${pathToFileURL(join(temp, "pi-review.git")).href}.insteadOf`,
      GIT_CONFIG_VALUE_0: REPOSITORY,
    };
    delete env.PISHIP_BUILD_INPUT;
    const git = (cwd: string, ...args: string[]) => {
      const result = run(
        "git",
        [
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.test",
          "-c",
          "commit.gpgsign=false",
          ...args,
        ],
        cwd,
        env,
      );
      expect(result.status, result.stderr).toBe(0);
      return result.stdout.trim();
    };
    const work = join(temp, "git-work");
    write(work, {
      "package.json": JSON.stringify({ name: "pi-review", version: "1.0.0" }),
      "prompts/review.md":
        "---\ndescription: Review the change\n---\nReview the change.\n",
    });
    git(work, "init", "--quiet", "--initial-branch=main");
    git(work, "add", "-A");
    git(work, "commit", "--quiet", "-m", "fixture");
    const commit = git(work, "rev-parse", "HEAD");
    git(temp, "clone", "--quiet", "--bare", work, join(temp, "pi-review.git"));

    const distribution = join(temp, "reviewer");
    write(distribution, {
      "resources/AGENTS.md": "# Reviewer\n",
      "packages/team/package.json": JSON.stringify({
        name: "team",
        version: "0.1.0",
        pi: { skills: ["./skills"] },
      }),
      "packages/team/skills/triage/SKILL.md":
        "---\nname: triage\ndescription: Triage an issue.\n---\nTriage.\n",
      "piship.yaml": `schema: piship/v1alpha6
app: { id: reviewer, name: Reviewer, command: reviewer, version: 1.0.0 }
runtime: { pi: "${PINNED_PI_VERSION}" }
deployment: { mode: personal }
identity: { mode: none }
credential: { provider: pi-native }
inference: { provider: pi-native }
resources:
  instructions:
    user: [./resources/AGENTS.md]
  packages:
    - id: team
      source: local
      path: ./packages/team
      class: user
    - id: pi-review
      source: git
      repository: ${REPOSITORY}
      ref: ${commit}
      class: company
packageTrust:
  git: { hosts: [git.example.test] }
  local: { paths: [./packages] }
policy:
  default: allow
updates: { channel: stable, channels: [stable] }
`,
    });
    const manifest = join(distribution, "piship.yaml");
    const cli = (...args: string[]) =>
      run(process.execPath, [bin, ...args], temp, env);
    const locked = cli("lock", manifest);
    expect(locked.status, locked.stderr).toBe(0);
    expect(
      existsSync(
        join(
          distribution,
          "piship.lock.d",
          "packages",
          "pi-review",
          "package-lock.json",
        ),
      ),
    ).toBe(true);
    const built = cli("build", manifest);
    expect(built.status, built.stderr).toBe(0);
    const artifact = join(temp, "dist", "reviewer");
    const inventory = JSON.parse(
      readFileSync(join(artifact, "metadata", "inventory.json"), "utf8"),
    ) as Record<string, string>;
    expect(Object.keys(inventory)).toEqual(
      expect.arrayContaining([
        "pi-packages/pi-review/package/prompts/review.md",
        "pi-packages/team/package/skills/triage/SKILL.md",
        "pi-packages/team/package-lock.json",
      ]),
    );
    const installed = run(
      process.execPath,
      [join(artifact, "piship.mjs"), "install", artifact],
      temp,
      env,
    );
    expect(installed.status, installed.stderr).toBe(0);
    const command = join(
      temp,
      "bin",
      process.platform === "win32" ? "reviewer.cmd" : "reviewer",
    );
    const smoke = run(command, ["--smoke"], temp, env);
    expect(smoke.status, smoke.stderr).toBe(0);
    expect(JSON.parse(smoke.stdout)).toMatchObject({
      skills: expect.arrayContaining(["triage"]),
      prompts: expect.arrayContaining(["review"]),
    });
    // Pi never saw a package: nothing was installed into its agent dir.
    expect(existsSync(join(temp, "state", "reviewer", "agent", "npm"))).toBe(
      false,
    );
    expect(existsSync(join(temp, "state", "reviewer", "agent", "git"))).toBe(
      false,
    );
  }, 600000);
});
