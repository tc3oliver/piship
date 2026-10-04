// Package resolution against local fixtures only: an npm registry stub (a
// packument and tarball server on a loopback port, in a worker thread so it
// answers while npm runs synchronously) and a git fixture in a local bare
// repository, reached through git's own `url.<base>.insteadOf` configuration
// so the declared source stays an https URL.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runCommand } from "./command.js";
import {
  auditPiPackage,
  checkPiPackageInstallScripts,
  checkPiPackageSources,
} from "./gates.js";
import {
  type PackageContext,
  resolvePiPackage,
  vendorPiPackage,
} from "./resolve.js";
import { effectivePackageTrust } from "./trust.js";
import type { DeclaredPackage } from "./types.js";

type Files = Record<string, string>;
interface PublishedVersion {
  readonly manifest: Record<string, unknown>;
  readonly files?: Files;
  /** Serve different bytes than the packument's integrity describes. */
  readonly tamper?: boolean;
}

let root: string;
let registry: string;
let worker: Worker;
let env: NodeJS.ProcessEnv;

function write(base: string, files: Files): void {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(base, path)), { recursive: true });
    writeFileSync(join(base, path), content);
  }
}

function run(command: string, args: string[], cwd: string): string {
  const result = spawnSync(command, args, {
    cwd,
    env: { ...env, COPYFILE_DISABLE: "1" },
    encoding: "utf8",
  });
  if (result.status !== 0)
    throw new Error(`${command} ${args.join(" ")}: ${result.stderr}`);
  return result.stdout;
}

/** Pack an npm tarball (`package/…`) and return its bytes. */
function tarball(version: PublishedVersion): Buffer {
  const dir = mkdtempSync(join(root, "pack-"));
  write(join(dir, "package"), {
    "package.json": JSON.stringify(version.manifest),
    ...version.files,
  });
  run("tar", ["-czf", "out.tgz", "package"], dir);
  return readFileSync(join(dir, "out.tgz"));
}

const PACKAGES: Record<string, Record<string, PublishedVersion>> = {
  "@company/pi-platform": {
    "1.4.1": {
      manifest: {
        name: "@company/pi-platform",
        version: "1.4.1",
        dependencies: { "left-pad": "^1.3.0" },
      },
      files: { "extensions/platform.ts": "export default () => {};\n" },
    },
    "1.4.2": {
      manifest: {
        name: "@company/pi-platform",
        version: "1.4.2",
        keywords: ["pi-package"],
        dependencies: { "left-pad": "^1.3.0" },
        peerDependencies: { "@earendil-works/pi-coding-agent": "*" },
        pi: {
          extensions: ["./extensions/*.ts"],
          skills: ["./skills"],
          prompts: ["./prompts/*.md"],
        },
      },
      files: {
        "extensions/platform.ts":
          'import pad from "left-pad";\nexport default () => pad;\n',
        "skills/deploy/SKILL.md": "---\nname: deploy\n---\nDeploy.\n",
        "prompts/review.md": "Review.\n",
      },
    },
  },
  "left-pad": {
    "1.3.0": {
      manifest: { name: "left-pad", version: "1.3.0", main: "index.js" },
      files: { "index.js": "module.exports = (s) => s;\n" },
    },
  },
  "with-install-script": {
    "1.0.0": {
      manifest: {
        name: "with-install-script",
        version: "1.0.0",
        dependencies: { "runs-scripts": "1.0.0" },
      },
      files: { "extensions/x.ts": "export default () => {};\n" },
    },
  },
  "runs-scripts": {
    "1.0.0": {
      manifest: {
        name: "runs-scripts",
        version: "1.0.0",
        scripts: {
          postinstall:
            "node -e \"require('fs').writeFileSync('postinstall-ran','')\"",
        },
      },
      files: { "index.js": "module.exports = 1;\n" },
    },
  },
  "with-gyp": {
    "1.0.0": {
      manifest: {
        name: "with-gyp",
        version: "1.0.0",
        dependencies: { "native-dep": "1.0.0" },
      },
      files: { "extensions/x.ts": "export default () => {};\n" },
    },
  },
  "native-dep": {
    "1.0.0": {
      manifest: { name: "native-dep", version: "1.0.0" },
      files: { "binding.gyp": "{}\n", "index.js": "module.exports = 1;\n" },
    },
  },
  "bundles-pi": {
    "1.0.0": {
      manifest: {
        name: "bundles-pi",
        version: "1.0.0",
        dependencies: { "@earendil-works/pi-ai": "1.0.2" },
      },
    },
  },
  "bundles-pi-deep": {
    "1.0.0": {
      manifest: {
        name: "bundles-pi-deep",
        version: "1.0.0",
        dependencies: { "bundles-pi": "1.0.0" },
      },
    },
  },
  "@earendil-works/pi-ai": {
    "1.0.2": {
      manifest: { name: "@earendil-works/pi-ai", version: "1.0.2" },
    },
  },
  "git-dependency": {
    "1.0.0": {
      manifest: {
        name: "git-dependency",
        version: "1.0.0",
        dependencies: {
          evil: "github:attacker/repo#0123456789abcdef0123456789abcdef01234567",
        },
      },
      files: { "extensions/x.ts": "export default () => {};\n" },
    },
  },
  "ships-modules": {
    "1.0.0": {
      manifest: { name: "ships-modules", version: "1.0.0" },
      files: {
        "extensions/x.ts": 'import "evil";\nexport default () => {};\n',
        "node_modules/evil/package.json": '{"name":"evil","version":"1.0.0"}',
        "node_modules/evil/index.js": "module.exports = 1;\n",
      },
    },
  },
  tampered: {
    "1.0.0": {
      manifest: { name: "tampered", version: "1.0.0" },
      files: { "extensions/x.ts": "export default () => {};\n" },
      tamper: true,
    },
  },
};

/**
 * The registry stub: packuments, tarballs, and the npm audit bulk endpoint.
 * It posts its port, then takes its content (and later advisories) as messages.
 */
const REGISTRY = `
const { createServer } = require("node:http");
const { parentPort } = require("node:worker_threads");
let content = { packuments: {}, tarballs: {}, advisories: {} };
parentPort.on("message", (value) => {
  content = { ...content, ...value };
  parentPort.postMessage("ok");
});
const server = createServer((request, response) => {
  const path = decodeURIComponent(new URL(request.url, "http://x").pathname).slice(1);
  response.setHeader("content-type", "application/json");
  if (request.method === "POST") {
    request.resume();
    request.on("end", () => response.end(JSON.stringify(content.advisories)));
    return;
  }
  if (content.tarballs[path]) {
    response.setHeader("content-type", "application/octet-stream");
    return response.end(Buffer.from(content.tarballs[path], "base64"));
  }
  if (content.packuments[path])
    return response.end(JSON.stringify(content.packuments[path]));
  response.statusCode = 404;
  response.end("{}");
});
server.listen(0, "127.0.0.1", () => parentPort.postMessage(server.address().port));
`;

async function send(value: Record<string, unknown>): Promise<void> {
  const answered = new Promise((resolve) => worker.once("message", resolve));
  worker.postMessage(value);
  await answered;
}

async function startRegistry(): Promise<void> {
  worker = new Worker(REGISTRY, { eval: true });
  const port = await new Promise<number>((resolve) =>
    worker.once("message", resolve),
  );
  registry = `http://127.0.0.1:${port}`;
  const packuments: Record<string, unknown> = {};
  const tarballs: Record<string, string> = {};
  for (const [name, versions] of Object.entries(PACKAGES)) {
    const entries: Record<string, unknown> = {};
    for (const [version, published] of Object.entries(versions)) {
      const bytes = tarball(published);
      const file = `${name}/-/${name.split("/").at(-1)}-${version}.tgz`;
      tarballs[file] = (
        published.tamper ? tarball({ ...published, files: {} }) : bytes
      ).toString("base64");
      entries[version] = {
        ...published.manifest,
        ...(published.manifest.scripts ? { hasInstallScript: true } : {}),
        dist: {
          tarball: `${registry}/${file}`,
          integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
          shasum: createHash("sha1").update(bytes).digest("hex"),
        },
      };
    }
    packuments[name] = {
      name,
      "dist-tags": { latest: Object.keys(versions).at(-1) },
      versions: entries,
    };
  }
  await send({ packuments, tarballs });
}

const SECURITY_REPOSITORY = "https://git.example.test/platform/pi-security";
let securityCommit: string;
let securityTag: string;

function createGitFixture(): void {
  const work = join(root, "git-work");
  write(work, {
    "package.json": JSON.stringify({
      name: "pi-security",
      version: "2.0.0",
      dependencies: { "left-pad": "1.3.0" },
      devDependencies: { "never-installed": "9.9.9" },
    }),
    "extensions/guard.ts": "export default () => {};\n",
    "prompts/audit.md": "Audit.\n",
  });
  const git = (...args: string[]) =>
    run(
      "git",
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "tag.gpgsign=false",
        ...args,
      ],
      work,
    ).trim();
  git("init", "--quiet", "--initial-branch=main");
  git("add", "-A");
  git("commit", "--quiet", "-m", "fixture");
  git("tag", "v2.0.0");
  securityCommit = git("rev-parse", "HEAD");
  securityTag = "v2.0.0";
  run(
    "git",
    ["clone", "--quiet", "--bare", work, join(root, "pi-security.git")],
    root,
  );
  // Every git call sees the bare repository behind the https URL.
  env.GIT_CONFIG_COUNT = "1";
  env.GIT_CONFIG_KEY_0 = `url.${pathToFileURL(join(root, "pi-security.git")).href}.insteadOf`;
  env.GIT_CONFIG_VALUE_0 = SECURITY_REPOSITORY;
}

/**
 * Another git fixture behind `https://git.example.test/fixtures/<name>`,
 * committed after `prepare` (for content `write` cannot make), and its SHA.
 */
function gitFixture(
  name: string,
  files: Files,
  prepare?: (work: string) => void,
): { repository: string; commit: string } {
  const work = join(root, `git-${name}`);
  write(work, files);
  prepare?.(work);
  const git = (...args: string[]) =>
    run(
      "git",
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.autocrlf=false",
        ...args,
      ],
      work,
    ).trim();
  git("init", "--quiet", "--initial-branch=main");
  git("add", "-A");
  git("commit", "--quiet", "-m", "fixture");
  const commit = git("rev-parse", "HEAD");
  run("git", ["clone", "--quiet", "--bare", work, `${work}.git`], root);
  const repository = `https://git.example.test/fixtures/${name}`;
  const index = Number(env.GIT_CONFIG_COUNT ?? "0");
  env.GIT_CONFIG_COUNT = String(index + 1);
  env[`GIT_CONFIG_KEY_${index}`] =
    `url.${pathToFileURL(`${work}.git`).href}.insteadOf`;
  env[`GIT_CONFIG_VALUE_${index}`] = repository;
  return { repository, commit };
}

const gitPackage = (
  id: string,
  fixture: { repository: string; commit: string },
): DeclaredPackage => ({
  id,
  source: "git",
  repository: fixture.repository,
  ref: fixture.commit,
  class: "company",
  filters: {},
});

/** The context with a runner that records every command before running it. */
function recorded(base: PackageContext): {
  context: PackageContext;
  calls: string[][];
} {
  const calls: string[][] = [];
  return {
    calls,
    context: {
      ...base,
      run: (command, args, options) => {
        calls.push([command, ...args]);
        return runCommand(command, args, options);
      },
    },
  };
}

const npmCalls = (calls: string[][]) =>
  calls.filter(([command]) => command === "npm");

beforeAll(async () => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "piship-packages-")));
  // npm and git read only this suite's configuration, never the developer's.
  env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !/^(npm_|GIT_)/i.test(key)),
  );
  writeFileSync(join(root, "npmrc"), "");
  Object.assign(env, {
    HOME: root,
    USERPROFILE: root,
    GIT_CONFIG_NOSYSTEM: "1",
    npm_config_userconfig: join(root, "npmrc"),
    npm_config_cache: join(root, "npm-cache"),
    npm_config_update_notifier: "false",
    // npm retries a tarball that fails its integrity check with backoff.
    npm_config_fetch_retries: "0",
  });
  await startRegistry();
  env.npm_config_registry = `${registry}/`;
  createGitFixture();
}, 60_000);

afterAll(async () => {
  await worker?.terminate();
  if (root) rmSync(root, { recursive: true, force: true });
});

function context(mode: "managed" | "personal" = "managed"): PackageContext {
  const distributionDir = join(root, "distribution");
  mkdirSync(distributionDir, { recursive: true });
  return {
    distributionDir,
    mode,
    trust: effectivePackageTrust(
      mode === "managed"
        ? {
            npm: { requireIntegrity: true },
            git: { hosts: ["git.example.test"], requireCommitSha: true },
            local: { paths: ["./packages"] },
          }
        : undefined,
      mode,
    ),
    targets: ["darwin-arm64", "linux-x64", "win32-x64"],
    env,
    workDir: root,
  };
}

const npmPackage = (
  name: string,
  version: string,
  extra: Partial<DeclaredPackage> = {},
): DeclaredPackage =>
  ({
    id: name.replace(/[@/]/g, "-").replace(/^-/, ""),
    source: "npm",
    package: name,
    version,
    class: "company",
    filters: {},
    ...(extra as object),
  }) as DeclaredPackage;

const SLOW = 120_000;

describe("npm packages", () => {
  it(
    "lock to an exact version, integrity, lockfile, and inventory; build reproduces them",
    () => {
      const declaration = npmPackage("@company/pi-platform", "1.4.2", {
        registry,
      } as Partial<DeclaredPackage>);
      const resolved = resolvePiPackage(declaration, context());
      const { locked } = resolved;
      expect(locked).toMatchObject({
        id: "company-pi-platform",
        source: "npm",
        version: "1.4.2",
        url: `${registry}/@company/pi-platform/-/pi-platform-1.4.2.tgz`,
        optionalDependencies: {
          "darwin-arm64": [],
          "linux-x64": [],
          "win32-x64": [],
        },
      });
      expect(locked.integrity).toMatch(/^sha512-/);
      expect(
        locked.resources.map((item) => `${item.kind}:${item.path}`),
      ).toEqual([
        "extensions:extensions/platform.ts",
        "skills:skills/deploy/SKILL.md",
        "prompts:prompts/review.md",
      ]);
      expect(locked.files).toBe(4);
      expect(locked.tree).toMatch(/^sha256-[0-9a-f]{64}$/);
      expect(resolved.dependencies.map((item) => item.path)).toEqual([
        "node_modules/@company/pi-platform",
        "node_modules/left-pad",
      ]);
      // The peer Pi package is never installed or locked.
      expect(resolved.lockfile).not.toContain("node_modules/@earendil-works");

      const directory = join(root, "vendor", locked.id);
      const vendored = vendorPiPackage(
        declaration,
        { locked, lockfile: resolved.lockfile },
        context(),
        directory,
      );
      expect(vendored.locked).toEqual(locked);
      expect(
        existsSync(join(vendored.packageRoot, "extensions", "platform.ts")),
      ).toBe(true);
      expect(existsSync(join(directory, "node_modules", "left-pad"))).toBe(
        true,
      );
      expect(
        existsSync(join(directory, "node_modules", "@earendil-works")),
      ).toBe(false);
    },
    SLOW,
  );

  it(
    "resolve a personal range to the newest matching version",
    () => {
      const { locked, lockfile } = resolvePiPackage(
        npmPackage("@company/pi-platform", "~1.4.0"),
        context("personal"),
      );
      expect(locked.version).toBe("1.4.2");
      expect(lockfile).not.toMatch(/"version": "[~^]/);
    },
    SLOW,
  );

  it("refuse a range in managed before any registry call", () => {
    expect(() =>
      resolvePiPackage(npmPackage("@company/pi-platform", "^1.4.0"), context()),
    ).toThrow(/not exact/);
  });

  it(
    "never run lifecycle scripts, and stop at the install-script gate",
    () => {
      const declaration = npmPackage("with-install-script", "1.0.0");
      const resolved = resolvePiPackage(declaration, context());
      const script = resolved.dependencies.find(
        (item) => item.name === "runs-scripts",
      );
      expect(script?.installScript).toBe(true);
      const directory = join(root, "vendor", "with-install-script");
      vendorPiPackage(declaration, resolved, context(), directory);
      expect(
        existsSync(
          join(directory, "node_modules", "runs-scripts", "postinstall-ran"),
        ),
      ).toBe(false);
      expect(() =>
        checkPiPackageSources(declaration.id, resolved.dependencies, [
          registry,
        ]),
      ).toThrow(
        /install-script: pi-packages\/with-install-script\/node_modules\/runs-scripts@1\.0\.0 runs npm lifecycle scripts/,
      );
      expect(() =>
        checkPiPackageSources(
          declaration.id,
          resolved.dependencies,
          [registry],
          "Release",
          ["pi-packages/with-install-script/node_modules/runs-scripts@1.0.0"],
        ),
      ).not.toThrow();
    },
    SLOW,
  );

  it(
    "count a dependency's binding.gyp as an install script",
    () => {
      const resolved = resolvePiPackage(
        npmPackage("with-gyp", "1.0.0"),
        context(),
      );
      expect(
        resolved.dependencies.find((item) => item.name === "native-dep")
          ?.installScript,
      ).toBe(true);
      expect(() =>
        checkPiPackageSources("with-gyp", resolved.dependencies, [registry]),
      ).toThrow(/install-script/);
    },
    SLOW,
  );

  it(
    "apply release.sources to the whole closure",
    () => {
      const resolved = resolvePiPackage(
        npmPackage("@company/pi-platform", "1.4.2"),
        context(),
      );
      expect(() =>
        checkPiPackageSources("company-pi-platform", resolved.dependencies, [
          "https://registry.npmjs.org",
        ]),
      ).toThrow(/source: .* comes from http:\/\/127\.0\.0\.1/);
    },
    SLOW,
  );

  it(
    "refuse a Pi host package in the package's or a dependency's dependencies",
    () => {
      expect(() =>
        resolvePiPackage(npmPackage("bundles-pi", "1.0.0"), context()),
      ).toThrow(
        /the package lists host-provided @earendil-works\/pi-ai in dependencies/,
      );
      expect(() =>
        resolvePiPackage(npmPackage("bundles-pi-deep", "1.0.0"), context()),
      ).toThrow(/host-provided @earendil-works\/pi-ai/);
    },
    SLOW,
  );

  it(
    "fail on a tarball that does not match its integrity",
    () => {
      expect(() =>
        resolvePiPackage(npmPackage("tampered", "1.0.0"), context()),
      ).toThrow(/integrity|EINTEGRITY/i);
    },
    SLOW,
  );

  it(
    "refuse a build whose lockfile differs from the locked sha256",
    () => {
      const declaration = npmPackage("@company/pi-platform", "1.4.2");
      const resolved = resolvePiPackage(declaration, context());
      expect(() =>
        vendorPiPackage(
          declaration,
          { locked: resolved.locked, lockfile: `${resolved.lockfile} ` },
          context(),
          join(root, "vendor", "drifted-lockfile"),
        ),
      ).toThrow(/does not match its sha256/);
      expect(existsSync(join(root, "vendor", "drifted-lockfile"))).toBe(false);
    },
    SLOW,
  );

  it(
    "audit the package lockfile under release.vulnerabilities",
    async () => {
      const resolved = resolvePiPackage(
        npmPackage("@company/pi-platform", "1.4.2"),
        context(),
      );
      const policy = { failOn: "high" as const, allow: [] };
      const clean = await auditPiPackage(
        "company-pi-platform",
        resolved,
        policy,
        {
          mode: "managed",
          registry,
        },
      );
      expect(clean.report?.verdict).toBe("passed");
      await send({
        advisories: {
          "left-pad": [
            {
              id: 1,
              url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
              title: "fixture advisory",
              severity: "critical",
              vulnerable_versions: "<2.0.0",
              cwe: [],
              cvss: { score: 9.8, vectorString: null },
            },
          ],
        },
      });
      await expect(
        auditPiPackage("company-pi-platform", resolved, policy, {
          mode: "managed",
          registry,
        }),
      ).rejects.toThrow(/GHSA-aaaa-bbbb-cccc \(left-pad, critical\)/);
      await send({ advisories: {} });
    },
    SLOW,
  );

  it("an unreachable audit endpoint fails managed and warns personal", async () => {
    const unreachable = () => {
      throw new Error("ECONNREFUSED");
    };
    const files = { manifest: "{}", lockfile: "{}" };
    const policy = { failOn: "high" as const, allow: [] };
    await expect(
      auditPiPackage("x", files, policy, {
        mode: "managed",
        scanner: unreachable,
      }),
    ).rejects.toThrow(/ECONNREFUSED/);
    expect(
      await auditPiPackage("x", files, policy, {
        mode: "personal",
        scanner: unreachable,
        now: new Date("2026-10-04T00:00:00Z"),
      }),
    ).toEqual({
      id: "x",
      scannedAt: "2026-10-04T00:00:00.000Z",
      warning: "package x was not scanned: ECONNREFUSED",
    });
  });
});

describe("git packages", () => {
  const git = (ref: string): DeclaredPackage => ({
    id: "pi-security",
    source: "git",
    repository: SECURITY_REPOSITORY,
    ref,
    class: "company",
    filters: {},
  });

  it(
    "lock a full SHA with its tree from git archive; build reproduces them",
    () => {
      const resolved = resolvePiPackage(git(securityCommit), context());
      expect(resolved.locked).toMatchObject({
        source: "git",
        url: SECURITY_REPOSITORY,
        commit: securityCommit,
        files: 3,
      });
      expect(resolved.locked.resources.map((item) => item.path)).toEqual([
        "extensions/guard.ts",
        "prompts/audit.md",
      ]);
      // Only runtime dependencies reach the generated npm root.
      expect(JSON.parse(resolved.manifest)).toMatchObject({
        dependencies: { "left-pad": "1.3.0" },
      });
      expect(resolved.manifest).not.toContain("never-installed");
      const directory = join(root, "vendor", "pi-security");
      const vendored = vendorPiPackage(
        git(securityCommit),
        resolved,
        context(),
        directory,
      );
      expect(vendored.locked).toEqual(resolved.locked);
      expect(existsSync(join(directory, "package", ".git"))).toBe(false);
      expect(existsSync(join(directory, "node_modules", "left-pad"))).toBe(
        true,
      );
    },
    SLOW,
  );

  it(
    "resolve a personal tag to its commit SHA",
    () => {
      expect(
        resolvePiPackage(git(securityTag), context("personal")).locked.commit,
      ).toBe(securityCommit);
    },
    SLOW,
  );

  it("refuse a tag or an abbreviated SHA in managed", () => {
    expect(() => resolvePiPackage(git(securityTag), context())).toThrow(
      /requireCommitSha/,
    );
    expect(() =>
      resolvePiPackage(git(securityCommit.slice(0, 12)), context()),
    ).toThrow(/abbreviated/);
  });

  it(
    "refuse a build whose content differs from the locked tree digest",
    () => {
      const resolved = resolvePiPackage(git(securityCommit), context());
      expect(() =>
        vendorPiPackage(
          git(securityCommit),
          {
            locked: { ...resolved.locked, tree: `sha256-${"0".repeat(64)}` },
            lockfile: resolved.lockfile,
          },
          context(),
          join(root, "vendor", "wrong-tree"),
        ),
      ).toThrow(/tree digest and file count differs/);
    },
    SLOW,
  );
});

describe("local packages", () => {
  const local: DeclaredPackage = {
    id: "local-company",
    source: "local",
    path: "./packages/company",
    class: "company",
    filters: {},
  };

  it(
    "lock a content digest and detect a change at build",
    () => {
      const ctx = context();
      write(join(ctx.distributionDir, "packages", "company"), {
        "package.json": JSON.stringify({ name: "company", version: "0.1.0" }),
        "skills/onboarding/SKILL.md": "---\nname: onboarding\n---\n",
        "node_modules/stale/index.js": "ignored\n",
      });
      const resolved = resolvePiPackage(local, ctx);
      expect(resolved.locked).toMatchObject({
        source: "local",
        files: 2,
      });
      write(join(ctx.distributionDir, "packages", "company"), {
        "skills/onboarding/SKILL.md": "---\nname: onboarding\n---\nchanged\n",
      });
      expect(() =>
        vendorPiPackage(local, resolved, ctx, join(root, "vendor", "local")),
      ).toThrow(/tree digest and file count differs/);
    },
    SLOW,
  );

  it("refuse a path outside packageTrust.local.paths", () => {
    const ctx = context();
    write(join(ctx.distributionDir, "elsewhere"), { "package.json": "{}" });
    expect(() =>
      resolvePiPackage({ ...local, path: "./elsewhere" }, ctx),
    ).toThrow(/outside packageTrust.local.paths/);
  });
});

describe("lock-time script execution and shipped modules", () => {
  const GIT_SPEC =
    "github:attacker/repo#0123456789abcdef0123456789abcdef01234567";

  it.each([
    GIT_SPEC,
    "git+ssh://git@github.com/attacker/repo.git",
    "https://example.test/evil.tgz",
    "file:../evil",
    "link:../evil",
    "npm:left-pad@1.3.0",
    "attacker/repo",
    "latest",
  ])("refuse a local package's dependency %s before npm runs", (spec) => {
    const { context: ctx, calls } = recorded(context());
    write(join(ctx.distributionDir, "packages", "deps"), {
      "package.json": JSON.stringify({
        name: "deps",
        version: "1.0.0",
        optionalDependencies: { evil: spec },
      }),
    });
    expect(() =>
      resolvePiPackage(
        {
          id: "deps",
          source: "local",
          path: "./packages/deps",
          class: "company",
          filters: {},
        },
        ctx,
      ),
    ).toThrow(/only registry versions and semver ranges/);
    expect(npmCalls(calls)).toEqual([]);
  });

  it(
    "refuse a git package's git dependency before npm runs",
    () => {
      const fixture = gitFixture("git-dependency", {
        "package.json": JSON.stringify({
          name: "git-dependency",
          version: "1.0.0",
          dependencies: { evil: GIT_SPEC },
        }),
        ".npmrc": "git=/tmp/pwn.sh\n",
        "extensions/x.ts": "export default () => {};\n",
      });
      const { context: ctx, calls } = recorded(context());
      expect(() =>
        resolvePiPackage(gitPackage("git-dependency", fixture), ctx),
      ).toThrow(/evil@"github:attacker\/repo#0123/);
      expect(calls.some(([command]) => command === "git")).toBe(true);
      expect(npmCalls(calls)).toEqual([]);
    },
    SLOW,
  );

  it(
    "refuse an npm package whose published dependencies hold a git spec before npm installs anything",
    () => {
      const { context: ctx, calls } = recorded(context());
      expect(() =>
        resolvePiPackage(npmPackage("git-dependency", "1.0.0"), ctx),
      ).toThrow(/evil@"github:attacker/);
      expect(npmCalls(calls).map((call) => call[1])).toEqual(["view", "view"]);
    },
    SLOW,
  );

  it(
    "run every npm call with a git that refuses to run",
    () => {
      const stubs: { status: number | null }[] = [];
      const base = context();
      resolvePiPackage(npmPackage("@company/pi-platform", "1.4.2"), {
        ...base,
        run: (command, args, options) => {
          if (command === "npm") {
            const git = args.find((arg) => arg.startsWith("--git="));
            expect(git).toBeDefined();
            stubs.push(
              spawnSync((git as string).slice("--git=".length), ["clone"], {
                shell: process.platform === "win32",
              }),
            );
          }
          return runCommand(command, args, options);
        },
      });
      expect(stubs.length).toBeGreaterThanOrEqual(4);
      for (const stub of stubs) expect(stub.status).toBe(1);
    },
    SLOW,
  );

  it(
    "refuse a git package that ships node_modules, before npm runs",
    () => {
      const fixture = gitFixture("ships-modules", {
        "package.json": JSON.stringify({ name: "ships", version: "1.0.0" }),
        "extensions/x.ts": 'import "evil";\nexport default () => {};\n',
        "lib/node_modules/evil/index.js": "module.exports = 1;\n",
      });
      const { context: ctx, calls } = recorded(context());
      expect(() =>
        resolvePiPackage(gitPackage("ships-modules", fixture), ctx),
      ).toThrow(/lib\/node_modules ships its own node_modules/);
      expect(npmCalls(calls)).toEqual([]);
    },
    SLOW,
  );

  it(
    "refuse an npm package whose tarball ships node_modules the lockfile does not install",
    () => {
      expect(() =>
        resolvePiPackage(npmPackage("ships-modules", "1.0.0"), context()),
      ).toThrow(
        /node_modules\/ships-modules\/node_modules\/evil is not a package the npm lockfile installs/,
      );
    },
    SLOW,
  );

  it(
    "never copy a local package's node_modules",
    () => {
      const ctx = context();
      write(join(ctx.distributionDir, "packages", "with-modules"), {
        "package.json": JSON.stringify({ name: "with-modules" }),
        "skills/x/SKILL.md": "---\nname: x\n---\n",
        "node_modules/evil/index.js": "module.exports = 1;\n",
        "skills/x/node_modules/evil/index.js": "module.exports = 1;\n",
      });
      const declaration: DeclaredPackage = {
        id: "with-modules",
        source: "local",
        path: "./packages/with-modules",
        class: "company",
        filters: {},
      };
      const resolved = resolvePiPackage(declaration, ctx);
      expect(resolved.locked.files).toBe(2);
      const vendored = vendorPiPackage(
        declaration,
        resolved,
        ctx,
        join(root, "vendor", "with-modules"),
      );
      expect(existsSync(join(vendored.packageRoot, "node_modules"))).toBe(
        false,
      );
      expect(
        existsSync(join(vendored.packageRoot, "skills", "x", "node_modules")),
      ).toBe(false);
    },
    SLOW,
  );

  it(
    "count a git or local package root's own install script or binding.gyp",
    () => {
      const ctx = context();
      write(join(ctx.distributionDir, "packages", "native"), {
        "package.json": JSON.stringify({ name: "native", version: "1.0.0" }),
        "binding.gyp": "{}\n",
        "skills/x/SKILL.md": "---\nname: x\n---\n",
      });
      const local = resolvePiPackage(
        {
          id: "native",
          source: "local",
          path: "./packages/native",
          class: "company",
          filters: {},
        },
        ctx,
      );
      expect(local.ownInstallScript).toBe(`package@${local.locked.tree}`);
      expect(() =>
        checkPiPackageInstallScripts(
          "native",
          local.dependencies,
          local.ownInstallScript,
        ),
      ).toThrow(
        /install-script: pi-packages\/native\/package@sha256-[0-9a-f]{64} runs npm lifecycle scripts/,
      );
      expect(() =>
        checkPiPackageInstallScripts(
          "native",
          local.dependencies,
          local.ownInstallScript,
          "Release",
          [`pi-packages/native/package@${local.locked.tree}`],
        ),
      ).not.toThrow();

      const fixture = gitFixture("postinstall", {
        "package.json": JSON.stringify({
          name: "postinstall",
          version: "1.0.0",
          scripts: { postinstall: "node pwn.js" },
        }),
        "prompts/a.md": "A.\n",
      });
      const git = resolvePiPackage(gitPackage("postinstall", fixture), ctx);
      expect(git.ownInstallScript).toBe(`package@${fixture.commit}`);
    },
    SLOW,
  );

  it(
    "refuse a symlinked package.json in a git package before reading it or running npm",
    () => {
      writeFileSync(
        join(root, "outside.json"),
        JSON.stringify({ name: "outside" }),
      );
      const fixture = gitFixture(
        "symlinked-manifest",
        { "prompts/a.md": "A.\n" },
        (work) =>
          symlinkSync(join(root, "outside.json"), join(work, "package.json")),
      );
      const { context: ctx, calls } = recorded(context());
      expect(() =>
        resolvePiPackage(gitPackage("symlinked-manifest", fixture), ctx),
      ).toThrow(/package\.json is a symlink/);
      expect(npmCalls(calls)).toEqual([]);
    },
    SLOW,
  );

  it(
    "archive git content as committed, whatever the repository's .gitattributes say",
    () => {
      const content = "one\ntwo $Format:%H$ $Id$\n";
      const fixture = gitFixture("attributes", {
        ".gitattributes": "* text eol=crlf\n*.md export-subst ident\n",
        "package.json": JSON.stringify({ name: "attributes" }),
        "prompts/a.md": content,
      });
      // A user-level autocrlf in the build environment does not apply either.
      const ctx = {
        ...context(),
        env: { ...env, GIT_CONFIG_PARAMETERS: "'core.autocrlf'='true'" },
      };
      const resolved = resolvePiPackage(gitPackage("attributes", fixture), ctx);
      expect(resolved.locked.resources).toEqual([
        {
          kind: "prompts",
          path: "prompts/a.md",
          sha256: createHash("sha256").update(content).digest("hex"),
        },
      ]);
      const vendored = vendorPiPackage(
        gitPackage("attributes", fixture),
        resolved,
        ctx,
        join(root, "vendor", "attributes"),
      );
      expect(
        readFileSync(join(vendored.packageRoot, "prompts", "a.md"), "utf8"),
      ).toBe(content);
    },
    SLOW,
  );
});
