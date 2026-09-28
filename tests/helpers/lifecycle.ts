import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  createReadStream,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, inject, onTestFinished } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../examples/demo-company/fixtures/local-services.mjs";
import { branded, type Result } from "./distribution.js";

// Shared, immutable release fixtures for the production lifecycle scenarios.
// The two demo releases, the `piship build` payload, and the two signed
// channel generations are built once per test run, by whichever scenario file
// gets there first. Every scenario then works on its own install, state,
// channel directory, and fixture services, so the scenarios share no mutable
// state and Vitest can run them in parallel.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
export const windows = process.platform === "win32";
export const target = `${process.platform}-${process.arch}`;
export const KEY_ID = "acme-e2e";

export type Services = Awaited<ReturnType<typeof startLocalServices>>;

export interface LifecycleReleases {
  /** Owner signing key (private) and its pinned public half. */
  readonly key: string;
  readonly publicKey: string;
  /** acmecode 1.0.0 and 1.1.0 release archives for this target. */
  readonly first: string;
  readonly second: string;
  /** Payload inventories of the 1.0.0 release and of `piship build`. */
  readonly releaseInventory: string;
  readonly buildInventory: string;
  /** Signed stable channels offering 1.1.0: sequence 1 and sequence 2. */
  readonly channels: Readonly<Record<1 | 2, string>>;
}

interface Run {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function baseEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, PISHIP_NO_BROWSER: "1" };
  delete env.PISHIP_BUILD_INPUT;
  delete env.PISHIP_SANDBOX_ADAPTER;
  return env;
}

/** Run the PiShip CLI without blocking, so independent builds overlap. */
function piship(
  args: readonly string[],
  options: { cwd: string; env: NodeJS.ProcessEnv },
): Promise<Run> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [bin, ...args], options);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.stdin.end();
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function succeed(
  args: readonly string[],
  options: { cwd: string; env: NodeJS.ProcessEnv },
): Promise<Run> {
  const done = await piship(args, options);
  if (done.status !== 0)
    throw new Error(
      `piship ${args.join(" ")} exited ${done.status}: ${done.stderr || done.stdout}`,
    );
  return done;
}

/** The demo manifest the owner pins its release key into, at `version`. */
function prepareDistribution(
  directory: string,
  publicKey: string,
  version: string,
): string {
  cpSync(join(root, "examples", "demo-company"), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  let source = readFileSync(manifest, "utf8")
    .replace(
      "provider: system",
      "provider: file\n    acknowledgePlaintext: true",
    )
    .replace("127.0.0.1:8765", "127.0.0.1")
    .replace(
      "    keys: []",
      `    keys:\n      - id: ${KEY_ID}\n        publicKey: ${publicKey}`,
    )
    .replace(/^ {2}version: \d+\.\d+\.\d+$/m, `  version: ${version}`);
  if (windows)
    source = source.replace(
      "  required: true\n  filesystem:",
      "  required: false\n  filesystem:",
    );
  writeFileSync(manifest, source);
  return manifest;
}

async function buildReleases(directory: string): Promise<LifecycleReleases> {
  const started = Date.now();
  const env = { ...baseEnv(), PISHIP_STATE_HOME: join(directory, "state") };
  const options = { cwd: directory, env };
  // The owner generates a signing key and pins its public half.
  const key = join(directory, "keys", "release.pem");
  mkdirSync(join(directory, "keys"));
  const keygen = await succeed(["keygen", key, "--id", KEY_ID], options);
  const publicKey = /publicKey: (\S+)/.exec(keygen.stdout)?.[1];
  if (!publicKey) throw new Error(`keygen printed no public key`);
  const manifests = Object.fromEntries(
    await Promise.all(
      ["1.0.0", "1.1.0"].map(async (version) => {
        const manifest = prepareDistribution(
          join(directory, version, "distribution"),
          publicKey,
          version,
        );
        await succeed(["lock", manifest], options);
        return [version, manifest] as const;
      }),
    ),
  );
  const archive = (version: string) =>
    join(
      directory,
      version,
      "out",
      "releases",
      `acmecode-${version}-${target}.tar.gz`,
    );
  // Both releases and the plain build are independent: build them together.
  await Promise.all([
    ...["1.0.0", "1.1.0"].map(async (version) => {
      const built = await succeed(
        [
          "release",
          manifests[version] as string,
          "--out",
          join(directory, version, "out"),
        ],
        options,
      );
      if (!built.stdout.includes(`acmecode-${version}-${target}`))
        throw new Error(`release ${version} did not report its archive`);
    }),
    succeed(["build", manifests["1.0.0"] as string], {
      ...options,
      cwd: join(directory, "1.0.0"),
    }),
  ]);
  // Two generations of the signed stable channel offering 1.1.0.
  const channels = {
    1: join(directory, "channel-1"),
    2: join(directory, "channel-2"),
  };
  await Promise.all(
    ([1, 2] as const).map(async (sequence) => {
      mkdirSync(channels[sequence]);
      const copy = join(channels[sequence], `acmecode-1.1.0-${target}.tar.gz`);
      cpSync(archive("1.1.0"), copy);
      await succeed(
        [
          "sign-channel",
          channels[sequence],
          copy,
          "--channel",
          "stable",
          "--key",
          key,
          "--key-id",
          KEY_ID,
          "--sequence",
          String(sequence),
        ],
        options,
      );
    }),
  );
  console.info(
    `lifecycle fixtures: 2 releases, 1 build, 2 signed channels in ${Date.now() - started} ms`,
  );
  return {
    key,
    publicKey,
    first: archive("1.0.0"),
    second: archive("1.1.0"),
    releaseInventory: join(
      directory,
      "1.0.0",
      "out",
      "releases",
      `acmecode-1.0.0-${target}`,
      "payload",
      "metadata",
      "inventory.json",
    ),
    buildInventory: join(
      directory,
      "1.0.0",
      "dist",
      "acmecode",
      "metadata",
      "inventory.json",
    ),
    channels,
  };
}

/**
 * The shared release fixtures, built on first use. An atomic directory
 * create elects one builder per test run; other scenario files wait for its
 * result (or its failure) instead of building again.
 */
export async function lifecycleReleases(): Promise<LifecycleReleases> {
  const directory = inject("lifecycleFixtures");
  const ready = join(directory, "ready.json");
  const failed = join(directory, "failed.txt");
  let builder = false;
  try {
    mkdirSync(join(directory, "build"));
    builder = true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  if (builder) {
    try {
      const releases = await buildReleases(join(directory, "build"));
      writeFileSync(ready, JSON.stringify(releases));
      return releases;
    } catch (error) {
      writeFileSync(failed, String((error as Error).stack ?? error));
      throw error;
    }
  }
  while (!existsSync(ready)) {
    if (existsSync(failed))
      throw new Error(
        `lifecycle fixtures failed to build:\n${readFileSync(failed, "utf8")}`,
      );
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return JSON.parse(readFileSync(ready, "utf8")) as LifecycleReleases;
}

/** Serve a directory over loopback HTTP, the way a company update host would. */
async function serve(directory: string): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  const server = createServer((request, response) => {
    const name = decodeURIComponent(
      new URL(request.url ?? "/", "http://127.0.0.1").pathname.slice(1),
    );
    const path = join(directory, name);
    if (!name || name.includes("/") || !existsSync(path)) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-length": statSync(path).size });
    createReadStream(path).pipe(response);
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

export function scan(directory: string, secrets: readonly string[]): string[] {
  const hits: string[] = [];
  const visit = (path: string) => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      if (statSync(child).isDirectory()) {
        if (name !== "node_modules") visit(child);
      } else {
        const text = readFileSync(child, "latin1");
        for (const secret of secrets)
          if (secret && text.includes(secret))
            hits.push(`${child} contains ${secret.slice(0, 10)}…`);
      }
    }
  };
  visit(directory);
  return hits;
}

export interface Scenario {
  readonly releases: LifecycleReleases;
  readonly services: Services;
  readonly temp: string;
  readonly home: string;
  readonly state: string;
  readonly install: string;
  readonly command: string;
  readonly channelDir: string;
  /** Run the PiShip CLI in this scenario's environment. */
  cli(...args: string[]): Run;
  /** Run the installed branded command; acts as the browser for sign-in. */
  run(args: string[]): Promise<Result>;
  /** Install 1.0.0 with the install script shipped inside its release. */
  installFirst(): Promise<void>;
  /** Publish a signed channel generation into this scenario's channel. */
  publish(sequence: 1 | 2): void;
}

/**
 * A fresh, isolated lifecycle environment over the shared releases: its own
 * fixture services, update host, home, state, install home, and bin home.
 * Everything is torn down when the calling test finishes.
 */
export async function lifecycleScenario(name: string): Promise<Scenario> {
  const releases = await lifecycleReleases();
  const services: Services = await startLocalServices();
  const temp = mkdtempSync(join(tmpdir(), `piship-lifecycle-${name}-`));
  const channelDir = join(temp, "channel");
  mkdirSync(channelDir);
  const host = await serve(channelDir);
  onTestFinished(async () => {
    await host.close();
    await services.close();
    rmSync(temp, { recursive: true, force: true });
  });
  const home = join(temp, "home");
  mkdirSync(home, { recursive: true });
  // On POSIX the install home is reached through a symlink, as macOS
  // temporary directories are (/var -> /private/var).
  const install = join(temp, "install");
  if (!windows) {
    mkdirSync(join(temp, "install-real"));
    symlinkSync(join(temp, "install-real"), install);
  }
  const state = join(temp, "state");
  const env: NodeJS.ProcessEnv = {
    ...baseEnv(),
    ...services.env(),
    ACMECODE_UPDATE_SOURCE: host.url,
    PISHIP_STATE_HOME: state,
    PISHIP_INSTALL_HOME: install,
    PISHIP_BIN_HOME: join(temp, "bin"),
    HOME: home,
    USERPROFILE: home,
  };
  const command = join(temp, "bin", windows ? "acmecode.cmd" : "acmecode");
  const cli = (...args: string[]): Run => {
    const done = spawnSync(process.execPath, [bin, ...args], {
      cwd: temp,
      env,
      encoding: "utf8",
    });
    return { status: done.status, stdout: done.stdout, stderr: done.stderr };
  };
  const run = (args: string[]): Promise<Result> =>
    branded(command, args, {
      cwd: temp,
      env,
      approve: (url) => services.approve(url),
    });
  return {
    releases,
    services,
    temp,
    home,
    state,
    install,
    command,
    channelDir,
    cli,
    run,
    async installFirst() {
      const extracted = join(temp, "download");
      mkdirSync(extracted);
      expect(
        spawnSync("tar", ["-xzf", releases.first, "-C", extracted], {
          encoding: "utf8",
        }).status,
      ).toBe(0);
      const releaseDir = join(extracted, `acmecode-1.0.0-${target}`);
      const installed = windows
        ? spawnSync(
            "powershell.exe",
            [
              "-NoProfile",
              "-ExecutionPolicy",
              "Bypass",
              "-File",
              join(releaseDir, "install.ps1"),
            ],
            { cwd: temp, env, encoding: "utf8" },
          )
        : spawnSync("sh", [join(releaseDir, "install.sh")], {
            cwd: temp,
            env,
            encoding: "utf8",
          });
      expect(installed.status, installed.stderr).toBe(0);
      expect(installed.stdout).toContain("Installed acmecode@1.0.0");
      rmSync(extracted, { recursive: true, force: true });
      expect((await run(["version"])).stdout).toContain("AcmeCode 1.0.0");
    },
    publish(sequence) {
      const source = releases.channels[sequence];
      for (const file of readdirSync(source))
        cpSync(join(source, file), join(channelDir, file));
    },
  };
}
