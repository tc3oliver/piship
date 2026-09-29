import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
import {
  clearPlatformStore,
  expectOwnParts,
  LIVE_SECRET_STORE,
  platformStoreRefs,
  primaryRefs,
  type Storage,
  shareKeychainSearchList,
} from "./secret-store.js";
import { acquireLease, runAll, storeScenarioTeardown } from "./teardown.js";

// Shared, immutable release fixtures for the production lifecycle scenarios.
// For each example distribution (the managed demo company and the personal
// MyPi), its two releases, the demo's `piship build` payload, and the two
// signed channel generations are built once per test run, by whichever
// scenario file needs them first, in a fixture directory of their own. Every
// scenario then works on its own install, state, channel directory, and (for
// the demo) fixture services, so the scenarios share no mutable state and
// Vitest can run them in parallel.
const root = fileURLToPath(new URL("../../", import.meta.url));
const bin = join(root, "packages/cli/dist/bin.js");
export const windows = process.platform === "win32";
export const target = `${process.platform}-${process.arch}`;
export const KEY_ID = "acme-e2e";

export type Services = Awaited<ReturnType<typeof startLocalServices>>;

export interface ReleaseFixtures {
  /** Owner signing key (private) and its pinned public half. */
  readonly key: string;
  readonly publicKey: string;
  /** The distribution's 1.0.0 and 1.1.0 release archives for this target. */
  readonly first: string;
  readonly second: string;
  /** Payload inventory of the 1.0.0 release. */
  readonly releaseInventory: string;
  /** Signed stable channels offering 1.1.0: sequence 1 and sequence 2. */
  readonly channels: Readonly<Record<1 | 2, string>>;
}

export interface LifecycleReleases extends ReleaseFixtures {
  /** Payload inventory of `piship build` for the demo 1.0.0 manifest. */
  readonly buildInventory: string;
}

/** An example distribution the lifecycle fixtures are built from. */
interface Distribution {
  /** Directory under `examples/`. */
  readonly example: string;
  /** Subdirectory of the run's fixture directory. */
  readonly fixture: string;
  /** App ID, which is also the branded command. */
  readonly id: string;
  readonly name: string;
  /** Runtime variable the manifest reads `updates.source` from. */
  readonly updateVariable: string;
  /** Also run `piship build` on the 1.0.0 manifest. */
  readonly plainBuild: boolean;
  /** The owner's edits: pin the release key and set the version. */
  patch(source: string, publicKey: string, version: string): string;
}

function pinKey(source: string, publicKey: string, version: string): string {
  return source
    .replace(
      "    keys: []",
      `    keys:\n      - id: ${KEY_ID}\n        publicKey: ${publicKey}`,
    )
    .replace(/^ {2}version: \d+\.\d+\.\d+$/m, `  version: ${version}`);
}

/**
 * The demo company, storing its secrets in the file fallback or, as the
 * example ships, in the system store. Platform store references are named
 * after the app ID alone (`piship:<id>:...`), so the system variant has an ID
 * of its own for each test run: it never meets an entry of a real install
 * or of an earlier run.
 */
function demo(storage: Storage, fixtures: string): Distribution {
  const id =
    storage === "file"
      ? "acmecode"
      : `acmelive-${createHash("sha256").update(fixtures).digest("hex").slice(0, 8)}`;
  return {
    example: "demo-company",
    fixture: storage === "file" ? "demo-company" : "demo-company-system",
    id,
    name: "AcmeCode",
    updateVariable: "ACMECODE_UPDATE_SOURCE",
    plainBuild: storage === "file",
    patch(source, publicKey, version) {
      const stored =
        storage === "file"
          ? source.replace(
              "provider: system",
              "provider: file\n    acknowledgePlaintext: true",
            )
          : source
              .replace(/^( {2}(?:id|command)): acmecode$/gm, `$1: ${id}`)
              .replace('resource: "acmecode/**"', `resource: "${id}/**"`);
      const patched = pinKey(
        stored.replace("127.0.0.1:8765", "127.0.0.1"),
        publicKey,
        version,
      );
      return windows
        ? patched.replace(
            "  required: true\n  filesystem:",
            "  required: false\n  filesystem:",
          )
        : patched;
    },
  };
}

// The personal example needs no edit beyond the key and the version: it has
// no enterprise endpoint, no system secret store, and no required sandbox.
const PERSONAL: Distribution = {
  example: "personal",
  fixture: "personal",
  id: "mypi",
  name: "MyPi",
  updateVariable: "MYPI_UPDATE_SOURCE",
  plainBuild: false,
  patch: pinKey,
};

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

/** The example manifest the owner pins its release key into, at `version`. */
function prepareDistribution(
  distribution: Distribution,
  directory: string,
  publicKey: string,
  version: string,
): string {
  cpSync(join(root, "examples", distribution.example), directory, {
    recursive: true,
  });
  const manifest = join(directory, "piship.yaml");
  const source = distribution.patch(
    readFileSync(manifest, "utf8"),
    publicKey,
    version,
  );
  if (!source.includes(`publicKey: ${publicKey}`))
    throw new Error(`${distribution.example}: the release key was not pinned`);
  writeFileSync(manifest, source);
  return manifest;
}

async function buildReleases(
  distribution: Distribution,
  directory: string,
): Promise<ReleaseFixtures & { buildInventory?: string }> {
  const { id } = distribution;
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
          distribution,
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
      `${id}-${version}-${target}.tar.gz`,
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
      if (!built.stdout.includes(`${id}-${version}-${target}`))
        throw new Error(`release ${version} did not report its archive`);
    }),
    ...(distribution.plainBuild
      ? [
          succeed(["build", manifests["1.0.0"] as string], {
            ...options,
            cwd: join(directory, "1.0.0"),
          }),
        ]
      : []),
  ]);
  // Two generations of the signed stable channel offering 1.1.0.
  const channels = {
    1: join(directory, "channel-1"),
    2: join(directory, "channel-2"),
  };
  await Promise.all(
    ([1, 2] as const).map(async (sequence) => {
      mkdirSync(channels[sequence]);
      const copy = join(channels[sequence], `${id}-1.1.0-${target}.tar.gz`);
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
    `lifecycle fixtures (${id}): 2 releases, ${distribution.plainBuild ? 1 : 0} build(s), 2 signed channels in ${Date.now() - started} ms`,
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
      `${id}-1.0.0-${target}`,
      "payload",
      "metadata",
      "inventory.json",
    ),
    ...(distribution.plainBuild
      ? {
          buildInventory: join(
            directory,
            "1.0.0",
            "dist",
            id,
            "metadata",
            "inventory.json",
          ),
        }
      : {}),
    channels,
  };
}

/**
 * A distribution's shared release fixtures, built on first use in its own
 * fixture directory. An atomic directory create elects one builder per
 * distribution and test run; other scenario files wait for its result (or
 * its failure) instead of building again.
 */
async function sharedReleases(
  distribution: Distribution,
  fixtures: string = inject("lifecycleFixtures"),
): Promise<ReleaseFixtures & { buildInventory?: string }> {
  const directory = join(fixtures, distribution.fixture);
  mkdirSync(directory, { recursive: true });
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
      const releases = await buildReleases(
        distribution,
        join(directory, "build"),
      );
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
        `${distribution.example} lifecycle fixtures failed to build:\n${readFileSync(failed, "utf8")}`,
      );
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return JSON.parse(readFileSync(ready, "utf8")) as ReleaseFixtures & {
    buildInventory?: string;
  };
}

/** The demo company's shared release fixtures, built on first use. */
export async function lifecycleReleases(): Promise<LifecycleReleases> {
  const { buildInventory, ...releases } = await sharedReleases(
    demo("file", inject("lifecycleFixtures")),
  );
  if (!buildInventory)
    throw new Error("demo lifecycle fixtures have no build inventory");
  return { ...releases, buildInventory };
}

/** The personal example's shared release fixtures, built on first use. */
export function personalReleases(): Promise<ReleaseFixtures> {
  return sharedReleases(PERSONAL);
}

/**
 * Build the distributions' fixtures into `fixtures` before any scenario
 * starts, through the same election the scenarios use, so they find them
 * ready instead of building while other E2E files compete for the CPU. The
 * system-store demo is built only when the platform store is live.
 */
export async function prebuildLifecycleFixtures(
  fixtures: string,
): Promise<void> {
  await Promise.all([
    sharedReleases(demo("file", fixtures), fixtures),
    sharedReleases(PERSONAL, fixtures),
    ...(LIVE_SECRET_STORE
      ? [sharedReleases(demo("system", fixtures), fixtures)]
      : []),
  ]);
}

/**
 * Serve a directory over loopback HTTP, the way an update host would, and
 * record every requested path.
 */
async function serve(directory: string): Promise<{
  url: string;
  requests: string[];
  close: () => Promise<void>;
}> {
  const requests: string[] = [];
  const server = createServer((request, response) => {
    const name = decodeURIComponent(
      new URL(request.url ?? "/", "http://127.0.0.1").pathname.slice(1),
    );
    requests.push(name);
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
    requests,
    // close() alone waits for idle keep-alive connections from the updater.
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
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

/** A lifecycle environment over one distribution's shared releases. */
export interface BaseScenario<Releases extends ReleaseFixtures> {
  readonly releases: Releases;
  readonly temp: string;
  readonly home: string;
  readonly state: string;
  readonly install: string;
  readonly command: string;
  readonly channelDir: string;
  /** Paths requested from this scenario's update host, in order. */
  readonly hostRequests: readonly string[];
  /** The environment every command of this scenario runs with. */
  readonly env: NodeJS.ProcessEnv;
  /** Run the PiShip CLI in this scenario's environment. */
  cli(...args: string[]): Run;
  /** Run the installed branded command. */
  run(args: string[]): Promise<Result>;
  /** Install 1.0.0 with the install script shipped inside its release. */
  installFirst(): Promise<void>;
  /** Publish a signed channel generation into this scenario's channel. */
  publish(sequence: 1 | 2): void;
}

export interface Scenario extends BaseScenario<ReleaseFixtures> {
  readonly services: Services;
  /** Run the installed branded command; acts as the browser for sign-in. */
  run(args: string[]): Promise<Result>;
  /** The app ID, which is also the branded command. */
  readonly id: string;
  /** Where the distribution stores its secrets. */
  readonly storage: Storage;
  /**
   * The platform store entries of this distribution, parts of split values
   * included; only names are read. For `system` storage only.
   */
  storeRefs(): string[];
  /** The secret references the identity and credential metadata name. */
  metadataRefs(): string[];
  /**
   * Assert that the secret store holds exactly `refs` (by default the ones
   * the metadata names). With system storage the platform store lists them,
   * each with only its own parts (`+0` to `+n-1`, as many as at the previous
   * check for a reference seen there), and the file fallback does not exist, so
   * nothing silently degraded to it; with file storage the fallback holds
   * one file per reference. Returns the platform store listing (empty for
   * file storage).
   */
  expectSecretStore(refs?: readonly string[]): string[];
}

function metadataRefs(state: string): string[] {
  const read = (path: string, field: string): string[] => {
    if (!existsSync(path)) return [];
    const value = JSON.parse(readFileSync(path, "utf8"))[field];
    return typeof value === "string" ? [value] : [];
  };
  return [
    ...read(join(state, "identity", "session.json"), "secretRef"),
    ...read(
      join(state, "credentials-metadata", "inference.json"),
      "credential_ref",
    ),
  ].sort();
}

function expectSecretStore(
  storage: Storage,
  state: string,
  storeRefs: () => string[],
  counts: Map<string, number>,
  refs: readonly string[] = metadataRefs(state),
): string[] {
  const expected = [...refs].sort();
  const fallback = join(state, "secrets");
  if (storage === "file") {
    expect(existsSync(fallback) ? readdirSync(fallback).sort() : []).toEqual(
      expected
        .map(
          (ref) => `${createHash("sha256").update(ref).digest("hex")}.secret`,
        )
        .sort(),
    );
    return [];
  }
  expect(existsSync(fallback), "the file fallback in managed mode").toBe(false);
  const listed = storeRefs();
  expect(primaryRefs(listed)).toEqual(expected);
  expect(
    listed.filter(
      (ref) =>
        ref.includes("+") &&
        !expected.some((primary) => ref.startsWith(`${primary}+`)),
    ),
    "parts without their primary",
  ).toEqual([]);
  expectOwnParts(listed, expected, counts);
  return listed;
}

export type PersonalScenario = BaseScenario<ReleaseFixtures>;

/**
 * A fresh, isolated environment over a distribution's shared releases: its
 * own update host, home, state, install home, and bin home. Everything is
 * torn down when the calling test finishes.
 */
async function createScenario<Releases extends ReleaseFixtures>(
  distribution: Distribution,
  releases: Releases,
  name: string,
  options: {
    env?: NodeJS.ProcessEnv;
    approve?: (url: string) => Promise<unknown>;
    close?: () => Promise<void>;
  },
): Promise<BaseScenario<Releases>> {
  const { id } = distribution;
  const temp = mkdtempSync(join(tmpdir(), `piship-${id}-${name}-`));
  const channelDir = join(temp, "channel");
  mkdirSync(channelDir);
  const host = await serve(channelDir);
  // Each step runs even when an earlier one fails, so a failing update host
  // never skips the store cleanup or the lease release in `options.close`.
  onTestFinished(() =>
    runAll([
      () => host.close(),
      () => options.close?.(),
      () => rmSync(temp, { recursive: true, force: true }),
    ]),
  );
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
    ...options.env,
    [distribution.updateVariable]: host.url,
    PISHIP_STATE_HOME: state,
    PISHIP_INSTALL_HOME: install,
    PISHIP_BIN_HOME: join(temp, "bin"),
    HOME: home,
    USERPROFILE: home,
  };
  const command = join(temp, "bin", windows ? `${id}.cmd` : id);
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
      ...(options.approve ? { approve: options.approve } : {}),
    });
  return {
    releases,
    temp,
    home,
    state,
    install,
    command,
    channelDir,
    hostRequests: host.requests,
    env,
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
      const releaseDir = join(extracted, `${id}-1.0.0-${target}`);
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
      expect(installed.stdout).toContain(`Installed ${id}@1.0.0`);
      rmSync(extracted, { recursive: true, force: true });
      expect((await run(["version"])).stdout).toContain(
        `${distribution.name} 1.0.0`,
      );
    },
    publish(sequence) {
      const source = releases.channels[sequence];
      for (const file of readdirSync(source))
        cpSync(join(source, file), join(channelDir, file));
    },
  };
}

/**
 * A fresh, isolated demo lifecycle environment over the shared releases: its
 * own fixture services, update host, home, state, install home, and bin home.
 * Everything is torn down when the calling test finishes.
 *
 * With `storage: "system"` the distribution keeps the example's platform
 * secret store, which needs PISHIP_LIVE_SECRET_STORE=1; it starts with no
 * entry of its app ID in the store and deletes whatever it left on teardown.
 */
export async function lifecycleScenario(
  name: string,
  options: { readonly storage?: Storage } = {},
): Promise<Scenario> {
  const storage = options.storage ?? "file";
  if (storage === "file") {
    const releases = await lifecycleReleases();
    const services: Services = await startLocalServices();
    const scenario = await createScenario(
      demo("file", inject("lifecycleFixtures")),
      releases,
      name,
      {
        env: services.env(),
        approve: (url) => services.approve(url),
        close: () => services.close(),
      },
    );
    const state = join(scenario.state, "acmecode");
    const storeRefs = (): string[] => {
      throw new Error("A file-storage scenario has no platform store");
    };
    const partCounts = new Map<string, number>();
    return {
      ...scenario,
      services,
      id: "acmecode",
      storage,
      storeRefs,
      metadataRefs: () => metadataRefs(state),
      expectSecretStore: (refs) =>
        expectSecretStore(storage, state, storeRefs, partCounts, refs),
    };
  }
  if (!LIVE_SECRET_STORE)
    throw new Error(
      "A system-storage scenario writes to the platform secret store; set PISHIP_LIVE_SECRET_STORE=1",
    );
  const fixtures = inject("lifecycleFixtures");
  const distribution = demo("system", fixtures);
  const releases = await sharedReleases(distribution, fixtures);
  const prefix = `piship:${distribution.id}:`;
  // One system-store scenario at a time: every such scenario of a run
  // shares one app ID, so its references, and the teardown that clears
  // them, would otherwise meet those of a scenario in another file.
  const release = await acquireLease(join(fixtures, "platform-store.lease"));
  let services: Services | undefined;
  let scenario: BaseScenario<ReleaseFixtures>;
  // Set once the scenario's environment reaches the store; the teardown
  // clears the store through it.
  let storeEnv: NodeJS.ProcessEnv | undefined;
  try {
    services = (await startLocalServices()) as Services;
    const started = services;
    scenario = await createScenario(distribution, releases, name, {
      env: started.env(),
      approve: (url) => started.approve(url),
      close: storeScenarioTeardown({
        clearStore: () => {
          if (storeEnv) clearPlatformStore(prefix, storeEnv);
        },
        closeServices: () => started.close(),
        release,
      }),
    });
  } catch (error) {
    await runAll([() => services?.close(), release]).catch(() => {});
    throw error;
  }
  // The teardown clears the store only once `storeEnv` is set. That leaves
  // nothing behind only because no command of the scenario reaches the
  // store before this point; set it before any later step that writes.
  shareKeychainSearchList(scenario.home);
  storeEnv = scenario.env;
  const storeRefs = () => platformStoreRefs(prefix, scenario.env);
  expect(storeRefs(), "entries left by an earlier scenario").toEqual([]);
  const state = join(scenario.state, distribution.id);
  const partCounts = new Map<string, number>();
  return {
    ...scenario,
    services,
    id: distribution.id,
    storage,
    storeRefs,
    metadataRefs: () => metadataRefs(state),
    expectSecretStore: (refs) =>
      expectSecretStore(storage, state, storeRefs, partCounts, refs),
  };
}

/**
 * A fresh, isolated personal lifecycle environment over the shared MyPi
 * releases. It starts no identity provider, broker, or gateway: the only
 * service is the loopback update host.
 */
export async function personalScenario(
  name: string,
): Promise<PersonalScenario> {
  return createScenario(PERSONAL, await personalReleases(), name, {});
}
