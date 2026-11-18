// Pi compatibility: Pi loads extensions through jiti, which caches the
// transpiled code and reads it back after checking only a hash of the source.
// The environment PiShip launches Pi with must decide whether that cache is
// used (see applyPiEnvironment); a Pi or jiti upgrade that stops honoring it
// must fail here.
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverAndLoadExtensions } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyPiEnvironment,
  jitiCacheDirectory,
} from "./launch/pi-defaults.js";

const probe = globalThis as { __pishipJitiPlanted?: number };
let root: string;
let saved: NodeJS.ProcessEnv;

beforeEach(() => {
  saved = { ...process.env };
  root = mkdtempSync(join(tmpdir(), "piship-jiti-"));
  mkdirSync(join(root, "tmp"));
  process.env.TMPDIR = join(root, "tmp");
  process.env.TEMP = join(root, "tmp");
  process.env.TMP = join(root, "tmp");
  delete process.env.JITI_FS_CACHE;
  delete process.env.JITI_CACHE;
  delete probe.__pishipJitiPlanted;
});

afterEach(() => {
  for (const name of Object.keys(process.env))
    if (!(name in saved)) delete process.env[name];
  Object.assign(process.env, saved);
  delete probe.__pishipJitiPlanted;
  rmSync(root, { recursive: true, force: true });
});

/** Load a TypeScript extension once to fill the cache, then plant code in the cached file. */
async function plantedExtension(): Promise<string> {
  const extension = join(root, "ext.ts");
  writeFileSync(
    extension,
    "const n: number = 1;\nexport default function (_pi: unknown) { void n; }\n",
  );
  process.env.JITI_RESPECT_TMPDIR_ENV = "1";
  const first = await discoverAndLoadExtensions(
    [extension],
    root,
    join(root, "agent"),
  );
  expect(first.errors).toEqual([]);
  const cache = jitiCacheDirectory();
  const [cached] = readdirSync(cache);
  expect(cached).toBeDefined();
  const file = join(cache, cached as string);
  writeFileSync(
    file,
    `globalThis.__pishipJitiPlanted = (globalThis.__pishipJitiPlanted ?? 0) + 1;\n${readFileSync(file, "utf8")}`,
  );
  return extension;
}

describe("Pi's jiti transpile cache", () => {
  it("runs a planted cached file when the cache is on, which is why PiShip controls it", async () => {
    const extension = await plantedExtension();
    await discoverAndLoadExtensions([extension], root, join(root, "agent"));
    expect(probe.__pishipJitiPlanted).toBe(1);
  });

  it("is not read under verifyAtLaunch", async () => {
    const extension = await plantedExtension();
    applyPiEnvironment(join(root, "agent"), "personal", false, process.env);
    expect(
      (await discoverAndLoadExtensions([extension], root, join(root, "agent")))
        .errors,
    ).toEqual([]);
    expect(probe.__pishipJitiPlanted).toBeUndefined();
  });

  it.skipIf(process.platform === "win32")(
    "is not read from a directory other users can write",
    async () => {
      const extension = await plantedExtension();
      chmodSync(jitiCacheDirectory(), 0o777);
      applyPiEnvironment(
        join(root, "agent"),
        "personal",
        jitiCacheDirectory(),
        process.env,
      );
      expect(
        (
          await discoverAndLoadExtensions(
            [extension],
            root,
            join(root, "agent"),
          )
        ).errors,
      ).toEqual([]);
      expect(probe.__pishipJitiPlanted).toBeUndefined();
    },
  );
});
