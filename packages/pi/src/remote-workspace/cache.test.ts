import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SandboxBackend } from "@piship/sandbox";
import type { SandboxConfig } from "@piship/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CACHE_MAX_AGE_MS,
  CacheKeyRefused,
  cacheFile,
  cacheKey,
  cacheMode,
  describeCache,
  SetupCache,
  cachedBackend,
} from "./cache.js";

let base: string;
let root: string;
let state: string;
beforeEach(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), "piship-cache-")));
  root = join(base, "project");
  state = join(base, "state");
  mkdirSync(root);
});
afterEach(() => rmSync(base, { recursive: true, force: true }));

const input = (over: Partial<Parameters<typeof cacheKey>[0]> = {}) => ({
  root,
  endpoint: "https://api.example.com",
  template: "e2b-compatible:base",
  user: "user",
  workdir: "/home/user/workspace",
  network: "allow",
  setup: "npm ci",
  identity: "alice",
  policy: "rules-1",
  keyFiles: ["package-lock.json"],
  ...over,
});
const sandbox = (over: Record<string, unknown>) =>
  ({
    workspace: "remote",
    provider: "e2b-compatible",
    ...over,
  }) as SandboxConfig;

describe("cacheMode", () => {
  it("defaults to snapshot only with a setup on e2b-compatible", () => {
    const remote = { setup: "npm ci" };
    expect(cacheMode(sandbox({ remote }))).toBe("snapshot");
    expect(cacheMode(sandbox({ remote: {} }))).toBe("off");
    expect(cacheMode(sandbox({}))).toBe("off");
    expect(cacheMode(sandbox({ provider: "custom", remote }))).toBe("off");
    expect(
      cacheMode(
        sandbox({
          provider: "custom",
          remote: { ...remote, cache: "snapshot" },
        }),
      ),
    ).toBe("snapshot");
    expect(cacheMode(sandbox({ remote: { ...remote, cache: "off" } }))).toBe(
      "off",
    );
    // Nothing to cache without a setup command, whatever is asked.
    expect(cacheMode(sandbox({ remote: { cache: "snapshot" } }))).toBe("off");
    expect(cacheMode(sandbox({ workspace: undefined, remote }))).toBe("off");
  });
});

describe("cacheKey", () => {
  it("changes with every input and with the content of a key file, not with its absence", () => {
    const before = cacheKey(input());
    expect(before).toMatch(/^[0-9a-f]{64}$/);
    expect(cacheKey(input())).toBe(before);
    for (const over of [
      { endpoint: "https://other.example.com" },
      { template: "e2b-compatible:node" },
      { user: "root" },
      { workdir: "/root/workspace" },
      { network: "deny" },
      { setup: "npm install" },
      { identity: "bob" },
      { policy: "rules-2" },
      { keyFiles: ["package-lock.json", "uv.lock"] },
    ])
      expect(cacheKey(input(over))).not.toBe(before);
    writeFileSync(join(root, "package-lock.json"), "one");
    const one = cacheKey(input());
    expect(one).not.toBe(before);
    writeFileSync(join(root, "package-lock.json"), "two");
    expect(cacheKey(input())).not.toBe(one);
  });

  it("refuses a key file that is a symlink, a directory or reached through one", () => {
    writeFileSync(join(base, "outside"), "x");
    symlinkSync(join(base, "outside"), join(root, "package-lock.json"));
    expect(() => cacheKey(input())).toThrow(CacheKeyRefused);
    mkdirSync(join(root, "uv.lock"));
    expect(() => cacheKey(input({ keyFiles: ["uv.lock"] }))).toThrow(
      CacheKeyRefused,
    );
    mkdirSync(join(base, "real"));
    writeFileSync(join(base, "real", "go.sum"), "x");
    symlinkSync(join(base, "real"), join(root, "dir"));
    expect(() => cacheKey(input({ keyFiles: ["dir/go.sum"] }))).toThrow(
      CacheKeyRefused,
    );
  });
});

describe("SetupCache", () => {
  const key = "a".repeat(64);
  it("uses a snapshot only for its key, while fresh", async () => {
    let now = Date.parse("2026-01-01T00:00:00Z");
    const cache = new SetupCache({
      stateDir: state,
      root,
      key,
      now: () => now,
    });
    expect(cache.usable()).toBeUndefined();
    await cache.save(async () => ({ id: "snap-1" }), {
      notify: () => {},
      warn: () => {},
    });
    expect(cache.usable()).toBe("snap-1");
    expect(
      new SetupCache({
        stateDir: state,
        root,
        key: "b".repeat(64),
        now: () => now,
      }).usable(),
    ).toBeUndefined();
    now += CACHE_MAX_AGE_MS + 1;
    expect(cache.usable()).toBeUndefined();
  });

  it("refuses to store an id that is not a plain snapshot id", async () => {
    const cache = new SetupCache({ stateDir: state, root, key });
    const warnings: string[] = [];
    await cache.save(async () => ({ id: "../x" }), {
      notify: () => {},
      warn: (message) => warnings.push(message),
    });
    expect(warnings).toHaveLength(1);
    expect(cache.usable()).toBeUndefined();
  });

  it("describes its state for doctor without the backend", async () => {
    const config = sandbox({ remote: { setup: "npm ci" } });
    expect(describeCache(sandbox({}), state, root)).toBe("off");
    expect(
      describeCache(
        sandbox({ remote: { setup: "x", cache: "off" } }),
        state,
        root,
      ),
    ).toContain("off");
    expect(describeCache(config, state, root)).toContain("no snapshot yet");
    const cache = new SetupCache({ stateDir: state, root, key });
    await cache.save(async () => ({ id: "snap-1" }), {
      notify: () => {},
      warn: () => {},
    });
    expect(describeCache(config, state, root)).toMatch(
      /^snapshot snap-1 from \d{4}-/,
    );
    expect(
      describeCache(config, state, root, Date.now() + CACHE_MAX_AGE_MS * 2),
    ).toContain("older than 7 days");
    await cache.save(
      async () => {
        throw Object.assign(new Error("none"), {
          code: "SNAPSHOT_UNSUPPORTED",
        });
      },
      { notify: () => {}, warn: () => {} },
    );
    expect(describeCache(config, state, root)).toContain("no snapshots");
    expect(cacheFile(state, root)).toContain("cache.json");
  });
});

describe("cachedBackend", () => {
  const key = "a".repeat(64);
  const say = { notify: () => {}, warn: () => {} };
  const fake = (over: Partial<SandboxBackend> = {}) => {
    const templates: (string | undefined)[] = [];
    const deleted: string[] = [];
    const backend = {
      id: "fake",
      provider: "custom",
      available: async () => ({ available: true }),
      capabilities: () => ({}),
      prepare: async (request: { template?: string }) => {
        templates.push(request.template);
        return {};
      },
      deleteSnapshot: async (id: string) => {
        deleted.push(id);
      },
      ...over,
    } as unknown as SandboxBackend;
    return { backend, templates, deleted };
  };

  it("starts only the session's own sandbox from the snapshot, not the network contrast one", async () => {
    const cache = new SetupCache({ stateDir: state, root, key });
    await cache.save(async () => ({ id: "snap-1" }), say);
    const { backend, templates } = fake();
    const wrapped = cachedBackend(backend, cache);
    const profile = {} as never;
    await wrapped.prepare({ profile, purpose: "contrast" });
    expect(templates).toEqual([undefined]);
    expect(cache.restored).toBe(false);
    await wrapped.prepare({ profile });
    expect(templates).toEqual([undefined, "snap-1"]);
    expect(cache.restored).toBe(true);
  });

  it("deletes a snapshot the backend refused as gone", async () => {
    const cache = new SetupCache({ stateDir: state, root, key });
    await cache.save(async () => ({ id: "snap-1" }), say);
    const { backend, deleted } = fake({
      prepare: async (request: { template?: string }) => {
        if (request.template)
          throw Object.assign(new Error("400"), { code: "SNAPSHOT_GONE" });
        return {} as never;
      },
    });
    cachedBackend(backend, cache);
    await cachedBackend(backend, cache).prepare({ profile: {} as never });
    expect(deleted).toEqual(["snap-1"]);
    expect(cache.usable()).toBeUndefined();
  });

  it("deletes the snapshot another session saved meanwhile when this one replaces it", async () => {
    const first = new SetupCache({ stateDir: state, root, key });
    const second = new SetupCache({ stateDir: state, root, key });
    const { backend, deleted } = fake();
    cachedBackend(backend, first);
    cachedBackend(backend, second);
    await first.save(async () => ({ id: "snap-a" }), say);
    await second.save(async () => ({ id: "snap-b" }), say);
    expect(deleted).toEqual(["snap-a"]);
    expect(
      describeCache(sandbox({ remote: { setup: "x" } }), state, root),
    ).toContain("snap-b");
  });

  it("deletes the new snapshot when its id cannot be recorded", async () => {
    const cache = new SetupCache({ stateDir: state, root, key });
    const { backend, deleted } = fake();
    cachedBackend(backend, cache);
    mkdirSync(cacheFile(state, root), { recursive: true }); // a directory where the file goes
    await cache.save(async () => ({ id: "snap-x" }), say);
    expect(deleted).toEqual(["snap-x"]);
  });
});
