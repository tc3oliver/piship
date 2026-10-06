import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { migrateManifestSource, PISHIP_SCHEMA_V1 } from "@piship/schema";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  LOCK_SCHEMA_V1,
  LOCK_SCHEMA_V1ALPHA6,
  lockManifest,
  requireCurrentLock,
  resolveLock,
} from "./index.js";

const roots: string[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const V1ALPHA6 = `schema: piship/v1alpha6
app: { id: acmepi, name: AcmePi, command: acmepi, version: 1.0.0 }
runtime: { pi: "1.0.3" }
deployment: { mode: personal }
variables: [ACME_GATEWAY_URL]
identity: { mode: none }
credential: { provider: none }
inference:
  provider: openai-compatible
  baseUrl: \${ACME_GATEWAY_URL}
models:
  default: acme/coder
  allowed: [acme/coder]
  catalog:
    acme/coder: { name: Acme Coder, contextWindow: 128000, maxOutputTokens: 8192 }
resources:
  instructions:
    user: [./resources/AGENTS.md]
updates: { channel: stable, channels: [stable] }
`;

function project(source: string): string {
  const dir = mkdtempSync(join(tmpdir(), "piship-lock-v1-"));
  roots.push(dir);
  mkdirSync(join(dir, "resources"));
  writeFileSync(join(dir, "resources", "AGENTS.md"), "# AcmePi\n");
  const path = join(dir, "piship.yaml");
  writeFileSync(path, source);
  return path;
}

describe("piship-lock/v1", () => {
  it("keeps the v1alpha6 manifest digest byte for byte", () => {
    // Computed by the v0.10 PiShip for this manifest. A v1alpha6 manifest and
    // lock written before piship/v1 must still verify, so it must not move.
    const bare = `schema: piship/v1alpha6
app: { id: mypi, name: MyPi, command: mypi, version: 1.0.0 }
runtime: { pi: "1.0.3" }
deployment: { mode: personal }
updates: { channel: stable, channels: [stable] }
`;
    const lock = resolveLock(project(bare));
    expect(lock.schema).toBe(LOCK_SCHEMA_V1ALPHA6);
    expect(lock.manifest).toEqual({
      schema: "piship/v1alpha6",
      sha256:
        "sha256-2942d6247c6ae064ac2856a3ef73b06768a64474b505a5de3b3a0ff600438ed8",
    });
  });

  it("records exactly the v1alpha6 content for a piship/v1 manifest", () => {
    const v1 = migrateManifestSource(V1ALPHA6).source;
    expect(v1).toContain("schema: piship/v1\n");
    const before = resolveLock(project(V1ALPHA6));
    const after = resolveLock(project(v1));
    expect(before.schema).toBe(LOCK_SCHEMA_V1ALPHA6);
    expect(after.schema).toBe(LOCK_SCHEMA_V1);
    expect(after.manifest.schema).toBe(PISHIP_SCHEMA_V1);
    expect(after.manifest.sha256).toMatch(/^sha256-[0-9a-f]{64}$/);
    expect(after.manifest.sha256).not.toBe(before.manifest.sha256);
    // Everything else, key for key, is the v1alpha6 lock.
    const { schema: _a, manifest: _b, ...rest } = after;
    const { schema: _c, manifest: _d, ...was } = before;
    expect(rest).toEqual(was);
    expect(after.runtimeTools).toEqual(before.runtimeTools);
    expect(after.enforcement).toEqual(before.enforcement);
    expect(after.data).toEqual(before.data);
  });

  it("round-trips: written, read back current, and stale after any change", () => {
    const path = project(migrateManifestSource(V1ALPHA6).source);
    const written = readFileSync(lockManifest(path), "utf8");
    expect(written.endsWith("\n")).toBe(true);
    expect(JSON.parse(written)).toEqual(requireCurrentLock(path));
    expect(readFileSync(lockManifest(path), "utf8")).toBe(written);
    writeFileSync(
      path,
      readFileSync(path, "utf8").replace("version: 1.0.0", "version: 1.0.1"),
    );
    expect(() => requireCurrentLock(path)).toThrow(/stale/);
  });

  it("ignores comments and key order in the digest, as in v1alpha6", () => {
    const v1 = migrateManifestSource(V1ALPHA6).source;
    const commented = `# a comment\n${v1}`;
    expect(resolveLock(project(commented)).manifest.sha256).toBe(
      resolveLock(project(v1)).manifest.sha256,
    );
  });

  it("never records resolved runtime values, entitlements, or credentials", () => {
    vi.stubEnv("ACME_GATEWAY_URL", "https://sentinel-gateway.invalid/v1");
    vi.stubEnv("ACME_API_KEY", "sentinel-secret-value");
    const path = project(migrateManifestSource(V1ALPHA6).source);
    const text = readFileSync(lockManifest(path), "utf8");
    expect(text).not.toContain("sentinel");
    // The reference is locked as written, never its value.
    expect(text).toContain(`\${ACME_GATEWAY_URL}`);
    const keys = new Set<string>();
    const walk = (value: unknown): void => {
      if (Array.isArray(value)) value.forEach(walk);
      else if (typeof value === "object" && value !== null)
        for (const [key, item] of Object.entries(value)) {
          keys.add(key);
          walk(item);
        }
    };
    walk(JSON.parse(text));
    for (const key of keys)
      expect(key).not.toMatch(
        /^(token|accessToken|refreshToken|apiKey|password|secret|entitlement|entitlements|principal|session|gatewayState|mcpState)$/i,
      );
  });
});
