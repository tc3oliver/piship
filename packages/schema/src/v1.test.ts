import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  LATEST_SCHEMA,
  ManifestError,
  PISHIP_SCHEMA_V1,
  PISHIP_SCHEMA_V1ALPHA6,
  parseManifest,
  parseManifestHeader,
  releaseOptions,
  SUPPORTED_SCHEMAS,
  schemaAtLeast,
} from "./index.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));

/** Every example manifest, as written. */
function exampleManifests(): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules") continue;
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (name === "piship.yaml" || name.endsWith(".piship.yaml"))
        found.push(path);
    }
  };
  walk(join(root, "examples"));
  return found;
}

const withSchema = (source: string, schema: string): unknown =>
  parseYaml(source.replace(/^schema: .*$/m, `schema: ${schema}`)) as unknown;

describe("piship/v1", () => {
  it("is the latest supported schema, after v1alpha6", () => {
    expect(SUPPORTED_SCHEMAS.at(-1)).toBe(PISHIP_SCHEMA_V1);
    expect(LATEST_SCHEMA).toBe(PISHIP_SCHEMA_V1);
    expect(SUPPORTED_SCHEMAS.at(-2)).toBe(PISHIP_SCHEMA_V1ALPHA6);
    expect(schemaAtLeast(PISHIP_SCHEMA_V1, PISHIP_SCHEMA_V1ALPHA6)).toBe(true);
    expect(schemaAtLeast(PISHIP_SCHEMA_V1ALPHA6, PISHIP_SCHEMA_V1)).toBe(false);
    expect(parseManifestHeader({ schema: "piship/v1" })).toEqual({
      schema: PISHIP_SCHEMA_V1,
    });
  });

  it("refuses a schema this PiShip does not know, naming the supported ones", () => {
    for (const schema of ["piship/v2", "piship/v1beta1", "piship/v10"]) {
      expect(parseManifestHeader({ schema })).toMatchObject({
        path: "schema",
        message: expect.stringContaining("piship/v1"),
      });
      expect(() => parseManifest({ schema })).toThrow(ManifestError);
    }
  });

  const examples = exampleManifests();
  it("finds the example manifests", () => {
    expect(examples.length).toBeGreaterThanOrEqual(7);
  });

  for (const path of examples) {
    it(`reads ${path.slice(root.length)} as the same manifest under v1alpha6 and v1`, () => {
      const source = readFileSync(path, "utf8");
      const alpha = parseManifest(withSchema(source, PISHIP_SCHEMA_V1ALPHA6));
      const stable = parseManifest(withSchema(source, PISHIP_SCHEMA_V1));
      expect(alpha.schema).toBe(PISHIP_SCHEMA_V1ALPHA6);
      expect(stable.schema).toBe(PISHIP_SCHEMA_V1);
      expect({ ...stable, schema: PISHIP_SCHEMA_V1ALPHA6 }).toEqual(alpha);
    });
  }

  it("accepts every v1alpha6 section and rejects unknown fields", () => {
    const manifest = {
      schema: PISHIP_SCHEMA_V1,
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: {
        pi: "1.1.0",
        tools: { codemode: "off" },
        cacheWarming: { mode: "streaming" },
        verifyAtLaunch: true,
      },
      deployment: { mode: "personal" },
      data: { sessions: { retention: "30d" } },
      updates: { channel: "stable", channels: ["stable"] },
      release: { bundle: false, strip: false },
    };
    const parsed = parseManifest(manifest);
    expect(parsed.schema).toBe(PISHIP_SCHEMA_V1);
    expect(parsed.runtime.cacheWarming?.mode).toBe("streaming");
    expect(parsed.data).toBeDefined();
    expect(() => parseManifest({ ...manifest, surprise: true })).toThrow(
      /surprise/,
    );
    // The same sections stay closed to the older alphas.
    expect(() =>
      parseManifest({ ...manifest, schema: "piship/v1alpha5" }),
    ).toThrow(ManifestError);
  });

  it("keeps the v1alpha6 release defaults: bundle and strip are on", () => {
    const manifest = parseManifest({
      schema: PISHIP_SCHEMA_V1,
      app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
      runtime: { pi: "1.1.0" },
      deployment: { mode: "personal" },
      updates: { channel: "stable", channels: ["stable"] },
    });
    expect(
      releaseOptions(manifest.schema, manifest.lifecycle?.release),
    ).toEqual({ bundle: true, strip: true });
    for (const schema of [PISHIP_SCHEMA_V1, PISHIP_SCHEMA_V1ALPHA6])
      expect(releaseOptions(schema, { bundle: false })).toEqual({
        bundle: false,
        strip: true,
      });
    expect(releaseOptions("piship/v1alpha5", undefined)).toEqual({
      bundle: false,
      strip: false,
    });
  });

  it("requires the managed sections for a managed v1 manifest", () => {
    expect(() =>
      parseManifest({
        schema: PISHIP_SCHEMA_V1,
        app: { id: "mypi", name: "MyPi", command: "mypi", version: "1.0.0" },
        runtime: { pi: "1.1.0" },
        deployment: { mode: "managed" },
        updates: { channel: "stable", channels: ["stable"] },
      }),
    ).toThrow(ManifestError);
  });
});
