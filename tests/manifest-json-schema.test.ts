// The editor JSON Schema for piship/v1 (schema/piship-v1.schema.json) must
// accept every real manifest and allow exactly the keys the validator allows,
// so a new manifest field fails here until the schema learns it.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { initDistribution } from "@piship/core";
import {
  ManifestError,
  parseManifest,
  readManifestDocument,
} from "@piship/schema";
import { Ajv } from "ajv";
import { afterAll, describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
type Node = {
  type?: string;
  additionalProperties?: boolean;
  properties?: Record<string, Node>;
};
const schema = JSON.parse(
  readFileSync(join(root, "schema/piship-v1.schema.json"), "utf8"),
) as Node;
const validate = new Ajv({ allErrors: true }).compile(schema);

const examples = readdirSync(join(root, "examples"), { recursive: true })
  .map(String)
  .filter((path) => path.endsWith("piship.yaml"))
  .map((path) => join(root, "examples", path))
  .filter((path) => readFileSync(path, "utf8").includes("schema: piship/v1\n"));
const fixtures = [
  ...examples,
  join(
    root,
    "packages/schema/src/migrations/fixtures/v1alpha6-v1.expected.yaml",
  ),
];
const temporary = mkdtempSync(join(tmpdir(), "piship-json-schema-"));
const templates = (
  [
    ["personal", {}],
    ["personal-no-search", { bundleSearchTools: false }],
    ["managed", { managed: true }],
  ] as const
).map(([name, options]) => {
  const directory = join(temporary, name);
  initDistribution(directory, { id: "my-agent", ...options });
  return join(directory, "piship.yaml");
});
afterAll(() => rmSync(temporary, { recursive: true, force: true }));

// biome-ignore lint/suspicious/noExplicitAny: probes write into arbitrary sections
const load = (path: string): any => readManifestDocument(path);

describe("schema/piship-v1.schema.json", () => {
  it.each([...fixtures, ...templates])("accepts %s", (path) => {
    const manifest = load(path);
    parseManifest(manifest);
    expect(validate(manifest), JSON.stringify(validate.errors)).toBe(true);
  });

  it("starts piship init templates with the schema modeline", () => {
    for (const path of templates)
      expect(readFileSync(path, "utf8")).toMatch(
        /^# yaml-language-server: \$schema=https:\/\/raw\.githubusercontent\.com\/tc3oliver\/piship\/main\/schema\/piship-v1\.schema\.json\n/,
      );
  });

  it("rejects an unknown field", () => {
    const manifest = load(examples[0] as string);
    manifest.app.colour = "blue";
    expect(validate(manifest)).toBe(false);
  });

  // Keys the validator names so it can reject them as secrets.
  const SECRET_KEYS: Record<string, string[]> = {
    credential: ["apiKey", "secret", "token"],
  };
  const PROBE = "qqqqqqqqqqqq";
  /** The keys the validator allows at `section` (root when empty), read from its unknown-field message. */
  function allowedKeys(section: string): string[] {
    const field = `${section || "manifest"}.${PROBE}`;
    for (const path of fixtures) {
      const manifest = load(path);
      if (section) manifest[section] ??= {};
      (section ? manifest[section] : manifest)[PROBE] = 1;
      try {
        parseManifest(manifest);
      } catch (error) {
        if (!(error instanceof ManifestError)) throw error;
        const hit = error.errors.find((item) => item.field === field);
        const listed = hit?.message.split("the fields allowed here are ")[1];
        if (listed)
          return listed
            .split(", ")
            .filter((key) => !SECRET_KEYS[section]?.includes(key));
      }
    }
    throw new Error(`No fixture reports the allowed fields of ${field}`);
  }
  const sections = Object.entries(schema.properties ?? {})
    .filter(([, node]) => node.type === "object")
    .map(([name]) => name);

  it.each(["", ...sections])("allows the validator's keys at %s", (section) => {
    const node = section ? schema.properties?.[section] : schema;
    expect(node?.additionalProperties).toBe(false);
    expect(Object.keys(node?.properties ?? {}).sort()).toEqual(
      allowedKeys(section).sort(),
    );
  });
});
