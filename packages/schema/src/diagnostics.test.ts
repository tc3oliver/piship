import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  ManifestError,
  migrateManifestSource,
  nearestField,
  readManifest,
} from "./index.js";

const directory = mkdtempSync(join(tmpdir(), "piship-diagnostics-"));
afterAll(() => rmSync(directory, { recursive: true, force: true }));
let counter = 0;
function manifest(text: string): string {
  counter += 1;
  const path = join(directory, `piship-${counter}.yaml`);
  writeFileSync(path, text);
  return path;
}
function failure(path: string): ManifestError {
  try {
    readManifest(path);
  } catch (error) {
    expect(error).toBeInstanceOf(ManifestError);
    return error as ManifestError;
  }
  throw new Error("expected the manifest to be rejected");
}

const valid = `schema: piship/v1alpha1
app:
  id: mypi
  name: My Pi
  command: mypi
  version: 1.0.0
runtime:
  pi: "1.1.0"
deployment:
  mode: personal
`;

describe("manifest diagnostics", () => {
  it("names the line and column of a bad field", () => {
    const error = failure(manifest(valid.replace("mode: personal", "mode: x")));
    expect(error.message).toContain(
      "invalid field at deployment.mode (line 10, column 9)",
    );
  });

  it("shows an unknown field at its name and suggests the nearest field", () => {
    const error = failure(
      manifest(valid.replace("  command: mypi", "  commmand: mypi")),
    );
    expect(error.message).toContain("app.commmand (line 5, column 3)");
    expect(error.message).toContain(
      "Unknown field commmand; did you mean command?",
    );
  });

  it("lists the allowed fields when nothing is near", () => {
    const error = failure(manifest(`${valid}colour: red\n`));
    expect(error.message).toContain("manifest.colour (line 11, column 1)");
    expect(error.message).toContain("the fields allowed here are schema, app");
  });

  it("suggests quoting an unquoted number where text is expected", () => {
    const error = failure(manifest(valid.replace("1.0.0", "1.0")));
    expect(error.message).toContain("app.version (line 6, column 12)");
    expect(error.message).toContain('so quote it: "1.0"');
  });

  it("names the current schema when a later one is written", () => {
    const error = failure(
      manifest(valid.replace("piship/v1alpha1", "piship/v2")),
    );
    expect(error.kind).toBe("schema mismatch");
    expect(error.message).toContain(
      "Unsupported schema piship/v2; the current schema is piship/v1, so write schema: piship/v1",
    );
    expect(error.message).toContain("(line 1, column 9)");
  });

  it("reports every problem it can find in one pass", () => {
    const error = failure(
      manifest(`schema: piship/v1alpha1
app:
  id: My_Pi
  name: My Pi
  commmand: mypi
  version: 1.0
runtime:
  pi: latest
deployment:
  mode: personal
extra: true
`),
    );
    expect(error.errors.map((item) => item.field).sort()).toEqual([
      "app.command",
      "app.commmand",
      "app.id",
      "app.version",
      "manifest.extra",
      "runtime.pi",
    ]);
    expect(error.message).toContain("Manifest has 6 problems");
    expect(error.errors.every((item) => item.position !== undefined)).toBe(
      true,
    );
    // A required field that is not there is shown at its section.
    const missing = failure(manifest(valid.replace("  command: mypi\n", "")));
    expect(missing.errors.map((item) => item.field)).toEqual(["app.command"]);
    expect(missing.message).toContain("app.command (line 2, column 1)");
  });

  it("shows a section missing from the top level at the start of the file", () => {
    const error = failure(
      manifest(valid.replace("piship/v1alpha1", "piship/v1alpha4")),
    );
    expect(error.message).toContain("updates (line 1, column 1)");
  });
  it("reports every YAML syntax error with its position", () => {
    const error = failure(manifest("app: [\nschema: x\n  bad: : :\n"));
    expect(error.kind).toBe("YAML parse failure");
    expect(error.errors.length).toBeGreaterThan(0);
    expect(error.errors.every((item) => item.position !== undefined)).toBe(
      true,
    );
  });

  it("locates the problems of a manifest being migrated", () => {
    expect(() =>
      migrateManifestSource(valid.replace("mode: personal", "mode: x")),
    ).toThrow("deployment.mode (line 10, column 9)");
  });

  it("suggests only a near field", () => {
    expect(nearestField("commmand", ["command", "name"])).toBe("command");
    expect(nearestField("nme", ["name", "id"])).toBe("name");
    expect(nearestField("zzzzzz", ["command", "name"])).toBeUndefined();
    // Names of up to three characters allow one edit: two match anything.
    expect(nearestField("abc", ["xyc"])).toBeUndefined();
  });

  it("reports every unknown field of a nested section, with suggestions", () => {
    const error = failure(
      manifest(`${valid.replace("piship/v1alpha1", "piship/v1alpha2")}identity:
  mode: none
credential:
  provider: pi-native
inference:
  provider: pi-native
  basUrl: https://example.com
  apii: x
`),
    );
    const messages = error.errors.map((item) => item.message).join("\n");
    expect(messages).toContain("inference.basUrl");
    expect(messages).toContain("inference.apii");
    expect(messages).toContain("did you mean baseUrl?");
  });
});
