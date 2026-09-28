import { describe, expect, it } from "vitest";
import {
  PISHIP_SCHEMA_VERSION,
  parseManifest,
  parseManifestHeader,
} from "./index.js";
const valid = {
  schema: PISHIP_SCHEMA_VERSION,
  app: { id: "mypi", name: "My Pi", command: "mypi", version: "0.1.0" },
  runtime: { pi: "0.87.1" },
  deployment: { mode: "personal" },
};
describe("alpha manifest", () => {
  it("accepts the minimal distribution", () => {
    expect(parseManifest(valid).resources.skills).toEqual([]);
    expect(parseManifestHeader(valid)).toEqual({
      schema: PISHIP_SCHEMA_VERSION,
    });
  });
  it("allows ordinary words that resemble credential names", () => {
    expect(
      parseManifest({ ...valid, app: { ...valid.app, name: "Secret Agent" } })
        .app.name,
    ).toBe("Secret Agent");
  });
  it.each(["1.0.0", "1.2.3-alpha.1", "1.2.3+build.5", "1.2.3-alpha.1+build.5"])(
    "accepts SemVer 2.0.0 version %s",
    (version) => {
      expect(
        parseManifest({ ...valid, app: { ...valid.app, version } }).app.version,
      ).toBe(version);
    },
  );
  it.each(["1.2.3-", "1.2.3-alpha..1", "1.2.3-01", "1.2.3+", "01.2.3"])(
    "rejects invalid SemVer version %s",
    (version) => {
      expect(() =>
        parseManifest({ ...valid, app: { ...valid.app, version } }),
      ).toThrow("app.version");
    },
  );
  it.each([
    [{ ...valid, schema: "piship/v1" }, "schema mismatch"],
    [
      { ...valid, app: { name: "My Pi", command: "mypi", version: "0.1.0" } },
      "app.id",
    ],
    [{ ...valid, app: { ...valid.app, command: "../pi" } }, "app.command"],
    [{ ...valid, runtime: { pi: "latest" } }, "runtime.pi"],
    [
      { ...valid, resources: { skills: ["./../outside"] } },
      "resources.skills[0]",
    ],
    [{ ...valid, app: { ...valid.app, apiKey: "secret" } }, "app.apiKey"],
    [{ ...valid, app: { ...valid.app, theme: "../unsafe" } }, "app.theme"],
    [
      { ...valid, resources: { themes: ["../unsafe.json"] } },
      "resources.themes[0]",
    ],
    [
      { ...valid, app: { ...valid.app, banner: "unsafe\noutput" } },
      "app.banner",
    ],
    [
      { ...valid, app: { ...valid.app, name: "$" + "{SECRET_NAME}" } },
      "app.name",
    ],
    [{ ...valid, deployment: { mode: "managed" } }, "deployment.mode"],
  ])("rejects invalid fields with location", (input, expected) => {
    expect(() => parseManifest(input)).toThrow(expected);
  });
});
