import { describe, expect, it } from "vitest";
import {
  PISHIP_SCHEMA_VERSION,
  parseManifest,
  parseManifestHeader,
} from "./index.js";
const valid = {
  schema: PISHIP_SCHEMA_VERSION,
  app: { id: "mypi", name: "My Pi", command: "mypi" },
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
  it.each([
    [{ ...valid, schema: "piship/v1" }, "schema mismatch"],
    [{ ...valid, app: { name: "My Pi", command: "mypi" } }, "app.id"],
    [{ ...valid, app: { ...valid.app, command: "../pi" } }, "app.command"],
    [{ ...valid, runtime: { pi: "latest" } }, "runtime.pi"],
    [
      { ...valid, resources: { skills: ["./../outside"] } },
      "resources.skills[0]",
    ],
    [{ ...valid, app: { ...valid.app, apiKey: "secret" } }, "app.apiKey"],
  ])("rejects invalid fields with location", (input, expected) => {
    expect(() => parseManifest(input)).toThrow(expected);
  });
});
