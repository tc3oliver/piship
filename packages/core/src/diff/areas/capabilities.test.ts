import { describe, expect, it } from "vitest";
import { parseManifest } from "@piship/schema";
import { Collector } from "../collector.js";
import { capabilities } from "./capabilities.js";

function manifest(settings: Record<string, string>) {
  const governance = parseManifest({
    schema: "piship/v1alpha6",
    app: { id: "unit", name: "Unit", command: "unit", version: "1.0.0" },
    runtime: { pi: "1.0.3" },
    deployment: { mode: "personal" },
    updates: { channel: "stable", channels: ["stable"] },
    capabilities: { permissions: { enabled: false } },
  }).governance;
  if (!governance) throw new Error("fixture must have governance");
  return {
    ...governance,
    capabilities: governance.capabilities.map((item) =>
      item.name === "permissions" ? { ...item, settings } : item,
    ),
  };
}

describe("provider auto approval diff", () => {
  it.each(["autoApproveFile", "autoApproveKey"])(
    "classifies changes to %s as high risk",
    (key) => {
      for (const [before, after] of [
        [{}, { [key]: "target" }],
        [{ [key]: "old" }, { [key]: "new" }],
        [{ [key]: "target" }, {}],
      ] as const) {
        const out = new Collector();
        capabilities(out, manifest(before), manifest(after));
        expect(out.changes).toEqual([
          expect.objectContaining({
            risk: "high",
            item: `capability permissions setting ${key}`,
          }),
        ]);
      }
    },
  );
});
