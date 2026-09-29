import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  MemorySecretStore,
  metadataFileSecretStore,
  recordedSecretStore,
  secretStoreProvider,
  storeForRecorded,
} from "./index.js";

let temp: string;
beforeEach(() => {
  temp = mkdtempSync(join(tmpdir(), "piship-store-owner-"));
});
afterEach(() => {
  rmSync(temp, { recursive: true, force: true });
});

describe("recordedSecretStore", () => {
  it("reads the top-level field of a file that parses", () => {
    expect(recordedSecretStore('{"secret_store":"system"}')).toBe("system");
    expect(recordedSecretStore('{ "secret_store" : "file" }')).toBe("file");
    expect(recordedSecretStore('{"schema":"x"}')).toBeUndefined();
  });

  it("ignores a nested key of the same name that comes first", () => {
    // A claim or a provider field must never pick the store secrets are
    // deleted from.
    const decoy = { secret_store: "system" };
    expect(
      recordedSecretStore(
        JSON.stringify({ claims: decoy, secret_store: "file" }),
      ),
    ).toBe("file");
    expect(recordedSecretStore(JSON.stringify({ claims: decoy }))).toBe(
      undefined,
    );
    expect(
      recordedSecretStore(
        JSON.stringify({ claims: { list: [decoy] }, secret_store: "bogus" }),
      ),
    ).toBeUndefined();
  });

  it("answers nothing for JSON that is not an object", () => {
    for (const text of ['"secret_store"', "null", "7", '["system"]'])
      expect(recordedSecretStore(text)).toBeUndefined();
  });

  it("still finds the field in the text of a damaged file", () => {
    const text = JSON.stringify(
      { schema: "x", secret_store: "system", pad: "y".repeat(40) },
      null,
      2,
    );
    const damaged = text.slice(0, text.indexOf("pad") + 5);
    expect(() => JSON.parse(damaged)).toThrow();
    expect(recordedSecretStore(damaged)).toBe("system");
    expect(recordedSecretStore('{"schema":"x","secret')).toBeUndefined();
  });

  it("reads the file at a path, and nothing for a file that does not exist", () => {
    const path = join(temp, "session.json");
    expect(metadataFileSecretStore(path)).toBeUndefined();
    writeFileSync(
      path,
      JSON.stringify({
        claims: { secret_store: "file" },
        secret_store: "system",
      }),
    );
    expect(metadataFileSecretStore(path)).toBe("system");
  });
});

describe("storeForRecorded", () => {
  const configured = new MemorySecretStore();
  const other = new MemorySecretStore();

  it("uses the configured store for its own provider and for none recorded", () => {
    expect(storeForRecorded(configured, "system", undefined, undefined)).toBe(
      configured,
    );
    expect(storeForRecorded(configured, "system", "system", undefined)).toBe(
      configured,
    );
  });

  it("resolves the recorded store, or none when it is not available here", () => {
    expect(storeForRecorded(configured, "file", "system", () => other)).toBe(
      other,
    );
    expect(
      storeForRecorded(configured, "file", "system", undefined),
    ).toBeNull();
    expect(
      storeForRecorded(configured, "file", "system", () => null),
    ).toBeNull();
    expect(
      storeForRecorded(configured, "file", "system", () => {
        throw new Error("no platform store");
      }),
    ).toBeNull();
  });

  it("names the provider a store serves", () => {
    expect(secretStoreProvider({ kind: "file" })).toBe("file");
    expect(secretStoreProvider({ kind: "memory" })).toBe("system");
  });
});
