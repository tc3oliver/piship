// The atomic writer under injected I/O faults: every byte is written before
// the rename, and every failure before the rename keeps the previous file
// and removes the temporary.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearFaults,
  type FsFault,
  fired,
  injectFault,
} from "../../../tests/helpers/fs-faults.js";
import { temporarySibling, writeFileAtomic } from "./atomic.js";

vi.mock("node:fs", async (importOriginal) =>
  (await import("../../../tests/helpers/fs-faults.js")).faultyFs(
    await importOriginal(),
  ),
);

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "piship-atomic-"));
});
afterEach(() => {
  clearFaults();
  rmSync(dir, { recursive: true, force: true });
});

const PREVIOUS = `${JSON.stringify({ active: "1.0.0" }, null, 2)}\n`;
const NEXT = `${JSON.stringify({ active: "1.1.0", pad: "x".repeat(4096) }, null, 2)}\n`;

function seeded(): string {
  const path = join(dir, "receipt.json");
  writeFileAtomic(path, PREVIOUS);
  return path;
}

describe("writeFileAtomic", () => {
  it("names its temporary after the writing process", () => {
    expect(temporarySibling(join(dir, "a.json"))).toMatch(
      new RegExp(`a\\.json\\.p${process.pid}-[0-9a-f]{12}\\.tmp$`),
    );
  });

  it("finishes a short write instead of publishing a truncated file", () => {
    const path = seeded();
    injectFault(/receipt\.json\..*\.tmp$/, { op: "write", short: true }, 3);
    writeFileAtomic(path, NEXT);
    expect(fired.length).toBeGreaterThan(0);
    expect(readFileSync(path, "utf8")).toBe(NEXT);
    expect(JSON.parse(readFileSync(path, "utf8")).active).toBe("1.1.0");
    expect(readdirSync(dir)).toEqual(["receipt.json"]);
  });

  it.each<[string, FsFault]>([
    ["a write that makes no progress", { op: "write", stall: true }],
    ["ENOSPC while writing", { op: "write", code: "ENOSPC" }],
    ["a failed fsync", { op: "fsync", code: "EIO" }],
    ["a failed rename", { op: "rename", code: "EACCES" }],
    ["a temporary that cannot be created", { op: "open", code: "EDQUOT" }],
  ])(
    "keeps the previous file byte for byte and no temporary after %s",
    (_name, fault) => {
      const path = seeded();
      injectFault(/receipt\.json/, fault);
      expect(() => writeFileAtomic(path, NEXT)).toThrow();
      expect(fired.length).toBeGreaterThan(0);
      expect(readFileSync(path, "utf8")).toBe(PREVIOUS);
      expect(readdirSync(dir)).toEqual(["receipt.json"]);
      clearFaults();
      writeFileAtomic(path, NEXT);
      expect(readFileSync(path, "utf8")).toBe(NEXT);
      expect(readdirSync(dir)).toEqual(["receipt.json"]);
    },
  );
});
