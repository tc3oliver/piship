import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PISHIP_ERROR_CODES } from "./errors.js";

const packages = fileURLToPath(new URL("../../", import.meta.url));
const definition = fileURLToPath(new URL("./errors.ts", import.meta.url));

// Non-test TypeScript source of every workspace package, except the code list
// itself, with comments removed so a mention in a comment never counts.
function sources(): string[] {
  const output: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (
        entry.name.endsWith(".ts") &&
        !entry.name.endsWith(".test.ts") &&
        !entry.name.endsWith(".d.ts") &&
        path !== definition
      )
        output.push(
          readFileSync(path, "utf8")
            .replace(/\/\*[\s\S]*?\*\//g, "")
            .replace(/(^|\s)\/\/.*$/gm, "$1"),
        );
    }
  };
  for (const name of readdirSync(packages).sort()) {
    const source = join(packages, name, "src");
    try {
      visit(source);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  return output;
}

/**
 * A producing position: the code argument of `new PiShipError(...)` or of the
 * release gate factory `gate(...)`, directly or as a branch of a conditional
 * such as `new PiShipError(expired ? "A" : "B", ...)`. Comparisons such as
 * `error.code === "A"` and type annotations do not count.
 */
function producer(code: string): RegExp {
  return new RegExp(
    `(?:\\bnew\\s+PiShipError|\\bgate)\\(\\s*(?:[\\w.!\\s]+\\?\\s*(?:"[A-Z_]+"\\s*:\\s*)?)?"${code}"`,
  );
}

describe("error codes", () => {
  const corpus = sources();

  it("scans the package sources", () => {
    expect(corpus.length).toBeGreaterThan(20);
  });

  it("counts only producing positions", () => {
    const match = (text: string) => producer("MODEL_DENIED").test(text);
    expect(match('throw new PiShipError(\n  "MODEL_DENIED",')).toBe(true);
    expect(match('new PiShipError(denied ? "MODEL_DENIED" : "X"')).toBe(true);
    expect(match('new PiShipError(denied ? "X" : "MODEL_DENIED"')).toBe(true);
    expect(match('throw gate("MODEL_DENIED", "policy"')).toBe(true);
    expect(match('if (error.code === "MODEL_DENIED")')).toBe(false);
    expect(match('const code: "MODEL_DENIED" = "MODEL_DENIED";')).toBe(false);
  });

  // A code no runtime path produces is a dead contract: remove it rather than
  // keeping it exported.
  it.each(PISHIP_ERROR_CODES)(
    "%s has a producing path in package source",
    (code) => {
      const pattern = producer(code);
      expect(
        corpus.some((source) => pattern.test(source)),
        `${code} is never produced; produce it somewhere or remove it`,
      ).toBe(true);
    },
  );
});
