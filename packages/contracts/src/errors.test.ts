import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PISHIP_ERROR_CODES } from "./errors.js";

const packages = fileURLToPath(new URL("../../", import.meta.url));
const definition = fileURLToPath(new URL("./errors.ts", import.meta.url));

// Non-test TypeScript source of every workspace package, except the code list itself.
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
        output.push(readFileSync(path, "utf8"));
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

describe("error codes", () => {
  const corpus = sources();

  it("scans the package sources", () => {
    expect(corpus.length).toBeGreaterThan(20);
  });

  // A code no runtime path produces is a dead contract: remove it rather than
  // keeping it exported.
  it.each(PISHIP_ERROR_CODES)(
    "%s has a producing path in package source",
    (code) => {
      const literal = `"${code}"`;
      expect(
        corpus.some((source) => source.includes(literal)),
        `${code} is only declared; produce it somewhere or remove it`,
      ).toBe(true);
    },
  );
});
