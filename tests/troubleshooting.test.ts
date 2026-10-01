// Every PiShip error code has a row on the troubleshooting page, so a new
// code cannot ship without a documented meaning and action.
import { readFileSync } from "node:fs";
import { PISHIP_ERROR_CODES } from "@piship/contracts";
import { describe, expect, it } from "vitest";

const page = readFileSync(
  new URL("../docs/troubleshooting.md", import.meta.url),
  "utf8",
);

describe("docs/troubleshooting.md", () => {
  it("has a row for every error code", () => {
    const rows = new Set(
      [...page.matchAll(/^\| `([A-Z_]+)` \|/gm)].map((match) => match[1]),
    );
    expect(PISHIP_ERROR_CODES.filter((code) => !rows.has(code))).toEqual([]);
    expect(
      [...rows].filter((code) => !PISHIP_ERROR_CODES.includes(code as never)),
    ).toEqual([]);
  });
});
