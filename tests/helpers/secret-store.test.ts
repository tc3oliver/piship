import { describe, expect, it } from "vitest";
import { expectOwnParts } from "./secret-store.js";

// The part check the live-store scenarios run after every step, on
// listings made up here: no platform store is touched.

const ref = "piship:acmelive-1:identity#1";
const parts = (count: number, from = 0) =>
  Array.from({ length: count }, (_, index) => `${ref}+${from + index}`);

describe("platform store part check", () => {
  it("accepts contiguous parts and a primary without parts", () => {
    const other = "piship:acmelive-1:inference#1";
    expectOwnParts(
      [ref, ...parts(3), other],
      [ref, other],
      new Map<string, number>(),
    );
  });

  it("rejects a stray part of a live reference", () => {
    // Parts 0-2 of the current write and a part 7 an earlier write left.
    expect(() =>
      expectOwnParts(
        [ref, ...parts(3), `${ref}+7`],
        [ref],
        new Map<string, number>(),
      ),
    ).toThrow(/the parts of/);
  });

  it("rejects a missing part", () => {
    expect(() =>
      expectOwnParts(
        [ref, `${ref}+0`, `${ref}+2`],
        [ref],
        new Map<string, number>(),
      ),
    ).toThrow(/the parts of/);
  });

  it("rejects a part count that changed since the previous check", () => {
    const counts = new Map<string, number>();
    expectOwnParts([ref, ...parts(4)], [ref], counts);
    expect(() => expectOwnParts([ref, ...parts(3)], [ref], counts)).toThrow(
      /the part count of/,
    );
  });

  it("starts over for a reference that was gone at the previous check", () => {
    const counts = new Map<string, number>();
    expectOwnParts([ref, ...parts(4)], [ref], counts);
    expectOwnParts([], [], counts);
    expectOwnParts([ref, ...parts(2)], [ref], counts);
  });
});
