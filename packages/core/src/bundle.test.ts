import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from "vitest";

const rename = vi.hoisted(() => vi.fn());
vi.mock("node:fs", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:fs")>()),
  renameSync: rename,
}));

import { renameWithRetry, wildcardTarget } from "./bundle.js";

function failure(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

describe("wildcardTarget", () => {
  it("replaces every wildcard, as Node resolves an exports pattern", () => {
    expect(wildcardTarget("./dist/*/*.js", "openai")).toBe(
      "./dist/openai/openai.js",
    );
  });
  it("inserts the subpath literally", () => {
    expect(wildcardTarget("./dist/*.js", "a$&b")).toBe("./dist/a$&b.js");
  });
});

describe("renameWithRetry", () => {
  let wait: MockInstance<typeof Atomics.wait>;
  beforeEach(() => {
    rename.mockReset();
    wait = vi.spyOn(Atomics, "wait").mockReturnValue("timed-out");
  });
  afterEach(() => wait.mockRestore());

  it("retries while Windows holds the tree open, then succeeds", () => {
    rename
      .mockImplementationOnce(() => {
        throw failure("EPERM");
      })
      .mockImplementationOnce(() => {
        throw failure("EBUSY");
      })
      .mockImplementation(() => undefined);
    renameWithRetry("from", "to");
    expect(rename).toHaveBeenCalledTimes(3);
    expect(rename).toHaveBeenLastCalledWith("from", "to");
    expect(wait.mock.calls.map((call) => call[3])).toEqual([100, 200]);
  });
  it("gives up with the original error once the holder does not let go", () => {
    rename.mockImplementation(() => {
      throw failure("EACCES");
    });
    expect(() => renameWithRetry("from", "to")).toThrow("EACCES");
    expect(rename).toHaveBeenCalledTimes(10);
  });
  it("does not retry an error that waiting cannot fix", () => {
    rename.mockImplementation(() => {
      throw failure("ENOENT");
    });
    expect(() => renameWithRetry("from", "to")).toThrow("ENOENT");
    expect(rename).toHaveBeenCalledTimes(1);
    expect(wait).not.toHaveBeenCalled();
  });
});
