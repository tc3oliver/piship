import { describe, expect, it } from "vitest";
import { formatError, PiShipError, systemError } from "./errors.js";

function failure(code: string, path?: string): Error {
  return Object.assign(new Error(`${code}: failed`), {
    code,
    syscall: "write",
    ...(path ? { path } : {}),
  });
}

describe("systemError", () => {
  it.each([
    ["ENOSPC", "full", "PISHIP_INSTALL_HOME"],
    ["EROFS", "read-only", "PISHIP_STATE_HOME"],
    ["ENAMETOOLONG", "too long", "shorter"],
    ["EBUSY", "in use", "Close other programs"],
    ["EMFILE", "too many files", "open-files limit"],
  ])("explains %s with a cause and one next action", (code, cause, action) => {
    const error = systemError(failure(code, "/home/u/.piship/x"));
    expect(error).toBeInstanceOf(PiShipError);
    expect(error?.message).toContain(cause);
    expect(error?.message).toContain(code);
    expect(error?.userAction).toContain(action);
    expect(error?.sanitizedDetail).toMatchObject({ code });
    expect(formatError(failure(code, "/tmp/x"))).toContain("Action:");
  });

  it("names the path where one is known and still reads well without one", () => {
    expect(systemError(failure("ENOSPC", "/data/x"))?.message).toContain(
      "/data/x",
    );
    expect(systemError(failure("ENAMETOOLONG"))?.message).toMatch(
      /^The path is too long/,
    );
  });

  it("leaves other errors alone", () => {
    expect(systemError(failure("ECONNRESET"))).toBeUndefined();
  });
});
