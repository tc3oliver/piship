import { PiShipError } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import { mustRun } from "./command.js";

function failure(stderr: string): PiShipError {
  try {
    mustRun(
      () => ({ status: 1, stdout: Buffer.alloc(0), stderr }),
      "pi-code",
      "npm",
      ["ci"],
      { cwd: "." },
    );
  } catch (error) {
    return error as PiShipError;
  }
  throw new Error("mustRun did not throw");
}

describe("mustRun", () => {
  it("names registry access and drops npm's stack when npm cannot reach the registry", () => {
    const error = failure(
      [
        "npm error code ECONNREFUSED",
        "npm error syscall connect",
        "npm error FetchError: request to http://127.0.0.1:9/x.tgz failed, reason: connect ECONNREFUSED 127.0.0.1:9",
        "npm error     at ClientRequest.<anonymous> (/npm/node_modules/minipass-fetch/lib/index.js:130:14)",
        "npm error     at ClientRequest.emit (node:events:514:28)",
      ].join("\n"),
    );
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.message).toContain(
      "npm ci failed: npm error code ECONNREFUSED",
    );
    expect(error.message).not.toContain("minipass-fetch");
    expect(error.userAction).toMatch(/needs npm registry access/);
  });

  it("gives a generic action, not the registry one, for an unrelated npm failure", () => {
    const error = failure("npm error code EBADENGINE");
    expect(error.code).toBe("UPDATE_FAILED");
    expect(error.userAction).toMatch(/Fix what npm's output names/);
  });

  it("reports a failure the caller explains as a manifest mistake", () => {
    let thrown: unknown;
    try {
      mustRun(
        () => ({ status: 1, stdout: Buffer.alloc(0), stderr: "E404" }),
        "pi-code",
        "npm",
        ["view", "x@1.0.0"],
        { cwd: "." },
        () => "x@1.0.0 is not published",
      );
    } catch (error) {
      thrown = error;
    }
    expect((thrown as PiShipError).code).toBe("CONFIG_INVALID");
  });
});
