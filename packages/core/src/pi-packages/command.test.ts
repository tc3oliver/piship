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

  it("gives no registry action for an unrelated npm failure", () => {
    expect(failure("npm error code EBADENGINE").userAction).toBeUndefined();
  });
});
