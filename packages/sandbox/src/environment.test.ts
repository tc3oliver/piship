import { describe, expect, it } from "vitest";
import {
  filterEnvironment,
  isCredentialName,
  STDERR_TRUNCATION_MARKER,
  sanitizeStderr,
  stripCredentials,
} from "./environment.js";

describe("filterEnvironment", () => {
  const env = {
    PATH: "/usr/bin",
    HOME: "/home/u",
    LANG: "C",
    ACME_API_TOKEN: "not-for-children",
    AWS_SECRET_ACCESS_KEY: "x",
    GITHUB_TOKEN: "x",
    NODE_TLS_REJECT_UNAUTHORIZED: "0",
  };

  it("keeps only allowed names", () => {
    expect(
      filterEnvironment(env, ["PATH", "HOME", "MISSING"], {}, "linux"),
    ).toEqual({
      PATH: "/usr/bin",
      HOME: "/home/u",
    });
  });

  it("strips credential-looking names even when explicitly allowed", () => {
    const output = filterEnvironment(
      env,
      [
        "PATH",
        "ACME_API_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "NODE_TLS_REJECT_UNAUTHORIZED",
      ],
      {},
      "linux",
    );
    expect(Object.keys(output)).toEqual(["PATH"]);
  });

  it("applies set values but refuses secret names and secret-shaped values", () => {
    expect(filterEnvironment(env, [], { DOCS_MODE: "demo" }, "linux")).toEqual({
      DOCS_MODE: "demo",
    });
    expect(() =>
      filterEnvironment(env, [], { SERVICE_PASSWORD: "hunter2" }, "linux"),
    ).toThrow(expect.objectContaining({ code: "CONFIG_INVALID" }));
    expect(() =>
      filterEnvironment(
        env,
        [],
        { HEADER: "Bearer abcdefghijklmnop" },
        "linux",
      ),
    ).toThrow(expect.objectContaining({ code: "CONFIG_INVALID" }));
    expect(() =>
      filterEnvironment(env, [], { MODE: "sk-abcdefghijkl" }, "linux"),
    ).toThrow(/cannot be set/);
  });

  it("matches names case-insensitively on Windows", () => {
    expect(
      filterEnvironment({ Path: "C:\\bin" }, ["PATH"], {}, "win32"),
    ).toEqual({
      Path: "C:\\bin",
    });
    expect(
      filterEnvironment({ Path: "C:\\bin" }, ["PATH"], {}, "linux"),
    ).toEqual({});
  });

  it("shares the managed-runtime credential patterns", () => {
    for (const name of ["OPENAI_API_KEY", "PI_TOKEN", "DB_PASSWORD", "X_AUTH"])
      expect(isCredentialName(name)).toBe(true);
    for (const name of ["PATH", "HOME", "SSH_AUTH_SOCK", "AUTHOR"])
      expect(isCredentialName(name)).toBe(false);
    expect(
      stripCredentials({ PATH: "/bin", MY_SECRET: "x", GONE: undefined }),
    ).toEqual({
      PATH: "/bin",
    });
  });
});

describe("sanitizeStderr", () => {
  it("redacts token shapes", () => {
    const output = sanitizeStderr(
      "fatal: Authorization: Bearer abcdefgh12345678 rejected; key sk-abcdef123456",
    );
    expect(output).not.toContain("abcdefgh12345678");
    expect(output).not.toContain("sk-abcdef123456");
    expect(output).toContain("[REDACTED]");
  });

  it("truncates to the tail with a marker after redacting", () => {
    const secret = "sk-0123456789abcdef";
    const text = `${"x".repeat(100)} ${secret} ${"y".repeat(50)}`;
    const output = sanitizeStderr(text, 60);
    expect(output.startsWith(STDERR_TRUNCATION_MARKER)).toBe(true);
    expect(output).not.toContain("0123456789");
    expect(output.endsWith("y".repeat(50))).toBe(true);
    expect(sanitizeStderr("short", 60)).toBe("short");
  });

  it("never splits a multi-byte character", () => {
    const output = sanitizeStderr("é".repeat(50), 11);
    expect(output.split("\n")[1]).toBe("é".repeat(5));
  });
});
