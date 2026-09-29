import { resolve } from "node:path";
import {
  approvedNetworkEnvironment,
  DEFAULT_NETWORK_POLICY,
} from "@piship/contracts";
import { describe, expect, it } from "vitest";
import {
  filterEnvironment,
  isCredentialName,
  STDERR_TRUNCATION_MARKER,
  sanitizeStderr,
  stripCredentials,
  withApprovedNetwork,
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

describe("withApprovedNetwork", () => {
  const network = approvedNetworkEnvironment(
    { ...DEFAULT_NETWORK_POLICY, additionalCA: ["/etc/corp/ca.pem"] },
    {
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      NO_PROXY: "localhost",
    },
  );

  it("gives a child the approved network environment and no other proxy, CA, or TLS variable", () => {
    const output = withApprovedNetwork(
      {
        PATH: "/usr/bin",
        HTTPS_PROXY: "http://svc:hunter2@other.example:3128",
        ALL_PROXY: "socks5://other.example:1080",
        SSL_CERT_FILE: "/etc/ambient.pem",
        NODE_EXTRA_CA_CERTS: "/etc/ambient.pem",
        REQUESTS_CA_BUNDLE: "/etc/ambient.pem",
        GIT_SSL_NO_VERIFY: "1",
        NODE_TLS_REJECT_UNAUTHORIZED: "0",
        GONE: undefined,
      },
      network,
    );
    expect(output).toEqual({
      PATH: "/usr/bin",
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      https_proxy: "http://proxy.corp.example:3128",
      NO_PROXY: "localhost",
      no_proxy: "localhost",
      NODE_EXTRA_CA_CERTS: resolve("/etc/corp/ca.pem"),
    });
    expect(JSON.stringify(output)).not.toContain("hunter2");
  });

  it("drops ambient network variables even when nothing is approved", () => {
    expect(
      withApprovedNetwork(
        { PATH: "/usr/bin", https_proxy: "http://p:1", Ssl_Cert_File: "/x" },
        approvedNetworkEnvironment(
          { ...DEFAULT_NETWORK_POLICY, inheritProxyEnvironment: false },
          {},
        ),
      ),
    ).toEqual({ PATH: "/usr/bin" });
  });

  it("never adds a credential-looking name", () => {
    for (const name of Object.keys(network.variables))
      expect(isCredentialName(name)).toBe(false);
  });

  it("returns the environment unchanged when no network policy was applied", () => {
    const env = {
      PATH: "/usr/bin",
      HTTPS_PROXY: "http://proxy.corp.example:3128",
      SSL_CERT_FILE: "/etc/ambient.pem",
    };
    expect(withApprovedNetwork(env, undefined)).toEqual(env);
  });

  it("does not change its input", () => {
    const env = { HTTPS_PROXY: "http://ambient:1", PATH: "/usr/bin" };
    withApprovedNetwork(env, network);
    expect(env).toEqual({ HTTPS_PROXY: "http://ambient:1", PATH: "/usr/bin" });
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
