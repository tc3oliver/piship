import { afterEach, describe, expect, it } from "vitest";
import { PiShipError } from "./errors.js";
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  dropInsecureTlsSwitch,
  normalizeProxyEnvironment,
  proxyCorrectionNotice,
} from "./network.js";

const NAMES = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
];
const saved = new Map<string, string | undefined>(
  NAMES.map((name) => [name, process.env[name]]),
);
afterEach(() => {
  for (const [name, value] of saved) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

describe("normalizeProxyEnvironment", () => {
  it("gives a scheme-less host:port the http:// scheme and reports it without credentials", () => {
    const env: NodeJS.ProcessEnv = {
      HTTPS_PROXY: "proxy.corp:8080",
      http_proxy: "user:secret@proxy.corp:3128",
      ALL_PROXY: "localhost:1080",
    };
    const corrections = normalizeProxyEnvironment(env);
    expect(env.HTTPS_PROXY).toBe("http://proxy.corp:8080");
    expect(env.http_proxy).toBe("http://user:secret@proxy.corp:3128");
    expect(env.ALL_PROXY).toBe("http://localhost:1080");
    expect(corrections.map((fix) => fix.name).sort()).toEqual([
      "ALL_PROXY",
      "HTTPS_PROXY",
      "http_proxy",
    ]);
    const notice = proxyCorrectionNotice(corrections) ?? "";
    expect(notice).toContain("HTTPS_PROXY");
    expect(notice).toContain("http://proxy.corp:8080");
    expect(notice).not.toContain("secret");
    // Running it again changes nothing.
    expect(normalizeProxyEnvironment(env)).toEqual([]);
  });

  it("leaves a proxy with a scheme, an empty value, and ALL_PROXY's socks scheme alone", () => {
    const env: NodeJS.ProcessEnv = {
      HTTPS_PROXY: "https://proxy.corp:8443",
      HTTP_PROXY: "  ",
      ALL_PROXY: "socks5://proxy.corp:1080",
    };
    expect(normalizeProxyEnvironment(env)).toEqual([]);
    expect(env.HTTPS_PROXY).toBe("https://proxy.corp:8443");
    expect(env.ALL_PROXY).toBe("socks5://proxy.corp:1080");
    expect(proxyCorrectionNotice([])).toBeUndefined();
  });

  it("names the variable and what to set for a value that cannot be a proxy, never the value", () => {
    for (const value of ["http://", "ftp://proxy.corp:21", "::::", "a b:c"]) {
      const env: NodeJS.ProcessEnv = { HTTPS_PROXY: value };
      let thrown: unknown;
      try {
        normalizeProxyEnvironment(env);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, value).toBeInstanceOf(PiShipError);
      const error = thrown as PiShipError;
      expect(error.message).toContain("HTTPS_PROXY");
      expect(error.userAction).toContain("http://host:port");
      expect(error.message + error.userAction).not.toContain("ftp://proxy");
    }
  });

  it("keeps a managed-style request from crashing with a raw undici error on host:port", async () => {
    process.env.HTTPS_PROXY = "127.0.0.1:9";
    const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY, "network");
    const outcome = await fetch("https://example.invalid/").then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(process.env.HTTPS_PROXY).toBe("http://127.0.0.1:9");
    expect(String((outcome as Error | undefined)?.message)).not.toContain(
      "Invalid URL protocol",
    );
  });

  it("reports an unusable proxy as a PiShipError naming the variable when the managed fetch is built", () => {
    process.env.HTTPS_PROXY = "ftp://proxy.corp:21";
    expect(() => createManagedFetch(DEFAULT_NETWORK_POLICY, "network")).toThrow(
      /HTTPS_PROXY is not a proxy address/,
    );
  });
});

describe("dropInsecureTlsSwitch", () => {
  it("removes only the disabled-verification setting", () => {
    const env: NodeJS.ProcessEnv = { NODE_TLS_REJECT_UNAUTHORIZED: "0" };
    expect(dropInsecureTlsSwitch(env)).toBe(true);
    expect("NODE_TLS_REJECT_UNAUTHORIZED" in env).toBe(false);
    const other: NodeJS.ProcessEnv = { NODE_TLS_REJECT_UNAUTHORIZED: "1" };
    expect(dropInsecureTlsSwitch(other)).toBe(false);
    expect(other.NODE_TLS_REJECT_UNAUTHORIZED).toBe("1");
  });
});
