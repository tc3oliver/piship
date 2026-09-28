import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { selfSignedLoopbackCertificate } from "../../../tests/helpers/x509.js";
import {
  PiShipError,
  SecretValue,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  checkDestination,
  createManagedFetch,
  formatError,
  redact,
  redactValue,
  sanitizeManagedEnvironment,
  DEFAULT_NETWORK_POLICY,
} from "./index.js";

const cleanup: (() => void | Promise<void>)[] = [];
afterEach(async () => {
  for (const item of cleanup.splice(0).reverse()) await item();
});

describe("SecretValue", () => {
  it("redacts in every serialization path and reveals only explicitly", () => {
    const secret = new SecretValue("sk-live-value-123456");
    expect(String(secret)).toBe("[REDACTED]");
    expect(`${secret}`).toBe("[REDACTED]");
    expect(JSON.stringify({ secret })).toBe('{"secret":"[REDACTED]"}');
    expect(inspect({ secret })).not.toContain("sk-live");
    expect(secret.reveal()).toBe("sk-live-value-123456");
  });
  it("scrubs revealed values and token shapes from diagnostics", () => {
    const secret = new SecretValue("opaque-credential-98765");
    const text = redact(
      `failed with opaque-credential-98765; Authorization: Bearer abc.def.ghijkl; sk-other-abcdef "access_token":"xyz123456"`,
    );
    expect(text).not.toContain(secret.reveal());
    expect(text).not.toContain("abc.def.ghijkl");
    expect(text).not.toContain("sk-other-abcdef");
    expect(text).not.toContain("xyz123456");
    expect(
      redactValue({ apiKey: "anything", nested: { value: secret } }),
    ).toEqual({
      apiKey: "[REDACTED]",
      nested: { value: "[REDACTED]" },
    });
  });
  it("sanitizes PiShipError message, action, and detail", () => {
    const secret = new SecretValue("token-material-4242");
    const error = new PiShipError(
      "CREDENTIAL_ACQUIRE_FAILED",
      "broker echoed token-material-4242",
      {
        userAction: "retry with token-material-4242",
        sanitizedDetail: { credential: "token-material-4242" },
      },
    );
    const rendered = `${formatError(error)} ${JSON.stringify(error)}`;
    expect(rendered).not.toContain(secret.reveal());
    expect(error.code).toBe("CREDENTIAL_ACQUIRE_FAILED");
  });
});

describe("network policy", () => {
  it("allows plain HTTP only for loopback and enforces private-only hosts", () => {
    expect(() =>
      checkDestination(
        new URL("http://gateway.example/v1"),
        DEFAULT_NETWORK_POLICY,
      ),
    ).toThrow("Refusing non-HTTPS");
    expect(() =>
      checkDestination(
        new URL("http://127.0.0.1:9/v1"),
        DEFAULT_NETWORK_POLICY,
      ),
    ).not.toThrow();
    const privateOnly = {
      ...DEFAULT_NETWORK_POLICY,
      privateOnly: true,
      allowHosts: ["llm.internal.example"],
    };
    expect(() =>
      checkDestination(new URL("https://api.public.example/v1"), privateOnly),
    ).toThrow("Private-only network policy denies undeclared host");
    expect(() =>
      checkDestination(new URL("https://llm.internal.example/v1"), privateOnly),
    ).not.toThrow();
    expect(() =>
      checkDestination(
        new URL("https://user:pw@llm.internal.example"),
        privateOnly,
      ),
    ).toThrow("must not embed credentials");
  });
  it("refuses to run with TLS verification disabled", () => {
    expect(() =>
      assertTlsVerificationEnabled({ NODE_TLS_REJECT_UNAUTHORIZED: "0" }),
    ).toThrow("disables TLS verification");
    expect(() => assertTlsVerificationEnabled({})).not.toThrow();
  });
  it("removes ambient credentials and, when not inherited, proxy variables", () => {
    const env: NodeJS.ProcessEnv = {
      PATH: "/bin",
      HOME: "/home/user",
      OPENAI_API_KEY: "sk-ambient",
      ANTHROPIC_API_KEY: "x",
      AWS_SECRET_ACCESS_KEY: "y",
      GITHUB_TOKEN: "z",
      MY_SERVICE_TOKEN: "t",
      SSH_AUTH_SOCK: "/tmp/agent",
      HTTPS_PROXY: "http://proxy:3128",
      NODE_EXTRA_CA_CERTS: "/etc/ca.pem",
      NODE_TLS_REJECT_UNAUTHORIZED: "0",
      ACME_CREDENTIAL_BROKER_URL: "https://broker",
    };
    const removed = sanitizeManagedEnvironment(
      env,
      { ...DEFAULT_NETWORK_POLICY, inheritProxyEnvironment: false },
      ["ACME_CREDENTIAL_BROKER_URL"],
    );
    expect(removed).toEqual([
      "ANTHROPIC_API_KEY",
      "AWS_SECRET_ACCESS_KEY",
      "GITHUB_TOKEN",
      "HTTPS_PROXY",
      "MY_SERVICE_TOKEN",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "OPENAI_API_KEY",
    ]);
    expect(Object.keys(env).sort()).toEqual([
      "ACME_CREDENTIAL_BROKER_URL",
      "HOME",
      "NODE_EXTRA_CA_CERTS",
      "PATH",
      "SSH_AUTH_SOCK",
    ]);
  });
  it("verifies TLS against default roots plus a declared enterprise CA, never disabling verification", async () => {
    const certificate = selfSignedLoopbackCertificate();
    const server = createHttpsServer(
      { cert: certificate.certificate, key: certificate.key },
      (_request, response) => response.end("private gateway"),
    );
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    cleanup.push(
      () => new Promise<void>((resolve) => server.close(() => resolve())),
    );
    const url = `https://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const directory = mkdtempSync(join(tmpdir(), "piship-ca-"));
    cleanup.push(() => rmSync(directory, { recursive: true, force: true }));
    const bundle = join(directory, "company-ca.pem");
    writeFileSync(bundle, certificate.certificate);
    const noCa = createManagedFetch({
      ...DEFAULT_NETWORK_POLICY,
      inheritProxyEnvironment: false,
    });
    await expect(noCa(url)).rejects.toMatchObject({
      code: "GATEWAY_UNREACHABLE",
    });
    const withCa = createManagedFetch({
      ...DEFAULT_NETWORK_POLICY,
      inheritProxyEnvironment: false,
      additionalCA: [bundle],
    });
    expect(await (await withCa(url)).text()).toBe("private gateway");
    writeFileSync(join(directory, "empty.pem"), "not a certificate");
    expect(() =>
      createManagedFetch({
        ...DEFAULT_NETWORK_POLICY,
        additionalCA: [join(directory, "empty.pem")],
      }),
    ).toThrow("contains no PEM certificate");
    const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    cleanup.push(() => {
      if (previous === undefined)
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
    });
    await expect(withCa(url)).rejects.toMatchObject({
      code: "TLS_POLICY_VIOLATION",
    });
  });
  it("applies private-only policy to in-process fetch used by Pi and extensions", async () => {
    const { Agent, setGlobalDispatcher } = await import("undici");
    cleanup.push(() => setGlobalDispatcher(new Agent()));
    const server = createHttpServer((_request, response) =>
      response.end("declared"),
    );
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    cleanup.push(
      () => new Promise<void>((resolve) => server.close(() => resolve())),
    );
    applyProcessNetworkPolicy({
      ...DEFAULT_NETWORK_POLICY,
      inheritProxyEnvironment: false,
      privateOnly: true,
      allowHosts: ["127.0.0.1"],
    });
    const port = (server.address() as AddressInfo).port;
    expect(await (await fetch(`http://127.0.0.1:${port}/`)).text()).toBe(
      "declared",
    );
    await expect(fetch(`http://localhost:${port}/`)).rejects.toThrow();
  });

  it("routes managed requests through the configured proxy when inherited", async () => {
    const seen: string[] = [];
    const proxy = createHttpServer((request, response) => {
      seen.push(request.url ?? "");
      response.end("via proxy");
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    cleanup.push(
      () => new Promise<void>((resolve) => proxy.close(() => resolve())),
    );
    const saved = { ...process.env };
    cleanup.push(() => {
      for (const key of ["HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"]) {
        if (saved[key] === undefined) delete process.env[key];
        else process.env[key] = saved[key];
      }
    });
    for (const key of ["http_proxy", "no_proxy", "NO_PROXY"])
      delete process.env[key];
    process.env.HTTP_PROXY = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    const fetch = createManagedFetch({
      ...DEFAULT_NETWORK_POLICY,
      inheritProxyEnvironment: true,
    });
    const response = await fetch("http://127.0.0.1:59999/broker");
    expect(await response.text()).toBe("via proxy");
    expect(seen).toEqual(["http://127.0.0.1:59999/broker"]);
    const direct = createManagedFetch({
      ...DEFAULT_NETWORK_POLICY,
      inheritProxyEnvironment: false,
    });
    await expect(direct("http://127.0.0.1:59999/broker")).rejects.toMatchObject(
      { code: "GATEWAY_UNREACHABLE" },
    );
  });
});
