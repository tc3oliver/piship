import { spawn } from "node:child_process";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";
import { fetch as undiciFetch } from "undici";
import { afterEach, describe, expect, it } from "vitest";
import { selfSignedLoopbackCertificate } from "../../../tests/helpers/x509.js";
import {
  PiShipError,
  SecretValue,
  applyProcessNetworkPolicy,
  assertTlsVerificationEnabled,
  checkDestination,
  createDispatcher,
  createManagedFetch,
  formatError,
  parseRetryAfter,
  principalDigest,
  principalId,
  principalKey,
  redact,
  samePrincipal,
  redactValue,
  sanitizeManagedEnvironment,
  DEFAULT_NETWORK_POLICY,
  trimTrailingSlashes,
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
  it("uses one pattern set that includes vendor token shapes", () => {
    const tokens = [
      `github_pat_${"a".repeat(30)}`,
      `ghs_${"b".repeat(36)}`,
      `xoxp-${"2".repeat(14)}`,
      "ASIAABCDEFGHIJKLMNOP",
      `AIza${"c".repeat(35)}`,
      `glpat-${"d".repeat(20)}`,
      `Basic ${"QWxhZGRpbjpvcGVu".repeat(2)}`,
      `eyAbcdefghijkl.eyMnopqrstuvwx.sig`,
      "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
    ];
    for (const token of tokens)
      expect(redact(`before ${token} after`)).toBe("before [REDACTED] after");
    // Ordinary words that start with "ey" survive.
    expect(redact("eyebrows.eyelashes")).toBe("eyebrows.eyelashes");
    expect(redactValue({ token: "t", cookie: "c", passwd: "p" })).toEqual({
      token: "[REDACTED]",
      cookie: "[REDACTED]",
      passwd: "[REDACTED]",
    });
  });
  it("redacts adversarial 1 MB inputs in linear time", () => {
    const size = 1 << 20;
    const fill = (unit: string, tail = "") =>
      unit.repeat(Math.ceil(size / unit.length)) + tail;
    const inputs = [
      fill("ey-"),
      fill("eyJ-"),
      fill("ey_a"),
      `ey${fill("a")}`,
      `eyJ${fill("a")}.`,
      fill("eyaaaaaaaaaaa."),
      fill("sk-"),
      fill("ghp_"),
      fill("github_pat_-"),
      fill("xoxb-"),
      fill("AKIA"),
      fill("AIza-"),
      fill("glpat-"),
      fill("basic "),
      `Basic ${fill("a")}`,
      fill("bearer "),
      `bearer${fill(" ")}`,
      fill("authorization: "),
      `authorization${fill(" ")}`,
      fill("secret "),
      `password${fill(" ")}`,
      fill('"secret"'),
      fill("-----BEGIN "),
      fill("-----BEGIN PRIVATE KEY-----"),
      `-----BEGIN ${fill("A")}`,
    ];
    for (const input of inputs) {
      const started = performance.now();
      redact(input);
      const elapsed = performance.now() - started;
      expect(
        elapsed,
        `${input.slice(0, 16)}... took ${elapsed} ms`,
      ).toBeLessThan(1000);
    }
  });
  it("keeps plain English that mentions basic", () => {
    for (const text of [
      "Use basic authentication for the proxy",
      "Basic configuration applies to every workspace",
      "BASIC INSTRUCTIONS",
      "the basic understanding",
    ])
      expect(redact(text)).toBe(text);
    expect(redact("send Basic dXNlcjpwYXNz now")).toBe("send [REDACTED] now");
    expect(redact("Basic YWxhZGRpbjpvcGVuc2VzYW1l")).toBe("[REDACTED]");
    expect(redact("Authorization: Basic anything")).toBe(
      "Authorization: [REDACTED]",
    );
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

  it("parses Retry-After seconds and HTTP-dates and shows the wait", () => {
    const now = Date.parse("Wed, 21 Oct 2015 07:28:00 GMT");
    expect(parseRetryAfter("120", now)).toBe(120_000);
    expect(parseRetryAfter(" 1.5 ", now)).toBe(1500);
    expect(parseRetryAfter("Wed, 21 Oct 2015 07:28:30 GMT", now)).toBe(30_000);
    expect(parseRetryAfter("Wed, 21 Oct 2015 07:00:00 GMT", now)).toBe(0);
    for (const value of [undefined, null, "", "-5", "soon", "12abc"])
      expect(parseRetryAfter(value, now)).toBeUndefined();
    const limited = new PiShipError(
      "GATEWAY_RATE_LIMITED",
      "The inference gateway is rate limiting requests",
      { retryable: true, retryAfterMs: 29_100, userAction: "Wait" },
    );
    expect(formatError(limited)).toBe(
      "GATEWAY_RATE_LIMITED: The inference gateway is rate limiting requests\nRetry after: 30 s\nAction: Wait",
    );
    expect(formatError(new PiShipError("UPDATE_FAILED", "x"))).toBe(
      "UPDATE_FAILED: x",
    );
    expect(
      formatError(
        new PiShipError("GATEWAY_RATE_LIMITED", "x", { retryAfterMs: 0 }),
      ),
    ).toBe("GATEWAY_RATE_LIMITED: x");
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
      code: "TLS_POLICY_VIOLATION",
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
    // Refusal of a disabled-TLS environment is covered by the
    // assertTlsVerificationEnabled test above and, end to end, by the managed
    // E2E launch; this test never disables verification in its own process.
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

// An HTTP/1.1 server in another process, as a broker is. It keeps
// connections alive without a Keep-Alive hint, closes one after IDLE_MS idle
// (a short server keep-alive timeout), and answers with the number of the
// connection the request came on.
const KEEP_ALIVE_SERVER = `
let connections = 0;
const server = require("node:net").createServer((socket) => {
  const id = String(++connections);
  let idle;
  let buffered = "";
  socket.on("error", () => {});
  socket.on("data", (chunk) => {
    clearTimeout(idle);
    buffered += chunk.toString("latin1");
    for (let end = buffered.indexOf("\\r\\n\\r\\n"); end !== -1; end = buffered.indexOf("\\r\\n\\r\\n")) {
      const length = Number(/content-length: *(\\d+)/i.exec(buffered.slice(0, end))?.[1] ?? 0);
      if (buffered.length < end + 4 + length) break;
      buffered = buffered.slice(end + 4 + length);
      socket.write("HTTP/1.1 200 OK\\r\\ncontent-length: " + id.length + "\\r\\nconnection: keep-alive\\r\\n\\r\\n" + id);
    }
    idle = setTimeout(() => socket.destroy(), Number(process.env.IDLE_MS));
  });
});
server.listen(0, "127.0.0.1", () => console.log(server.address().port));
`;

async function keepAliveServer(idleMs = 300): Promise<string> {
  const server = spawn(process.execPath, ["-e", KEEP_ALIVE_SERVER], {
    stdio: ["ignore", "pipe", "inherit"],
    env: { ...process.env, IDLE_MS: String(idleMs) },
  });
  cleanup.push(() => {
    server.kill();
  });
  const port = await new Promise<string>((resolve) =>
    server.stdout.once("data", (chunk) => resolve(String(chunk).trim())),
  );
  return `http://127.0.0.1:${port}/broker`;
}

describe("managed fetch connections", () => {
  // A platform secret store call runs its tool synchronously (PowerShell on
  // Windows takes seconds), so the process reads nothing of a pooled
  // connection the server closed meanwhile; whether the next request still
  // sees it closed depends on the event-loop phase it is made in. A request
  // written into that dead connection fails, and a broker POST that fails
  // that way has an unknown outcome and is never retried. So no managed
  // request reuses a connection.
  it("opens a connection per request, also right after the process was blocked", async () => {
    const url = await keepAliveServer();
    const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY);
    const block = new Int32Array(new SharedArrayBuffer(4));
    const post = async (body: string) =>
      (await fetch(url, { method: "POST", body })).text();
    // undici returns a connection to its pool a turn after the response
    // ends; waiting that turn makes a pooled connection certain to be
    // reused, so a dispatcher that pools fails this test every time.
    const settled = () => new Promise((resolve) => setImmediate(resolve));
    const seen: string[] = [];
    // The block runs in the continuation of a response body (as after a
    // broker answer) and of a file read (a poll-phase callback, as after the
    // state file reads before a store call); each is longer than the
    // server's idle timeout.
    const continuations = [
      async () => {
        await settled();
        seen.push(await post("x"));
      },
      async () => {
        await readFile(fileURLToPath(import.meta.url));
      },
    ];
    for (let round = 0; round < 3; round += 1)
      for (const continuation of continuations) {
        await settled();
        seen.push(await post("a"));
        await continuation();
        Atomics.wait(block, 0, 0, 1000);
        seen.push(await post("b"));
      }
    expect(new Set(seen).size).toBe(seen.length);
  }, 30_000);

  it("keeps pooling connections for the process-wide dispatcher", async () => {
    // A long idle time: this test needs a live connection, not a closed one.
    const url = await keepAliveServer(5000);
    const dispatcher = createDispatcher(DEFAULT_NETWORK_POLICY);
    cleanup.push(() => dispatcher.close());
    const post = async () =>
      (
        await undiciFetch(url, { method: "POST", body: "a", dispatcher })
      ).text();
    const first = await post();
    await new Promise((resolve) => setImmediate(resolve));
    expect(await post()).toBe(first);
  });
});

describe("trimTrailingSlashes", () => {
  it("removes trailing slashes in linear time", () => {
    expect(trimTrailingSlashes("https://gw.example/v1///")).toBe(
      "https://gw.example/v1",
    );
    expect(trimTrailingSlashes("https://gw.example/v1")).toBe(
      "https://gw.example/v1",
    );
    expect(trimTrailingSlashes("///")).toBe("");
    const started = performance.now();
    trimTrailingSlashes(`${"/".repeat(1_000_000)}x`);
    expect(performance.now() - started).toBeLessThan(1000);
  });
});

describe("normalized principal", () => {
  const alice = { issuer: "https://idp.example/realms/acme", subject: "alice" };
  it("keys a principal by issuer and subject only", () => {
    expect(
      principalKey({ ...alice, email: "a@example.com" } as typeof alice),
    ).toEqual(alice);
    for (const value of [
      { subject: "alice" },
      { issuer: "https://idp.example" },
      { issuer: "", subject: "alice" },
      { issuer: "https://idp.example", subject: 7 },
    ])
      expect(() => principalKey(value)).toThrow(PiShipError);
  });
  it("compares both parts exactly and treats no identity as its own value", () => {
    expect(samePrincipal(alice, { ...alice })).toBe(true);
    expect(samePrincipal(alice, { ...alice, subject: "Alice" })).toBe(false);
    expect(samePrincipal(alice, { ...alice, issuer: `${alice.issuer}/` })).toBe(
      false,
    );
    expect(samePrincipal(null, null)).toBe(true);
    expect(samePrincipal(undefined, null)).toBe(true);
    expect(samePrincipal(alice, null)).toBe(false);
    expect(samePrincipal(null, alice)).toBe(false);
    expect(
      samePrincipal({ issuer: "", subject: "" }, { issuer: "", subject: "" }),
    ).toBe(false);
  });
  it("renders an unambiguous audit key and a directory-safe digest", () => {
    // Audit `user` under piship-audit/v1 (decision 29): changing this form
    // needs a new audit schema.
    expect(principalId(alice)).toBe("https://idp.example/realms/acme#alice");
    // A # or % in the issuer cannot make two principals share a string.
    const left = principalId({ issuer: "a#b", subject: "c" });
    const right = principalId({ issuer: "a", subject: "b#c" });
    expect(left).toBe("a%23b#c");
    expect(right).toBe("a#b#c");
    expect(principalId({ issuer: "a%23b", subject: "c" })).toBe("a%2523b#c");
    expect(principalDigest(alice)).toMatch(/^[0-9a-f]{32}$/);
    expect(principalDigest(alice)).toBe(principalDigest({ ...alice }));
    expect(principalDigest({ issuer: "a#b", subject: "c" })).not.toBe(
      principalDigest({ issuer: "a", subject: "b#c" }),
    );
    expect(principalDigest(alice)).not.toContain("alice");
  });
});
