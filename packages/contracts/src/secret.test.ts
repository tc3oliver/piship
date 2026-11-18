import { describe, expect, it } from "vitest";
import {
  forgetSecret,
  REDACTED_TEXT as REDACTED,
  redact,
  redactValue,
  SECRET_KEY_PATTERN,
  SecretValue,
} from "./secret.js";

// Obvious fakes. The first has characters that base64, percent-encoding, and
// JSON escaping all change.
const VALUE = 'piship fake "secret"/+?&=0123456789';

describe("redaction of a registered secret", () => {
  it("redacts its base64, base64url, percent-encoded, and JSON-escaped forms", () => {
    const secret = new SecretValue(VALUE);
    const bytes = Buffer.from(VALUE, "utf8");
    const forms = [
      VALUE,
      bytes.toString("base64"),
      bytes.toString("base64").replace(/=+$/, ""),
      bytes.toString("base64url"),
      encodeURIComponent(VALUE),
      JSON.stringify(VALUE).slice(1, -1),
    ];
    for (const form of forms)
      expect(redact(`echoed: ${form} end`)).toBe("echoed: [REDACTED] end");
    // Inside a JSON body that repeats the request.
    expect(redact(JSON.stringify({ error: `got ${VALUE}` }))).not.toContain(
      JSON.stringify(VALUE).slice(1, -1),
    );
    forgetSecret(secret);
    for (const form of forms) expect(redact(form)).toBe(form);
  });
});

describe("encoded forms of a long secret", () => {
  it("registers and redacts a 100k-character run of `=` in linear time", () => {
    const run = "=".repeat(100_000);
    const started = performance.now();
    const secret = new SecretValue(run);
    const text = redact(`before ${run} after ${"=".repeat(100_001)}`);
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(text.startsWith("before [REDACTED] after [REDACTED]")).toBe(true);
    const base64 = Buffer.from(run).toString("base64");
    expect(redact(`x ${base64} y`)).toBe("x [REDACTED] y");
    forgetSecret(secret);
  });
  it("strips exactly the base64 padding for every length", () => {
    for (const value of ["abcdef", "abcdefg", "abcdefgh"]) {
      const secret = new SecretValue(value);
      const unpadded = Buffer.from(value)
        .toString("base64")
        .split("=")
        .join("");
      expect(redact(`<${unpadded}>`)).toBe("<[REDACTED]>");
      forgetSecret(secret);
    }
  });
});

describe("SECRET_KEY_PATTERN", () => {
  it("matches the spellings of credential keys and header names", () => {
    for (const key of [
      "token",
      "access_token",
      "accessToken",
      "refresh-token",
      "idToken",
      "apiToken",
      "api_token",
      "authToken",
      "auth-token",
      "sessionToken",
      "api_key",
      "apiKey",
      "api-key",
      "x-api-key",
      "X-Api-Key",
      "private_key",
      "clientSecret",
      "client-secret",
      "secret",
      "password",
      "passwd",
      "credential",
      "authorization",
      "Proxy-Authorization",
      "cookie",
      "Set-Cookie",
      "bearer",
    ])
      expect(SECRET_KEY_PATTERN.test(key), key).toBe(true);
  });
  it("leaves counts and identifiers alone", () => {
    for (const key of [
      "maxTokens",
      "totalTokens",
      "tokens",
      "tokenCount",
      "credentialId",
      "keyId",
      "secretStore",
      "passwordless",
      "authorizationEndpoint",
    ])
      expect(SECRET_KEY_PATTERN.test(key), key).toBe(false);
  });
});

describe("redactValue and keys that end in a credential word", () => {
  const sentinel = "zQ9fSentinelNoShape1234";
  it("redacts environment-style and vendor-style keys, at any depth", () => {
    const keys = [
      "DB_PASSWORD",
      "OPENAI_API_KEY",
      "GITHUB_TOKEN",
      "AWS_SECRET_ACCESS_KEY",
      "NPM_TOKEN",
      "secretAccessKey",
      "secretKey",
      "githubToken",
      "clientToken",
      "authKey",
      "apiSecret",
      "passphrase",
      "X-Amz-Security-Token",
      "X-Goog-Api-Key",
    ];
    const value = {
      env: Object.fromEntries(keys.map((key) => [key, sentinel])),
      list: [{ deeper: { GITHUB_TOKEN: sentinel } }],
    };
    const text = JSON.stringify(redactValue(value));
    expect(text).not.toContain(sentinel);
    expect(text.split(REDACTED).length - 1).toBe(keys.length + 1);
  });

  it("keeps counts, identifiers and public keys readable", () => {
    const value = {
      maxTokens: 4096,
      tokenCount: 3,
      keyId: "k1",
      accessKeyId: "AKIDEXAMPLE",
      publicKey: "ssh-ed25519 AAAA",
      secretStore: "keychain",
      credentialId: "c1",
      passwordless: true,
      authorizationEndpoint: "https://idp.example/auth",
    };
    expect(redactValue(value)).toEqual(value);
  });
});

describe("redactValue", () => {
  it("replaces a reference back to an object being copied", () => {
    const value: Record<string, unknown> = { name: "a" };
    value.self = value;
    value.list = [value];
    expect(redactValue(value)).toEqual({
      name: "a",
      self: "[Circular]",
      list: ["[Circular]"],
    });
  });
  it("copies an object that appears twice without being its own ancestor", () => {
    const shared = { apiKey: "x", note: "n" };
    expect(redactValue({ a: shared, b: [shared, shared] })).toEqual({
      a: { apiKey: "[REDACTED]", note: "n" },
      b: [
        { apiKey: "[REDACTED]", note: "n" },
        { apiKey: "[REDACTED]", note: "n" },
      ],
    });
  });
  it("shows bytes as redacted text instead of one number per byte", () => {
    const secret = new SecretValue("piship-fake-buffer-secret-0123");
    expect(
      redactValue({
        body: Buffer.from(`upstream said ${secret.reveal()}`),
        view: new TextEncoder().encode("plain bytes"),
      }),
    ).toEqual({
      body: "upstream said [REDACTED]",
      view: "plain bytes",
    });
    forgetSecret(secret);
  });
});

describe("redaction of common secret forms", () => {
  const value = "s3cr3t-Value_0123";
  it.each([
    ["X-Api-Key header", `X-Api-Key: ${value}`, "X-Api-Key: "],
    ["lowercase api-key header", `api-key: ${value}`, "api-key: "],
    ["x-api-key in any case", `X-API-KEY:${value}`, "X-API-KEY:"],
    [
      "Authorization Token scheme",
      `Authorization: Token ${value}`,
      "Authorization: ",
    ],
    [
      "Authorization in lower case",
      `authorization: token ${value}`,
      "authorization: ",
    ],
    [
      "query token after ?",
      `GET /v1/models?token=${value} HTTP/1.1`,
      "?token=",
    ],
    [
      "query token after &",
      `https://h.example/x?a=1&token=${value}&b=2`,
      "&token=",
    ],
    ["access_token query", `?access_token=${value}`, "access_token="],
    ["Cookie header", `Cookie: session=${value}; theme=dark`, "Cookie: "],
    ["Set-Cookie header", `Set-Cookie: sid=${value}; Path=/`, "Set-Cookie: "],
    [
      "escaped JSON password",
      `{\\"password\\":\\"${value}\\"}`,
      '\\"password\\":\\"',
    ],
    [
      "escaped JSON api_key",
      `\\"api_key\\": \\"${value}\\"`,
      '\\"api_key\\": \\"',
    ],
    [
      "camelCase secretAccessKey",
      `{"secretAccessKey":"${value}"}`,
      '"secretAccessKey":"',
    ],
    ["camelCase key=value", `secretAccessKey=${value}`, "secretAccessKey="],
    ["clientSecret", `clientSecret: ${value}`, "clientSecret: "],
  ])("redacts %s", (_name, input, label) => {
    const output = redact(input);
    expect(output).not.toContain(value);
    expect(output).toContain(label);
    expect(output).toContain(REDACTED);
  });

  it.each([
    [
      "a password in a URL",
      "postgres://app:{v}@db.internal/app",
      "postgres://app:",
    ],
    [
      "a proxy password",
      "HTTPS_PROXY=http://user:{v}@proxy:8080",
      "http://user:",
    ],
    [
      "a git remote password",
      "git clone https://me:{v}@git.example/r.git",
      "https://me:",
    ],
    ["--password with a space", "mysql --password {v} -h db", "--password "],
    ["--api-key with a space", "tool --api-key {v} run", "--api-key "],
    ["--token with a space", "gh --token {v}", "--token "],
    ["a passphrase", "passphrase: {v}", "passphrase: "],
    ["npm token", "npm_{36}", ""],
    ["Stripe live key", "sk_live_{v}", ""],
    ["Hugging Face token", "hf_{30}", ""],
    ["Google OAuth token", "ya29.{v}{v}", ""],
  ])("redacts %s", (_name, template, label) => {
    const secret = "Zq9fSentinel0123456789abcdefghij";
    const input = template
      .replaceAll("{36}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
      .replaceAll("{30}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5")
      .replaceAll("{v}", secret);
    const output = redact(input);
    expect(output).not.toContain(secret);
    expect(output).not.toMatch(/a1B2c3D4e5F6g7H8i9J0/);
    expect(output).toContain(REDACTED);
    expect(output).toContain(label);
  });

  it("leaves the option that follows, and options that only start with a credential word", () => {
    expect(redact("login --password-stdin --user me")).toBe(
      "login --password-stdin --user me",
    );
    expect(redact("run --token --verbose")).toBe("run --token --verbose");
    expect(
      redact("Option --api-key is not available to a subagent child"),
    ).toBe("Option --api-key is not available to a subagent child");
    expect(redact("ssh://git@host/repo and http://host:8080/path")).toBe(
      "ssh://git@host/repo and http://host:8080/path",
    );
  });

  it("keeps the parameters after a redacted query token", () => {
    expect(redact(`https://h.example/x?token=${value}&page=2`)).toBe(
      `https://h.example/x?token=${REDACTED}&page=2`,
    );
  });

  it("leaves counts and prose without a value alone", () => {
    for (const text of [
      "maxTokens: 4096",
      "the token expired",
      "basic authentication is off",
    ])
      expect(redact(text)).toBe(text);
  });

  it("keeps a problem that follows a label ending in a credential word (#196)", () => {
    for (const text of [
      "sign-in stopped before acquiring a new credential: delete piship:op:inference#1: SECRET_STORE_UNAVAILABLE: secret-tool was not found",
      "sandbox credential: delete piship:op:sandbox#2: the keyring is locked",
      "sandbox credential: revocation: the broker refused",
      "sandbox credential: the pending credential request record could not be removed",
    ])
      expect(redact(text)).toBe(text);
    // The same words as a whole value, or as the start of one, still go.
    for (const [text, expected] of <[string, string][]>[
      ["credential: delete", `credential: ${REDACTED}`],
      ["password=delete", `password=${REDACTED}`],
      ["secret: deleteme123 rest", `secret: ${REDACTED} rest`],
      ["token: the-real-token next", `token: ${REDACTED} next`],
      ['{"credential":"delete"}', `{"credential":"${REDACTED}"}`],
      ["credential: sk_live_abcdef", `credential: ${REDACTED}`],
    ])
      expect(redact(text)).toBe(expected);
  });

  it("still masks a value that looks like a manifest keyword or a live key", () => {
    // Manifest guidance avoids `credential: <word>`; the rule stays strict.
    for (const [text, expected] of <[string, string][]>[
      ["credential: runtime", `credential: ${REDACTED}`],
      ["credential: stored)", `credential: ${REDACTED}`],
      ["credential: sk-live-4f9a8b7c6d5e", `credential: ${REDACTED}`],
      ["api_key=tok_9f8e7d6c5b4a rest", `api_key=${REDACTED} rest`],
    ])
      expect(redact(text)).toBe(expected);
  });
});
