import { describe, expect, it } from "vitest";
import {
  forgetSecret,
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
