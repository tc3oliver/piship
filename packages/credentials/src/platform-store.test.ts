import { randomBytes } from "node:crypto";
import { SecretValue } from "@piship/contracts";
import { describe, expect, it } from "vitest";
import { createSecretStore } from "./index.js";

// Exercises the real platform secret store. It writes to the user's keychain,
// so it runs only when explicitly requested (the secret-store CI job sets it).
const live = process.env.PISHIP_LIVE_SECRET_STORE === "1";

describe.runIf(live)("platform secret store (live)", () => {
  it("stores, replaces, reads, and deletes a secret", async () => {
    const store = createSecretStore({
      provider: "system",
      fileDirectory: "unused",
    });
    const ref = `piship:live-test:inference#${randomBytes(4).toString("hex")}`;
    const first = new SecretValue(`sk-live-${randomBytes(12).toString("hex")}`);
    const second = new SecretValue(
      `sk-live-${randomBytes(12).toString("hex")} with spaces "and quotes"`,
    );
    try {
      expect(await store.get(ref)).toBeNull();
      await store.put(ref, first);
      expect((await store.get(ref))?.reveal()).toBe(first.reveal());
      await store.put(ref, second);
      expect((await store.get(ref))?.reveal()).toBe(second.reveal());
    } finally {
      await store.delete(ref);
    }
    expect(await store.get(ref)).toBeNull();
    await store.delete(ref);
  });
  it("round-trips a token bundle larger than one platform item", async () => {
    const store = createSecretStore({
      provider: "system",
      fileDirectory: "unused",
    });
    const ref = `piship:live-test:identity#${randomBytes(4).toString("hex")}`;
    // OIDC access, ID, and refresh tokens from real providers reach several KB.
    const large = new SecretValue(
      JSON.stringify({
        accessToken: randomBytes(2400).toString("base64url"),
        idToken: randomBytes(1800).toString("base64url"),
        refreshToken: randomBytes(600).toString("base64url"),
      }),
    );
    const small = new SecretValue(`sk-live-${randomBytes(12).toString("hex")}`);
    try {
      await store.put(ref, large);
      expect((await store.get(ref))?.reveal()).toBe(large.reveal());
      await store.put(ref, small);
      expect((await store.get(ref))?.reveal()).toBe(small.reveal());
      await store.put(ref, large);
      expect((await store.get(ref))?.reveal()).toBe(large.reveal());
    } finally {
      await store.delete(ref);
    }
    expect(await store.get(ref)).toBeNull();
  });
});
