import { randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type SecretStore, SecretValue } from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type CommandRunner,
  createSecretStore,
  SecretServiceSecretStore,
} from "./index.js";

// Exercises the real platform secret store. It writes to the user's keychain,
// so it runs only when explicitly requested (the CI check jobs set it: Keychain
// on macOS, Credential Manager on Windows, GNOME Keyring on Ubuntu).
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

describe("Linux Secret Service store", () => {
  // A stateful `secret-tool` double with the limit seen on libsecret 0.21.4:
  // `store` keeps at most 8192 bytes of stdin, warns, and still exits 0.
  // `lookup` and `clear` match on the given attributes, and `account` and
  // `parent` are the ones PiShip uses. Knobs inject the failures under test.
  function fakeSecretTool() {
    const items = new Map<string, string>();
    const parents = new Map<string, string>();
    const knobs = {
      /** Fail the nth `store` call (1-based) with a keyring error. */
      failStoreAt: 0,
      /** `clear` by `parent` removes one item per call, as on an old libsecret. */
      clearOne: false,
      /** `clear` by `parent` reports success and removes nothing. */
      clearNothing: false,
    };
    let stores = 0;
    const attribute = (args: string[], name: string) => {
      const at = args.indexOf(name);
      return at < 0 ? undefined : args[at + 1];
    };
    const matching = (args: string[]) => {
      const parent = attribute(args, "parent");
      const account = attribute(args, "account");
      return [...items.keys()].filter((key) =>
        parent === undefined ? key === account : parents.get(key) === parent,
      );
    };
    const run: CommandRunner = (_command, args, stdin) => {
      const account = attribute(args, "account") ?? "";
      if (args[0] === "store") {
        stores += 1;
        if (stores === knobs.failStoreAt)
          return {
            status: 1,
            stdout: "",
            stderr: "secret-tool: keyring error",
          };
        const text = stdin ?? "";
        items.set(account, text.slice(0, 8192));
        const parent = attribute(args, "parent");
        if (parent) parents.set(account, parent);
        else parents.delete(account);
        const stderr =
          text.length > 8191 ? "secret-tool: password is too long" : "";
        return { status: 0, stdout: "", stderr };
      }
      if (args[0] === "lookup") {
        const [first] = matching(args);
        return first === undefined
          ? { status: 1, stdout: "", stderr: "" }
          : { status: 0, stdout: items.get(first) ?? "", stderr: "" };
      }
      if (attribute(args, "parent") !== undefined && knobs.clearNothing)
        return { status: 0, stdout: "", stderr: "" };
      const found = matching(args);
      for (const key of knobs.clearOne ? found.slice(0, 1) : found) {
        items.delete(key);
        parents.delete(key);
      }
      return { status: 0, stdout: "", stderr: "" };
    };
    return { items, parents, knobs, run };
  }

  it("splits a value larger than secret-tool stores and removes stale parts", async () => {
    const { items, run } = fakeSecretTool();
    const store = new SecretServiceSecretStore(run);
    const ref = "piship:acmecode:identity";
    const large = new SecretValue(
      JSON.stringify({ idToken: "x".repeat(9000) }),
    );
    await store.put(ref, large);
    expect((await store.get(ref))?.reveal()).toBe(large.reveal());
    expect(items.size).toBeGreaterThan(1);
    for (const value of items.values()) expect(value.length).toBeLessThan(8192);
    const small = new SecretValue("sk-small");
    await store.put(ref, small);
    expect([...items.keys()]).toEqual([ref]);
    expect((await store.get(ref))?.reveal()).toBe(small.reveal());
    // 6000 bytes encode to exactly 8000 characters, which is still one item.
    await store.put(ref, new SecretValue("a".repeat(6000)));
    expect([...items.keys()]).toEqual([ref]);
    await store.put(ref, new SecretValue("a".repeat(6001)));
    expect(items.size).toBe(3);
    await store.put(ref, large);
    items.delete(`${ref}+1`);
    await expect(store.get(ref)).rejects.toMatchObject({
      code: "SECRET_STORE_UNAVAILABLE",
    });
    await store.delete(ref);
    expect(items.size).toBe(0);
  });

  describe("a value split across parts", () => {
    const ref = "piship:acmecode:identity";
    const large = new SecretValue(
      JSON.stringify({ idToken: "x".repeat(20_000) }),
    );

    it("leaves no part behind when a part write fails", async () => {
      const { items, knobs, run } = fakeSecretTool();
      const store = new SecretServiceSecretStore(run);
      knobs.failStoreAt = 2;
      await expect(store.put(ref, large)).rejects.toMatchObject({
        code: "SECRET_STORE_UNAVAILABLE",
      });
      expect(items.size).toBe(0);
      expect(await store.get(ref)).toBeNull();
    });

    it("drops a chunked value it could not replace instead of serving a mix of old and new", async () => {
      const { items, knobs, run } = fakeSecretTool();
      const store = new SecretServiceSecretStore(run);
      await store.put(ref, large);
      // The second store call of the replacement, so a part is already written.
      knobs.failStoreAt = items.size + 2;
      await expect(
        store.put(ref, new SecretValue("y".repeat(20_000))),
      ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
      expect(items.size).toBe(0);
      expect(await store.get(ref)).toBeNull();
    });

    it("keeps an earlier plain value when the chunked replacement fails", async () => {
      const { items, knobs, run } = fakeSecretTool();
      const store = new SecretServiceSecretStore(run);
      await store.put(ref, new SecretValue("sk-old"));
      knobs.failStoreAt = 2;
      await expect(store.put(ref, large)).rejects.toMatchObject({
        code: "SECRET_STORE_UNAVAILABLE",
      });
      expect([...items.keys()]).toEqual([ref]);
      expect((await store.get(ref))?.reveal()).toBe("sk-old");
    });

    it("fails closed on an extra part", async () => {
      const { items, parents, run } = fakeSecretTool();
      const store = new SecretServiceSecretStore(run);
      await store.put(ref, large);
      const count = items.size - 1;
      items.set(`${ref}+${count}`, "stray");
      parents.set(`${ref}+${count}`, ref);
      await expect(store.get(ref)).rejects.toMatchObject({
        code: "SECRET_STORE_UNAVAILABLE",
      });
      await store.delete(ref);
      expect(items.size).toBe(0);
    });

    it("deletes every part even when one clear call removes one item", async () => {
      const { items, knobs, run } = fakeSecretTool();
      const store = new SecretServiceSecretStore(run);
      await store.put(ref, large);
      knobs.clearOne = true;
      await store.delete(ref);
      expect(items.size).toBe(0);
    });

    it("reports a delete that removed nothing instead of claiming success", async () => {
      const { knobs, run } = fakeSecretTool();
      const store = new SecretServiceSecretStore(run);
      await store.put(ref, large);
      knobs.clearNothing = true;
      await expect(store.delete(ref)).rejects.toMatchObject({
        code: "SECRET_STORE_UNAVAILABLE",
      });
    });
  });

  it("reports a truncated store instead of keeping a cut-off secret", async () => {
    const run: CommandRunner = (_command, args) =>
      args[0] === "lookup"
        ? { status: 1, stdout: "", stderr: "" }
        : {
            status: 0,
            stdout: "",
            stderr: "secret-tool: password is too long",
          };
    await expect(
      new SecretServiceSecretStore(run).put(
        "piship:x:inference#1",
        new SecretValue("sk-sentinel"),
      ),
    ).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
  });

  describe("without a session bus", () => {
    let temp: string;
    beforeEach(() => {
      temp = mkdtempSync(join(tmpdir(), "piship-secret-service-"));
    });
    afterEach(() => {
      rmSync(temp, { recursive: true, force: true });
    });
    const ref = "piship:fail-closed:inference#1";
    const secret = new SecretValue(
      `sk-sentinel-${randomBytes(12).toString("hex")}`,
    );
    // Every operation must fail, and nothing may end up in a plaintext file:
    // the file directory would appear under `temp` if a fallback wrote to it.
    // `get` runs first so a reachable service would fail the test before
    // anything is stored.
    async function expectFailsClosed(store: SecretStore) {
      await expect(store.get(ref)).rejects.toMatchObject({
        code: "SECRET_STORE_UNAVAILABLE",
      });
      const put = await store.put(ref, secret).then(
        () => null,
        (error: unknown) => error,
      );
      expect(put).toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
      expect(String((put as Error).message)).not.toContain(secret.reveal());
      await expect(store.delete(ref)).rejects.toMatchObject({
        code: "SECRET_STORE_UNAVAILABLE",
      });
      expect(readdirSync(temp)).toEqual([]);
    }

    it("fails closed when secret-tool cannot reach a service", async () => {
      const run: CommandRunner = () => ({
        status: 1,
        stdout: "",
        stderr: "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY",
      });
      await expectFailsClosed(
        createSecretStore({
          provider: "system",
          fileDirectory: join(temp, "secrets"),
          platform: "linux",
          run,
        }),
      );
    });

    // The real tool, with every way to find a session bus removed from the
    // environment. Runs on Linux only: elsewhere secret-tool does not exist.
    it.runIf(process.platform === "linux")(
      "fails closed with the real secret-tool when no session bus is reachable",
      async () => {
        const hidden = [
          "DBUS_SESSION_BUS_ADDRESS",
          "DBUS_STARTER_ADDRESS",
          "DBUS_STARTER_BUS_TYPE",
          "XDG_RUNTIME_DIR",
          "DISPLAY",
          "WAYLAND_DISPLAY",
        ];
        const saved = hidden.map((name) => [name, process.env[name]] as const);
        for (const name of hidden) delete process.env[name];
        try {
          await expectFailsClosed(
            createSecretStore({
              provider: "system",
              fileDirectory: join(temp, "secrets"),
            }),
          );
        } finally {
          for (const [name, value] of saved)
            if (value !== undefined) process.env[name] = value;
        }
      },
    );
  });
});
