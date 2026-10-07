// What `login` prints while it waits for the browser, and how Ctrl-C ends
// the wait (#149).
import { describe, expect, it } from "vitest";
import {
  loginWaitingHint,
  pasteFallbackEnabled,
  readRedirectLine,
  untilInterrupted,
} from "./branded/login.js";

const authorize = (redirect: string) =>
  `https://idp.example/authorize?client_id=acme&redirect_uri=${encodeURIComponent(redirect)}&state=s`;

describe("login waiting hint", () => {
  it("names the return address, the timeout, how to cancel, and a provider error page, in English and Chinese", () => {
    const hint = loginWaitingHint(authorize("http://127.0.0.1:8765/callback"), {
      timeoutMs: 300_000,
      env: {},
    });
    expect(hint).toContain(
      "Waiting up to 5 minutes for the browser to return to http://127.0.0.1:8765/callback",
    );
    expect(hint).toContain("Press Ctrl-C to cancel");
    expect(hint).toMatch(/identity provider error.*client ID/s);
    expect(hint).toContain(
      "等待瀏覽器返回 http://127.0.0.1:8765/callback（最多 5 分鐘），按 Ctrl-C 取消。",
    );
    expect(hint).toContain("身分提供者的錯誤");
    expect(hint).not.toMatch(/ssh/i);
    expect(hint).not.toContain("paste");
    expect(hint).not.toContain("貼");
  });

  it.each([
    ["SSH_CONNECTION", "10.0.0.2 52000 10.0.0.9 22"],
    ["SSH_CLIENT", "10.0.0.2 52000 22"],
    ["SSH_TTY", "/dev/pts/1"],
    ["PISHIP_NO_BROWSER", "1"],
  ])(
    "offers pasting the address, in both languages, and never tells the user to run ssh (%s)",
    (name, value) => {
      const hint = loginWaitingHint(
        authorize("http://127.0.0.1:8765/callback"),
        { timeoutMs: 300_000, env: { [name]: value } },
      );
      expect(hint).toContain("paste the full address");
      expect(hint).toContain("press Enter");
      expect(hint).toContain("貼到這裡，按 Enter");
      expect(hint).not.toMatch(/ssh/i);
      expect(hint).not.toMatch(/forward|轉發/i);
    },
  );

  it.each([
    [{}, false],
    [{ PISHIP_NO_BROWSER: "0" }, false],
    [{ PISHIP_NO_BROWSER: "1" }, true],
    [{ SSH_CONNECTION: "10.0.0.2 52000 10.0.0.9 22" }, true],
    [{ SSH_CLIENT: "10.0.0.2 52000 22" }, true],
    [{ SSH_TTY: "/dev/pts/1" }, true],
  ])(
    "listens for a pasted redirect only where the browser cannot return (%j)",
    (env, expected) => {
      expect(pasteFallbackEnabled(env)).toBe(expected);
    },
  );

  it("keeps the hint short", () => {
    const hint = loginWaitingHint(authorize("http://[::1]:9000/cb"), {
      timeoutMs: 300_000,
      env: { SSH_TTY: "/dev/pts/1" },
    });
    expect(hint.split("\n")).toHaveLength(6);
    expect(hint).toContain("http://[::1]:9000/cb");
  });

  it("does not claim a return address or a timeout it does not know", () => {
    const hint = loginWaitingHint("https://idp.example/device?code=ABCD", {
      env: { SSH_TTY: "/dev/pts/1" },
    });
    expect(hint).toBe(
      "Waiting for sign-in to complete in the browser. Press Ctrl-C to cancel.\n等待在瀏覽器完成登入，按 Ctrl-C 取消。",
    );
  });
});

describe("login cancellation", () => {
  it("aborts the wait on Ctrl-C and removes its handler afterwards", async () => {
    const before = process.listenerCount("SIGINT");
    const waiting = untilInterrupted(
      (signal) =>
        new Promise((_, reject) =>
          signal.addEventListener("abort", () => reject(new Error("aborted"))),
        ),
    );
    expect(process.listenerCount("SIGINT")).toBe(before + 1);
    process.emit("SIGINT");
    await expect(waiting).rejects.toThrow("aborted");
    expect(process.listenerCount("SIGINT")).toBe(before);
  });

  it("removes its handler when the work finishes without one", async () => {
    const before = process.listenerCount("SIGINT");
    await expect(untilInterrupted(async () => "done")).resolves.toBe("done");
    expect(process.listenerCount("SIGINT")).toBe(before);
  });
});

describe("login paste reader", () => {
  it("reads one line from stdin and stops reading when aborted", async () => {
    const { PassThrough } = await import("node:stream");
    const input = new PassThrough();
    const original = Object.getOwnPropertyDescriptor(process, "stdin");
    Object.defineProperty(process, "stdin", {
      value: input,
      configurable: true,
    });
    try {
      const first = readRedirectLine(new AbortController().signal);
      input.write("http://127.0.0.1:1/callback?code=c&state=s\n");
      await expect(first).resolves.toBe(
        "http://127.0.0.1:1/callback?code=c&state=s",
      );
      // Abort or end of input without a line never resolves.
      const controller = new AbortController();
      let settled = false;
      void readRedirectLine(controller.signal).then(() => {
        settled = true;
      });
      controller.abort();
      input.end();
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(settled).toBe(false);
    } finally {
      if (original) Object.defineProperty(process, "stdin", original);
    }
  });
});
