// What `login` prints while it waits for the browser, and how Ctrl-C ends
// the wait (#149).
import { describe, expect, it } from "vitest";
import {
  inlineLoginOffered,
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
      paste: false,
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

  it("offers pasting the address in both languages, and never tells the user to run ssh", () => {
    const hint = loginWaitingHint(authorize("http://127.0.0.1:8765/callback"), {
      timeoutMs: 300_000,
      paste: true,
    });
    expect(hint).toContain("paste the full address");
    expect(hint).toContain("press Enter");
    expect(hint).toContain("貼到這裡，按 Enter");
    expect(hint).not.toMatch(/ssh/i);
    expect(hint).not.toMatch(/forward|轉發/i);
  });

  it("keeps the hint short", () => {
    const hint = loginWaitingHint(authorize("http://[::1]:9000/cb"), {
      timeoutMs: 300_000,
      paste: true,
    });
    expect(hint.split("\n")).toHaveLength(6);
    expect(hint).toContain("http://[::1]:9000/cb");
  });

  it("does not claim a return address or a timeout it does not know", () => {
    const hint = loginWaitingHint("https://idp.example/device?code=ABCD", {
      paste: true,
    });
    expect(hint).toBe(
      "Waiting for sign-in to complete in the browser. Press Ctrl-C to cancel.\n等待在瀏覽器完成登入，按 Ctrl-C 取消。",
    );
  });
});

describe("paste fallback detection", () => {
  const none = () => false;
  it.each([
    ["no signal on macOS", {}, "darwin", none, false],
    ["no signal on Windows", {}, "win32", none, false],
    ["a Linux desktop with X11", { DISPLAY: ":0" }, "linux", none, false],
    [
      "a Linux desktop with Wayland",
      { WAYLAND_DISPLAY: "wayland-0" },
      "linux",
      none,
      false,
    ],
    [
      "WSL without a display",
      { WSL_DISTRO_NAME: "Ubuntu" },
      "linux",
      none,
      false,
    ],
    [
      "PISHIP_NO_BROWSER=0",
      { PISHIP_NO_BROWSER: "0", DISPLAY: ":0" },
      "linux",
      none,
      false,
    ],
    ["PISHIP_NO_BROWSER=1", { PISHIP_NO_BROWSER: "1" }, "darwin", none, true],
    [
      "SSH_CONNECTION",
      { SSH_CONNECTION: "10.0.0.2 52000 10.0.0.9 22" },
      "darwin",
      none,
      true,
    ],
    ["SSH_CLIENT", { SSH_CLIENT: "10.0.0.2 52000 22" }, "darwin", none, true],
    ["SSH_TTY", { SSH_TTY: "/dev/pts/1" }, "darwin", none, true],
    ["Linux with no display", {}, "linux", none, true],
    [
      "a Docker container with a display variable",
      { DISPLAY: ":0" },
      "linux",
      (p: string) => p === "/.dockerenv",
      true,
    ],
    [
      "a Podman container with a display variable",
      { DISPLAY: ":0" },
      "linux",
      (p: string) => p === "/run/.containerenv",
      true,
    ],
    [
      "a Kubernetes pod with a display variable",
      { DISPLAY: ":0", KUBERNETES_SERVICE_HOST: "10.0.0.1" },
      "linux",
      none,
      true,
    ],
    [
      "a container marker on macOS",
      { KUBERNETES_SERVICE_HOST: "10.0.0.1" },
      "darwin",
      none,
      false,
    ],
  ] as const)("%s", (_name, env, platform, exists, expected) => {
    expect(pasteFallbackEnabled(env, { platform, exists })).toBe(expected);
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

describe("inline sign-in during a launch", () => {
  const tty = { stdinTTY: true, stdoutTTY: true };
  it("is offered only to a managed launch at a terminal outside CI", () => {
    expect(inlineLoginOffered("managed", tty, {})).toBe(true);
    expect(inlineLoginOffered("managed", tty, { CI: "0" })).toBe(true);
    expect(inlineLoginOffered("managed", tty, { CI: "false" })).toBe(true);
    expect(inlineLoginOffered("managed", tty, { CI: "true" })).toBe(false);
    expect(inlineLoginOffered("managed", tty, { CI: "1" })).toBe(false);
    expect(inlineLoginOffered("managed", { ...tty, stdinTTY: false }, {})).toBe(
      false,
    );
    expect(
      inlineLoginOffered("managed", { ...tty, stdoutTTY: false }, {}),
    ).toBe(false);
    expect(inlineLoginOffered("personal", tty, {})).toBe(false);
  });
});
