import { describe, expect, it, vi } from "vitest";
import { credentialedFetch } from "./http.js";

describe("remote control request deadlines", () => {
  const never = (_url: string | URL, init?: RequestInit): Promise<Response> =>
    new Promise((_resolve, reject) => {
      if (init?.signal?.aborted) {
        reject(init.signal.reason);
        return;
      }
      init?.signal?.addEventListener(
        "abort",
        () => reject(init.signal?.reason),
        { once: true },
      );
    });

  it("times out a control request even with a live caller signal", async () => {
    const caller = new AbortController();
    await expect(
      credentialedFetch(
        { fetch: never },
        "https://example.test",
        { signal: caller.signal },
        () => ["X-Key", "value"],
        false,
        20,
      ),
    ).rejects.toBeTruthy();
    expect(caller.signal.aborted).toBe(false);
  });

  it("honors caller cancellation before the transport deadline", async () => {
    const caller = new AbortController();
    const request = credentialedFetch(
      { fetch: never },
      "https://example.test",
      { signal: caller.signal },
      () => ["X-Key", "value"],
      false,
      10_000,
    );
    caller.abort(new Error("cancelled"));
    await expect(request).rejects.toThrow("cancelled");
  });

  it("leaves command data-plane requests governed by the caller", async () => {
    const caller = new AbortController();
    const fetcher = vi.fn((_url: string | URL, init?: RequestInit) => {
      expect(init?.signal).toBe(caller.signal);
      return Promise.resolve(new Response("ok"));
    });
    await credentialedFetch(
      { fetch: fetcher },
      "https://example.test",
      { signal: caller.signal },
      () => ["X-Key", "value"],
      false,
      0,
    );
    expect(fetcher).toHaveBeenCalledOnce();
  });
});
