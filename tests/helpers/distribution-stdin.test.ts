import * as childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

const { branded } = await import("./distribution.js");

const spawned = () => vi.mocked(childProcess.spawn);

/** The stdin a faked child hands `branded()`: records what it was written. */
class FakeStdin extends EventEmitter {
  readonly ended: string[] = [];
  end(chunk?: string): this {
    this.ended.push(chunk ?? "");
    return this;
  }
}

/** The smallest child `branded()` drives: two output streams and stdin. */
class FakeChild extends EventEmitter {
  readonly stdout = new EventEmitter();
  readonly stderr = new EventEmitter();
  readonly stdin = new FakeStdin();
  readonly kill = vi.fn();
}

/** Either outcome of a run, so a rejection is an assertion, not a throw. */
type Settled =
  | { result: { status: number | null; stdout: string; stderr: string } }
  | { error: unknown };

/**
 * Run `branded()` against a fake child and capture whichever way it settles.
 * `spawn` is faked, so no real process starts: the ordering of the events
 * below is then exact rather than a race.
 */
function settle(
  child: FakeChild,
  options: { input?: string; timeoutMs?: number } = {},
): Promise<Settled> {
  spawned().mockReturnValueOnce(child as never);
  return branded(process.execPath, ["-e", "void 0"], {
    cwd: process.cwd(),
    env: { ...process.env },
    ...options,
  }).then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );
}

/** An errno-shaped error, as a stream write failure carries. */
const errno = (code: string | undefined, message = "write failed") =>
  Object.assign(new Error(message), code === undefined ? {} : { code });

describe("branded() stdin handling", () => {
  it("resolves with the child's status when a queued write hits a closed pipe", async () => {
    // The state the macOS CI race reached: the child closed its read end
    // while the write was still queued, so the flush fails asynchronously.
    const child = new FakeChild();
    const settled = settle(child);
    child.stdin.emit("error", errno("EPIPE"));
    child.stdout.emit("data", "the output");
    child.emit("close", 0);
    expect(await settled).toEqual({
      result: { status: 0, stdout: "the output", stderr: "" },
    });
    // The child exited on its own terms, so it must not be killed for it.
    expect(child.kill).not.toHaveBeenCalled();
  });

  it("treats every pipe-closure code the same way", async () => {
    // Which code a closed read end produces depends on the platform and on
    // how far the write got, so all three shapes of "the child is gone" have
    // to be expected, not just the one macOS happened to report.
    for (const code of ["EPIPE", "ECONNRESET", "ERR_STREAM_DESTROYED"]) {
      const child = new FakeChild();
      const settled = settle(child);
      child.stdin.emit("error", errno(code));
      child.emit("close", 3);
      const outcome = await settled;
      expect("error" in outcome, code).toBe(false);
      expect("result" in outcome && outcome.result.status, code).toBe(3);
    }
  });

  it("catches an error the write raises before the handler could be added", async () => {
    // `end()` reports the failure synchronously, in the same tick the write
    // is queued. An EventEmitter with no `error` listener throws "Unhandled
    // 'error' event" here, so this only passes if the handler was installed
    // before the write rather than after it.
    const child = new FakeChild();
    child.stdin.end = function end(this: FakeStdin, chunk?: string) {
      this.ended.push(chunk ?? "");
      this.emit("error", errno("EPIPE"));
      return this;
    } as FakeStdin["end"];
    const settled = settle(child);
    child.emit("close", 0);
    const outcome = await settled;
    expect("result" in outcome && outcome.result.status).toBe(0);
  });

  it("reports a stdin failure that is not the child going away", async () => {
    // An unexpected error must not be swallowed: a bad file descriptor is a
    // real failure of the run, so it rejects with a message naming the
    // command and the output so far, and the child is killed rather than
    // left running behind a promise nobody is waiting on.
    const child = new FakeChild();
    const settled = settle(child);
    child.stderr.emit("data", "partial output");
    child.stdin.emit("error", errno("EBADF", "bad file descriptor"));
    const outcome = await settled;
    expect("result" in outcome).toBe(false);
    expect(String("error" in outcome && outcome.error)).toContain(
      "stdin failed: bad file descriptor",
    );
    expect(String("error" in outcome && outcome.error)).toContain(
      "partial output",
    );
    expect(child.kill).toHaveBeenCalledOnce();
  });

  it("reports an stdin error that carries no code at all", async () => {
    // No `code` means nothing classified it as an expected closure, so it is
    // reported rather than defaulted into the ignore set.
    const child = new FakeChild();
    const settled = settle(child);
    child.stdin.emit("error", new Error("stream ended unexpectedly"));
    const outcome = await settled;
    expect("result" in outcome).toBe(false);
    expect(String("error" in outcome && outcome.error)).toContain(
      "stream ended unexpectedly",
    );
  });

  it("rejects rather than resolving as success while the child is still running", async () => {
    // The child never exits here: the promise must still settle, and settle
    // as a failure, so a hung run is reported instead of passing.
    const child = new FakeChild();
    const settled = settle(child);
    child.stdin.emit("error", errno("EBADF"));
    const outcome = await settled;
    expect("result" in outcome).toBe(false);
    expect(String("error" in outcome && outcome.error)).toContain(
      "stdin failed",
    );
    // A late exit cannot turn the settled failure into a second completion.
    child.emit("close", 0);
  });

  it("settles once when the timeout and an stdin failure both fire", async () => {
    // Both paths reject; the second is a no-op on an already-settled promise,
    // so neither becomes an unhandled rejection nor a double completion. The
    // stdin path also clears the timer, so no misleading "did not finish"
    // rejection can arrive after the real one.
    const child = new FakeChild();
    const settled = settle(child, { timeoutMs: 5 });
    child.stdin.emit("error", errno("EBADF"));
    const outcome = await settled;
    expect(String("error" in outcome && outcome.error)).toContain(
      "stdin failed",
    );
    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(child.kill).toHaveBeenCalledOnce();
  });

  it("sends EOF when there is no input, and the input when there is", async () => {
    const bare = new FakeChild();
    const bareSettled = settle(bare);
    bare.emit("close", 0);
    await bareSettled;
    expect(bare.stdin.ended).toEqual([""]);

    const fed = new FakeChild();
    const fedSettled = settle(fed, { input: "the passphrase\n" });
    fed.emit("close", 0);
    await fedSettled;
    expect(fed.stdin.ended).toEqual(["the passphrase\n"]);
  });
});
