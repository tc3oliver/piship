// The launch retention sweep with the session owner check the launch passes:
// a session another launch holds is never deleted, and is once released.
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sweepData } from "@piship/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { liveOwner, SessionOwnership } from "./session-file.js";

let state: string;
beforeEach(() => {
  state = realpathSync(mkdtempSync(join(tmpdir(), "piship-launch-sweep-")));
});
afterEach(() => {
  rmSync(state, { recursive: true, force: true });
});

describe("launch data sweep", () => {
  it("keeps a session a live launch owns, and sweeps it once released", async () => {
    const directory = join(state, "sessions", "user");
    mkdirSync(directory, { recursive: true });
    const session = join(directory, "2026_owned.jsonl");
    writeFileSync(session, "{}\n");
    const old = new Date(Date.now() - 90 * 24 * 60 * 60_000);
    utimesSync(session, old, old);
    const ownership = new SessionOwnership();
    expect(ownership.claim(session)).toBe(true);
    const sweep = () =>
      sweepData({
        stateDir: state,
        trigger: "launch",
        retention: { sessions: 30 * 24 * 60 * 60_000 },
        record: () => {},
        sessionHeld: (file) => liveOwner(file) !== undefined,
      });
    try {
      const held = await sweep();
      expect(existsSync(session)).toBe(true);
      expect(held.classes).toEqual([
        expect.objectContaining({ class: "sessions", removed: 0, held: 1 }),
      ]);
    } finally {
      ownership.release();
    }
    await sweep();
    expect(existsSync(session)).toBe(false);
  });
});
