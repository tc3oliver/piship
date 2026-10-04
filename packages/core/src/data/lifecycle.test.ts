import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AUDIT_ROTATION } from "@piship/audit";
import { type DataManifest, parseData } from "@piship/schema";
import { STATE_DATA_CLASSES } from "../migration.js";
import {
  type DataSweptEvent,
  dataLifecycleIssues,
  effectiveRetention,
  effectiveRetentions,
  auditRotation,
  declaredRetention,
  sessionHasOwnerRecord,
  sweepData,
  sweepRetention,
} from "./lifecycle.js";

const DAY = 24 * 60 * 60_000;
const NOW = Date.parse("2026-10-04T12:00:00Z");

let state: string;
beforeEach(() => {
  state = mkdtempSync(join(tmpdir(), "piship-data-sweep-"));
});
afterEach(() => {
  rmSync(state, { recursive: true, force: true });
});

/** Write a file under the state directory with an mtime `ageDays` before NOW. */
function file(path: string, ageDays: number, content = "x\n"): string {
  const full = join(state, path);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
  const time = new Date(NOW - ageDays * DAY);
  utimesSync(full, time, time);
  return full;
}

function recorder() {
  const events: DataSweptEvent[] = [];
  return {
    events,
    record: (event: DataSweptEvent) => {
      events.push(event);
    },
  };
}

describe("retention bounds", () => {
  it("treats audit as a minimum and the other classes as maximums", () => {
    // A user may lengthen audit, never shorten it.
    expect(effectiveRetention("audit", 180 * DAY, 30 * DAY)).toBe(180 * DAY);
    expect(effectiveRetention("audit", 180 * DAY, 365 * DAY)).toBe(365 * DAY);
    // A user may shorten the others, never lengthen them.
    expect(effectiveRetention("sessions", 30 * DAY, 7 * DAY)).toBe(7 * DAY);
    expect(effectiveRetention("sessions", 30 * DAY, 90 * DAY)).toBe(30 * DAY);
    expect(effectiveRetention("cache", 7 * DAY, undefined)).toBe(7 * DAY);
    expect(effectiveRetention("temp", undefined, DAY)).toBe(DAY);
    expect(effectiveRetention("cache", undefined, undefined)).toBeUndefined();
  });

  it("leaves a class without any retention out", () => {
    expect(
      effectiveRetentions(
        { sessions: 30 * DAY, audit: 180 * DAY },
        { audit: 10 * DAY, cache: DAY },
      ),
    ).toEqual({ sessions: 30 * DAY, audit: 180 * DAY, cache: DAY });
    expect(effectiveRetentions({})).toEqual({});
  });

  it("purges onLogout classes at logout only, and never audit", () => {
    const retention = { sessions: 30 * DAY, audit: 180 * DAY };
    expect(sweepRetention("launch", retention, ["cache", "sessions"])).toEqual(
      retention,
    );
    expect(
      sweepRetention("logout", retention, ["cache", "temp", "audit"]),
    ).toEqual({ sessions: 30 * DAY, audit: 180 * DAY, cache: 0 });
  });

  it("rejects audit in onLogout", () => {
    const data = (onLogout: string[]) =>
      parseData({
        audit: { retention: "180d" },
        purge: { onLogout },
      }) as DataManifest;
    expect(
      dataLifecycleIssues(data(["cache", "audit"])).map((issue) => issue.path),
    ).toEqual(["data.purge.onLogout"]);
    expect(dataLifecycleIssues(data(["cache", "temp"]))).toEqual([]);
  });

  it("reads the declared retention in milliseconds", () => {
    const data = parseData({
      sessions: { retention: "30d" },
      audit: { retention: "180d" },
      temp: { retention: "12h" },
    }) as DataManifest;
    expect(declaredRetention(data)).toEqual({
      sessions: 30 * DAY,
      audit: 180 * DAY,
      temp: DAY / 2,
    });
  });

  it("gives the audit file rotation the declared audit minimum", () => {
    expect(auditRotation({})).toBe(AUDIT_ROTATION);
    expect(
      auditRotation({
        data: {
          declared: parseData({ audit: { retention: "180d" } }) as DataManifest,
        },
      }),
    ).toEqual({ ...AUDIT_ROTATION, minimumRetentionMs: 180 * DAY });
  });
});

describe("sweepData", () => {
  it("deletes only rotated audit files past retention, never the live log", async () => {
    const live = file("logs/audit.jsonl", 400);
    const oldRotated = file("logs/audit.jsonl.3", 200);
    const recentRotated = file("logs/audit.jsonl.1", 10);
    const lookalikes = [
      file("logs/audit.jsonl.0", 400),
      file("logs/audit.jsonl.2.tmp", 400),
      file("logs/audit.jsonl.lock", 400),
      file("logs/metrics.json", 400),
    ];
    const { events, record } = recorder();
    const result = await sweepData({
      stateDir: state,
      trigger: "launch",
      retention: { audit: 180 * DAY },
      record,
      now: NOW,
    });
    expect(existsSync(live)).toBe(true);
    expect(existsSync(oldRotated)).toBe(false);
    expect(existsSync(recentRotated)).toBe(true);
    for (const path of lookalikes) expect(existsSync(path)).toBe(true);
    expect(result.classes).toEqual([
      { class: "audit", removed: 1, held: 0, kept: 0, failed: 0 },
    ]);
    expect(events).toEqual([
      {
        event: "data.swept",
        resource: "audit",
        detail: {
          class: "audit",
          trigger: "launch",
          retentionSeconds: 180 * 24 * 60 * 60,
          cutoff: new Date(NOW - 180 * DAY).toISOString(),
          files: 1,
        },
      },
    ]);
  });

  it("writes the data.swept event before it deletes anything", async () => {
    const session = file("sessions/user/old.jsonl", 40);
    let presentWhenRecorded: boolean | undefined;
    await sweepData({
      stateDir: state,
      trigger: "launch",
      retention: { sessions: 30 * DAY },
      record: () => {
        presentWhenRecorded = existsSync(session);
      },
      now: NOW,
    });
    expect(presentWhenRecorded).toBe(true);
    expect(existsSync(session)).toBe(false);
  });

  it("deletes nothing of a class whose event cannot be recorded", async () => {
    const session = file("sessions/user/old.jsonl", 40);
    const cache = file("cache/blob", 40);
    const result = await sweepData({
      stateDir: state,
      trigger: "launch",
      retention: { sessions: 30 * DAY, cache: 7 * DAY },
      record: async (event) => {
        if (event.resource === "sessions") throw new Error("audit down");
      },
      now: NOW,
    });
    expect(existsSync(session)).toBe(true);
    expect(existsSync(cache)).toBe(false);
    expect(result.classes[0]).toMatchObject({
      class: "sessions",
      removed: 0,
      kept: 1,
      unrecorded: true,
    });
  });

  it("never touches an active (owner-held) session", async () => {
    const held = file("sessions/user/principal/2026_held.jsonl", 90);
    file(
      "sessions/user/principal/.piship-owners/2026_held.jsonl.00000000-0000-4000-8000-000000000000.json",
      0,
      "{}",
    );
    const free = file("sessions/user/principal/2026_free.jsonl", 90);
    const recent = file("sessions/user/principal/2026_recent.jsonl", 1);
    const { events, record } = recorder();
    const result = await sweepData({
      stateDir: state,
      trigger: "launch",
      retention: { sessions: 30 * DAY },
      record,
      now: NOW,
    });
    expect(existsSync(held)).toBe(true);
    expect(existsSync(free)).toBe(false);
    expect(existsSync(recent)).toBe(true);
    expect(result.classes).toEqual([
      { class: "sessions", removed: 1, held: 1, kept: 0, failed: 0 },
    ]);
    expect(events[0]?.detail).toMatchObject({ files: 1, held: 1 });
  });

  it("uses an injected live-owner check, and holds when it throws", async () => {
    const a = file("sessions/user/a.jsonl", 90);
    const b = file("sessions/user/b.jsonl", 90);
    const c = file("sessions/user/c.jsonl", 90);
    const { record } = recorder();
    await sweepData({
      stateDir: state,
      trigger: "launch",
      retention: { sessions: 30 * DAY },
      record,
      sessionHeld: (path) => {
        if (path === c) throw new Error("cannot tell");
        return path === a;
      },
      now: NOW,
    });
    expect(existsSync(a)).toBe(true);
    expect(existsSync(b)).toBe(false);
    expect(existsSync(c)).toBe(true);
  });

  it("keeps a session that becomes held between selection and deletion", async () => {
    const session = file("sessions/user/resumed.jsonl", 90);
    let claimed = false;
    const result = await sweepData({
      stateDir: state,
      trigger: "launch",
      retention: { sessions: 30 * DAY },
      record: () => {
        claimed = true;
      },
      sessionHeld: () => claimed,
      now: NOW,
    });
    expect(existsSync(session)).toBe(true);
    expect(result.classes[0]).toMatchObject({ removed: 0, kept: 1 });
  });

  it("never sweeps credential metadata or other unswept classes", async () => {
    // Every path of a class the sweep does not own, made very old.
    const untouched = STATE_DATA_CLASSES.filter(
      (entry) => !["sessions", "logs", "cache"].includes(entry.path),
    ).map((entry) =>
      entry.kind === "file"
        ? file(entry.path, 3650)
        : file(`${entry.path}/inner.jsonl`, 3650),
    );
    expect(
      untouched.some((path) => path.includes("credentials-metadata")),
    ).toBe(true);
    const { record } = recorder();
    await sweepData({
      stateDir: state,
      trigger: "logout",
      retention: { sessions: 0, audit: DAY, cache: 0 },
      record,
      now: NOW,
    });
    for (const path of untouched) expect(existsSync(path)).toBe(true);
  });

  it("purges every unheld session and cache file at logout", async () => {
    const session = file("sessions/user/today.jsonl", 0);
    const held = file("sessions/user/held.jsonl", 0);
    file(
      "sessions/user/.piship-owners/held.jsonl.00000000-0000-4000-8000-000000000001.json",
      0,
      "{}",
    );
    const cache = file("cache/a/b/c", 0);
    const audit = file("logs/audit.jsonl.1", 0);
    const { events, record } = recorder();
    await sweepData({
      stateDir: state,
      trigger: "logout",
      retention: sweepRetention("logout", { audit: 180 * DAY }, [
        "sessions",
        "cache",
      ]),
      record,
      now: NOW,
    });
    expect(existsSync(session)).toBe(false);
    expect(existsSync(held)).toBe(true);
    expect(existsSync(cache)).toBe(false);
    expect(existsSync(audit)).toBe(true);
    expect(events.map((event) => event.detail.retentionSeconds)).toEqual([
      0, 0,
    ]);
    expect(events.every((event) => event.detail.trigger === "logout")).toBe(
      true,
    );
  });

  it("does not sweep a class without a retention", async () => {
    const session = file("sessions/user/old.jsonl", 3650);
    const audit = file("logs/audit.jsonl.5", 3650);
    const { events, record } = recorder();
    const result = await sweepData({
      stateDir: state,
      trigger: "launch",
      retention: {},
      record,
      now: NOW,
    });
    expect(existsSync(session)).toBe(true);
    expect(existsSync(audit)).toBe(true);
    expect(events).toEqual([]);
    expect(result.classes).toEqual([]);
  });

  it.skipIf(process.platform === "win32")(
    "never follows or deletes a symbolic link",
    async () => {
      const outside = mkdtempSync(join(tmpdir(), "piship-data-outside-"));
      try {
        const target = join(outside, "victim.jsonl");
        writeFileSync(target, "keep\n");
        const old = new Date(NOW - 3650 * DAY);
        utimesSync(target, old, old);
        mkdirSync(join(state, "sessions", "user"), { recursive: true });
        symlinkSync(target, join(state, "sessions", "user", "link.jsonl"));
        symlinkSync(outside, join(state, "sessions", "user", "linked-dir"));
        mkdirSync(join(state, "logs"), { recursive: true });
        symlinkSync(target, join(state, "logs", "audit.jsonl.1"));
        symlinkSync(outside, join(state, "cache"));
        const { events, record } = recorder();
        await sweepData({
          stateDir: state,
          trigger: "logout",
          retention: { sessions: 0, audit: 0, cache: 0 },
          record,
          now: NOW,
        });
        expect(existsSync(target)).toBe(true);
        expect(existsSync(join(state, "sessions", "user", "link.jsonl"))).toBe(
          true,
        );
        expect(events).toEqual([]);
      } finally {
        rmSync(outside, { recursive: true, force: true });
      }
    },
  );

  it("finds owner records only for the named session", () => {
    const session = file("sessions/user/s.jsonl", 0);
    expect(sessionHasOwnerRecord(session)).toBe(false);
    file(
      "sessions/user/.piship-owners/s.jsonl.extra.jsonl.00000000-0000-4000-8000-000000000002.json",
      0,
    );
    // A record of `s.jsonl.extra.jsonl` starts with `s.jsonl.` too: still
    // conservative, it holds `s.jsonl`. Wrongly kept is harmless.
    expect(sessionHasOwnerRecord(session)).toBe(true);
    const other = file("sessions/user/t.jsonl", 0);
    expect(sessionHasOwnerRecord(other)).toBe(false);
  });
});
