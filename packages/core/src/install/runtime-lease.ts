// A launched payload stays present while a process can still read its
// resources. The lease names a process instance, so a reused PID does not
// make a crashed session look live.
import { randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { PiShipError, processHostToken } from "@piship/contracts";
import { installHome } from "../index.js";
import {
  type ProcessRecord,
  processIdentity,
  recordedIdentity,
  recordedProcessGone,
  recordedStart,
} from "../process-identity.js";
import { acquireLifecycleLock } from "./lifecycle-lock.js";
import { appDirectory, VERSION_NAME } from "./receipt.js";

const SCHEMA = "piship-runtime-lease/v1";
const UNKNOWN_IDENTITY_STALE_MS = 24 * 60 * 60_000;

interface Lease {
  readonly schema: typeof SCHEMA;
  readonly pid: number;
  /** Null off Linux: reading it starts a process (`recordedIdentity`). */
  readonly identity: string | null;
  /** Absent in a lease of an earlier PiShip. */
  readonly host?: string | null;
  readonly started?: number | null;
  readonly instance: string;
  readonly version: string;
}

function leaseRoot(id: string): string {
  return join(appDirectory(id), ".runtime-leases");
}

/**
 * How long a lifecycle operation waits for the launch gate: a launcher holds
 * it only while it registers, which takes well under a second.
 */
const LAUNCH_GATE_WAIT_MS = 3_000;

/**
 * Shared by launcher registration and every destructive payload operation. A
 * holder that keeps the gate past the wait fails the operation with `code`,
 * as retryable.
 */
export function acquireLaunchGate(
  id: string,
  code: "UPDATE_FAILED" | "ROLLBACK_FAILED" = "UPDATE_FAILED",
) {
  const path = join(installHome(), "receipts", `.${id}.launch.lock`);
  return acquireLifecycleLock(
    path,
    (_pid, holder) =>
      new PiShipError(
        code,
        `A launcher or lifecycle operation for ${id} is registering: ${path} is held by ${holder}`,
        {
          retryable: true,
          userAction: `Try again in a moment; if no launcher or PiShip command of ${id} is running, remove ${path}`,
        },
      ),
    () => new Error(`Could not lock launcher registration for ${id}`),
    LAUNCH_GATE_WAIT_MS,
  );
}

function parseLease(path: string, version: string): Lease | undefined {
  try {
    const value = JSON.parse(readFileSync(path, "utf8")) as Lease;
    if (
      value.schema !== SCHEMA ||
      value.version !== version ||
      !Number.isSafeInteger(value.pid) ||
      value.pid < 1 ||
      typeof value.instance !== "string" ||
      !/^[0-9a-f-]{36}$/.test(value.instance) ||
      (value.identity !== null && typeof value.identity !== "string")
    )
      return undefined;
    return {
      ...value,
      host:
        typeof value.host === "string" && /^[0-9a-f]{12}$/.test(value.host)
          ? value.host
          : null,
      started: Number.isSafeInteger(value.started)
        ? (value.started as number)
        : null,
    };
  } catch {
    return undefined;
  }
}

function alive(
  lease: Pick<ProcessRecord, "pid" | "identity"> & Partial<ProcessRecord>,
  path: string,
): boolean {
  const gone = recordedProcessGone({
    host: null,
    started: null,
    ...lease,
  });
  if (gone !== undefined) return !gone;
  // A record that cannot be judged (another host's, or one whose process
  // start cannot be read) is conservative while it is recent, then reclaimed
  // after an extended stale interval.
  try {
    return Date.now() - statSync(path).mtimeMs < UNKNOWN_IDENTITY_STALE_MS;
  } catch {
    return false;
  }
}

function recentUnverified(path: string): boolean {
  try {
    return Date.now() - statSync(path).mtimeMs < 60_000;
  } catch {
    return false;
  }
}

export interface RuntimeLeaseStatus {
  readonly version: string;
  readonly live: boolean;
  readonly path: string;
  /** Held by this process, such as the launcher running doctor. */
  readonly self: boolean;
}

/** Whether a lease record names this very process. */
function ownLease(
  record:
    | {
        readonly pid: number;
        readonly identity: string | null;
        readonly started?: number | null;
      }
    | undefined,
): boolean {
  if (record?.pid !== process.pid) return false;
  if (record.identity !== null)
    return record.identity === processIdentity(process.pid);
  // A start time is exact for this process; a record with neither names
  // only a process ID (an earlier PiShip), which is all there is to compare.
  return record.started == null || record.started === recordedStart();
}

/** Inspect known leases; optionally remove only stale records. */
export function runtimeLeases(id: string, sweep = false): RuntimeLeaseStatus[] {
  const root = leaseRoot(id);
  if (!existsSync(root)) return [];
  const result: RuntimeLeaseStatus[] = [];
  for (const version of readdirSync(root)) {
    if (version === ".launching") {
      const directory = join(root, version);
      let names: string[];
      try {
        names = readdirSync(directory);
      } catch {
        continue;
      }
      for (const name of names) {
        if (!/^[0-9a-f-]{36}\.json$/.test(name)) continue;
        const path = join(directory, name);
        let record: ProcessRecord | undefined;
        try {
          const value = JSON.parse(readFileSync(path, "utf8")) as Record<
            string,
            unknown
          >;
          // A marker of an earlier launcher names only its process ID.
          if (
            value.schema === "piship-launching-lease/v1" &&
            Number.isSafeInteger(value.pid) &&
            (value.pid as number) > 0
          )
            record = {
              pid: value.pid as number,
              identity:
                typeof value.identity === "string" &&
                value.identity.length <= 128
                  ? value.identity
                  : null,
              host:
                typeof value.host === "string" &&
                /^[0-9a-f]{12}$/.test(value.host)
                  ? value.host
                  : null,
              started: Number.isSafeInteger(value.started)
                ? (value.started as number)
                : null,
            };
        } catch {
          /* stale */
        }
        const self = ownLease(record);
        const live = self
          ? true
          : record
            ? alive(record, path)
            : recentUnverified(path);
        result.push({ version: "*", live, path, self });
        if (sweep && !live) rmSync(path, { force: true });
      }
      // Keep the launching directory: a new launcher can create a marker
      // concurrently with recovery, before it has read the receipt.
      continue;
    }
    if (!VERSION_NAME.test(version)) continue;
    const directory = join(root, version);
    try {
      if (!lstatSync(directory).isDirectory()) continue;
    } catch {
      continue;
    }
    for (const name of readdirSync(directory)) {
      if (!/^[0-9a-f-]{36}\.json$/.test(name)) continue;
      const path = join(directory, name);
      const record = parseLease(path, version);
      // This process's own lease needs no judging, and so no system query.
      const self = ownLease(record);
      const live = self
        ? true
        : record
          ? alive(record, path)
          : recentUnverified(path);
      result.push({ version, live, path, self });
      if (sweep && !live) rmSync(path, { force: true });
    }
    // Keep the directory: removing it could race a launcher between mkdir
    // and its exclusive lease file creation.
  }
  return result;
}

/** Hold a lease from launcher activation through process exit. */
export function holdRuntimeLease(id: string, version: string): () => void {
  if (!VERSION_NAME.test(version))
    throw new Error("Unsafe runtime lease version");
  const root = leaseRoot(id);
  const directory = join(root, version);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const instance = randomUUID();
  const path = join(directory, `${instance}.json`);
  // The record names this process by pid, host, start time and a random
  // instance, without asking the system for its start identity, which on
  // Windows is a PowerShell start. A process that finds the lease and must
  // judge it asks then (`recordedProcessGone`). A lease is only meaningful
  // while its process runs, so it is not flushed to disk: after a crash or a
  // reset there is no process left for it to name.
  const record: Lease = {
    schema: SCHEMA,
    pid: process.pid,
    identity: recordedIdentity(),
    host: processHostToken(),
    started: recordedStart(),
    instance,
    version,
  };
  const bytes = `${JSON.stringify(record)}\n`;
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  const beat = setInterval(() => {
    try {
      const now = new Date();
      utimesSync(path, now, now);
    } catch {
      /* removed */
    }
  }, 15_000);
  beat.unref?.();
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    clearInterval(beat);
    process.removeListener("exit", release);
    try {
      if (readFileSync(path, "utf8") === bytes) rmSync(path, { force: true });
    } catch {
      /* recovered later */
    }
  };
  process.on("exit", release);
  return release;
}
