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
import { installHome } from "../index.js";
import { processIdentity } from "../process-identity.js";
import { acquireLifecycleLock } from "./lifecycle-lock.js";
import { appDirectory, syncDirectory, VERSION_NAME } from "./receipt.js";

const SCHEMA = "piship-runtime-lease/v1";
const UNKNOWN_IDENTITY_STALE_MS = 24 * 60 * 60_000;

interface Lease {
  readonly schema: typeof SCHEMA;
  readonly pid: number;
  readonly identity: string | null;
  readonly instance: string;
  readonly version: string;
}

function leaseRoot(id: string): string {
  return join(appDirectory(id), ".runtime-leases");
}

/** Shared by launcher registration and every destructive payload operation. */
export function acquireLaunchGate(id: string) {
  const path = join(installHome(), "receipts", `.${id}.launch.lock`);
  return acquireLifecycleLock(
    path,
    () =>
      new Error(
        `A launcher or lifecycle operation for ${id} is registering; retry`,
      ),
    () => new Error(`Could not lock launcher registration for ${id}`),
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
    return value;
  } catch {
    return undefined;
  }
}

function alive(lease: Pick<Lease, "pid" | "identity">, path: string): boolean {
  try {
    process.kill(lease.pid, 0);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EPERM") return false;
  }
  const identity = processIdentity(lease.pid);
  if (lease.identity && identity) return lease.identity === identity;
  // A platform unable to query a process start time is conservative while
  // the lease is recent, then reclaims it after an extended stale interval.
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
        let record: { pid: number; identity: null } | undefined;
        try {
          const value = JSON.parse(readFileSync(path, "utf8")) as Record<
            string,
            unknown
          >;
          if (
            value.schema === "piship-launching-lease/v1" &&
            Number.isSafeInteger(value.pid) &&
            (value.pid as number) > 0
          )
            record = { pid: value.pid as number, identity: null };
        } catch {
          /* stale */
        }
        const live = record ? alive(record, path) : recentUnverified(path);
        result.push({ version: "*", live, path });
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
      const live = record ? alive(record, path) : recentUnverified(path);
      result.push({ version, live, path });
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
  const record: Lease = {
    schema: SCHEMA,
    pid: process.pid,
    identity: processIdentity(process.pid) ?? null,
    instance,
    version,
  };
  const bytes = `${JSON.stringify(record)}\n`;
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  syncDirectory(directory);
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
