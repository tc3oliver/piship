// Fault injection for the synchronous file calls of atomic writes. A test
// file mocks node:fs with the pass-through wrapper, then arms faults for
// paths that match:
//
//   vi.mock("node:fs", async (importOriginal) =>
//     (await import("<relative>/tests/helpers/fs-faults.js")).faultyFs(
//       await importOriginal(),
//     ),
//   );
//
// Nothing changes until a fault is armed; `clearFaults()` disarms them all.
import type * as fs from "node:fs";

export type FsFault =
  /** Throw a system error with this code (ENOSPC, EACCES, EIO, ...). */
  | {
      readonly op: "open" | "write" | "fsync" | "rename";
      readonly code: string;
    }
  /** Write only half of the bytes asked for, and report that. */
  | { readonly op: "write"; readonly short: true }
  /** Write nothing and report 0 bytes. */
  | { readonly op: "write"; readonly stall: true };

interface Armed {
  readonly fault: FsFault;
  readonly match: (path: string) => boolean;
  remaining: number;
}

const armed: Armed[] = [];
/** `<op> <path>` of every fault that fired, in order. */
export const fired: string[] = [];

/**
 * Arm `fault` for paths matching `match` (for rename, the destination), for
 * `times` calls.
 */
export function injectFault(
  match: RegExp | ((path: string) => boolean),
  fault: FsFault,
  times = Number.POSITIVE_INFINITY,
): void {
  armed.push({
    fault,
    match: typeof match === "function" ? match : (path) => match.test(path),
    remaining: times,
  });
}

export function clearFaults(): void {
  armed.length = 0;
  fired.length = 0;
}

function take(op: FsFault["op"], path: string): FsFault | undefined {
  const item = armed.find(
    (candidate) =>
      candidate.fault.op === op &&
      candidate.remaining > 0 &&
      candidate.match(path),
  );
  if (!item) return undefined;
  item.remaining -= 1;
  fired.push(`${op} ${path}`);
  return item.fault;
}

function systemError(code: string, syscall: string, path: string): Error {
  return Object.assign(
    new Error(`${code}: injected ${syscall} failure, '${path}'`),
    { code, syscall, path },
  );
}

type Fs = typeof fs;

/** node:fs with `openSync`, `writeSync`, `fsyncSync`, and `renameSync` faultable. */
export function faultyFs(actual: Fs): Fs & { default: Fs } {
  const paths = new Map<number, string>();
  const openSync = ((path: fs.PathLike, ...rest: unknown[]) => {
    const fault = take("open", String(path));
    if (fault && "code" in fault)
      throw systemError(fault.code, "open", String(path));
    const fd = (actual.openSync as (...args: unknown[]) => number)(
      path,
      ...rest,
    );
    paths.set(fd, String(path));
    return fd;
  }) as Fs["openSync"];
  const closeSync = ((fd: number) => {
    paths.delete(fd);
    actual.closeSync(fd);
  }) as Fs["closeSync"];
  const writeSync = ((fd: number, data: unknown, ...rest: unknown[]) => {
    const path = paths.get(fd);
    const fault = path === undefined ? undefined : take("write", path);
    const write = actual.writeSync as (...args: unknown[]) => number;
    if (!fault) return write(fd, data, ...rest);
    if ("code" in fault) throw systemError(fault.code, "write", path as string);
    if ("stall" in fault) return 0;
    let bytes: Buffer;
    let offset = 0;
    let length: number;
    if (typeof data === "string") {
      bytes = Buffer.from(data);
      length = bytes.length;
    } else {
      const view = data as NodeJS.ArrayBufferView;
      bytes = Buffer.from(view.buffer, view.byteOffset, view.byteLength);
      offset = typeof rest[0] === "number" ? rest[0] : 0;
      length = typeof rest[1] === "number" ? rest[1] : bytes.length - offset;
    }
    return write(fd, bytes, offset, Math.max(1, Math.floor(length / 2)));
  }) as Fs["writeSync"];
  const fsyncSync = ((fd: number) => {
    const path = paths.get(fd);
    const fault = path === undefined ? undefined : take("fsync", path);
    if (fault && "code" in fault)
      throw systemError(fault.code, "fsync", path as string);
    actual.fsyncSync(fd);
  }) as Fs["fsyncSync"];
  const renameSync = ((from: fs.PathLike, to: fs.PathLike) => {
    const fault = take("rename", String(to));
    if (fault && "code" in fault)
      throw systemError(fault.code, "rename", String(to));
    actual.renameSync(from, to);
  }) as Fs["renameSync"];
  const overrides = { openSync, closeSync, writeSync, fsyncSync, renameSync };
  return { ...actual, ...overrides, default: { ...actual, ...overrides } };
}
