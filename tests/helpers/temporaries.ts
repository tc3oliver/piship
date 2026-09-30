// A PiShip temporary directory of another process, as its marker would have
// been written: for tests of the recovery of what a hard termination left. The
// marker names `pid`, which the test chooses with `deadPid()` (the owner is
// gone) or `livePid()` (it is running).
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  TEMPORARY_OWNER_FILE,
  TEMPORARY_OWNER_SCHEMA,
  createTemporaryDirectory,
  readTemporaryOwner,
  type TemporaryKind,
  type TemporaryOwner,
} from "@piship/contracts";

/** The host token of this machine, which a marker records. */
export function hostToken(parent: string): string {
  mkdirSync(parent, { recursive: true });
  const probe = createTemporaryDirectory(parent, "staging");
  try {
    return (readTemporaryOwner(probe.path) as { owner: TemporaryOwner }).owner
      .host;
  } finally {
    probe.remove();
  }
}

/** Make `parent/name` with some private output in it and a marker for `pid`. */
export function plantTemporary(
  parent: string,
  name: string,
  kind: TemporaryKind,
  pid: number,
): string {
  const host = hostToken(parent);
  const path = join(parent, name);
  mkdirSync(join(path, "x"), { recursive: true });
  writeFileSync(join(path, "x", "output.txt"), "private tool output");
  const owner: TemporaryOwner = {
    schema: TEMPORARY_OWNER_SCHEMA,
    kind,
    name,
    pid,
    instance: "0123456789abcdef",
    host,
    created: new Date().toISOString(),
  };
  writeFileSync(join(path, TEMPORARY_OWNER_FILE), JSON.stringify(owner));
  return path;
}
