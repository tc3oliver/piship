// A shared, immutable, content-addressed store of the files an install or an
// update would otherwise write itself: the runtime, the Pi packages, and the
// dependencies a payload carries under `node_modules/` and `pi-packages/`.
//
// What it is. A cache that makes the second write of a file cheap. A file
// object is named by the SHA-256 of its bytes, is created once, is read-only,
// and is never modified or reused under another name. An installation is
// always whole without it: every file of an installed release is its own
// file in `apps/<id>/<version>` (with `hardlink`, a name for an object's
// inode, which survives the object's removal), the receipt names no store
// object, and a launch never opens the store. A release archive carries no
// reference to a store. So an offline machine with an empty store installs and
// launches exactly as one with a full store, and removing the store removes
// only the saved writes.
//
// What it is not. A source of trust. A file is placed only after the object's
// bytes are read back and hashed to the digest the archive's own bytes have,
// so a damaged or tampered object is detected, replaced from the bytes in
// hand, and never installed. The install is then checked against the
// release's inventory exactly as without a store.
//
// How a file is placed (`Primitive`):
// - `copy`: a new file with the object's bytes. Every installed file is its
//   own inode, so nothing a program writes to it reaches the store or another
//   installation.
// - `clone`: a copy-on-write clone where the volume has them (APFS, Btrfs,
//   XFS, ReFS); a new inode that shares blocks until written. Never aliased.
// - `hardlink`: the object's inode under a second name. No bytes are written
//   and no new content is scanned, but every installation that links the
//   object shares one file. Objects are read-only (0444, 0555) to make a write
//   through any of the names fail, and a placement hashes the object first,
//   so a mutated object is repaired, never spread; but a program that can
//   change a file's mode can still write through it, so it is not the default.
//
// Layout (`<root>`):
//   store.json                       layout schema
//   objects/<aa>/<sha256>[.x]        file objects; `.x` is the executable variant
//   refs/<id>/<version>.json         the objects one installed release placed
//   inflight/<id>                    an install or update that is populating the store
//   tmp/                             objects being written; renamed into objects/
import { createHash, randomUUID } from "node:crypto";
import {
  constants,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  chmod,
  copyFile,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { join } from "node:path";
import type { FilePlacement, FilePlacer } from "../archive.js";

export const STORE_SCHEMA = "piship-store/v1";
export const REF_SCHEMA = "piship-store-ref/v1";

/** How a stored file is given to an installation. */
export type Primitive = "copy" | "clone" | "hardlink";

/** How much of an object a placement reads before it is trusted. */
export type Verification = "content" | "size";

const WINDOWS = process.platform === "win32";
const DIGEST = /^[0-9a-f]{64}$/;
const ID = /^[a-z](?:[a-z0-9]|-(?=[a-z0-9]))*$/;
const VERSION = /^[0-9][0-9A-Za-z.+-]*$/;
/** Errors that say this volume or file system cannot do what the primitive needs. */
const UNSUPPORTED = new Set([
  "EXDEV",
  "ENOTSUP",
  "EOPNOTSUPP",
  "ENOSYS",
  "EPERM",
  "EINVAL",
]);

/**
 * The payload paths whose bytes are shared. Runtime, Pi package, and
 * dependency bytes: the same file in two installations is the same bytes
 * whoever ships it. A distribution's own resources, lock, policy, and metadata
 * stay where they are and never enter a store.
 */
export function isShareable(path: string): boolean {
  return path.startsWith("node_modules/") || path.startsWith("pi-packages/");
}

const sha256 = (data: Buffer): string =>
  createHash("sha256").update(data).digest("hex");

/** The object's file name: the digest, and `.x` for the executable variant (POSIX only). */
export function objectName(digest: string, executable: boolean): string {
  return executable && !WINDOWS ? `${digest}.x` : digest;
}

/** A parsed object file name, or undefined for any other name. */
export function parseObjectName(
  name: string,
): { digest: string; executable: boolean } | undefined {
  const executable = name.endsWith(".x");
  const digest = executable ? name.slice(0, -2) : name;
  return DIGEST.test(digest) ? { digest, executable } : undefined;
}

export const storeLayout = (root: string) => ({
  marker: join(root, "store.json"),
  objects: join(root, "objects"),
  refs: join(root, "refs"),
  inflight: join(root, "inflight"),
  temporary: join(root, "tmp"),
  lock: join(root, "gc.lock"),
});

export interface StoreCounts {
  /** Objects that were already stored and verified. */
  reused: number;
  /** Objects written. */
  created: number;
  /** Damaged objects found and replaced. */
  repaired: number;
  linked: number;
  cloned: number;
  copied: number;
  /** Files left to the caller's own write because the store could not place them. */
  declined: number;
}

export interface ContentStoreOptions {
  readonly primitive: Primitive;
  /** `content` (default) hashes an object before it is placed; `size` is for measurement only. */
  readonly verify?: Verification;
}

/**
 * One operation's view of a store. Create one per install or update, hand its
 * `placer()` to the extraction, `record` the release when it verified, and
 * `end` it.
 */
export class ContentStore {
  readonly root: string;
  readonly counts: StoreCounts = {
    reused: 0,
    created: 0,
    repaired: 0,
    linked: 0,
    cloned: 0,
    copied: 0,
    declined: 0,
  };
  private primitive: Primitive;
  private readonly verify: Verification;
  private readonly layout: ReturnType<typeof storeLayout>;
  private readonly ensured = new Map<string, Promise<void>>();
  private readonly directories = new Set<string>();
  private readonly placed = new Set<string>();
  private marker: string | undefined;
  private beginning: Promise<void> | undefined;
  private broken = false;

  private constructor(root: string, options: ContentStoreOptions) {
    this.root = root;
    this.layout = storeLayout(root);
    this.primitive = options.primitive;
    this.verify = options.verify ?? "content";
  }

  /**
   * The store at `root`, created if it does not exist; undefined where it
   * cannot be used (not writable, or a layout this PiShip does not know), so
   * an install carries on without it.
   */
  static open(
    root: string,
    options: ContentStoreOptions,
  ): ContentStore | undefined {
    const layout = storeLayout(root);
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      if (existsSync(layout.marker)) {
        const record = JSON.parse(readFileSync(layout.marker, "utf8")) as {
          schema?: unknown;
        } | null;
        if (record?.schema !== STORE_SCHEMA) return undefined;
      } else
        writeFileSync(
          layout.marker,
          `${JSON.stringify({ schema: STORE_SCHEMA })}\n`,
        );
      for (const directory of [
        layout.objects,
        layout.refs,
        layout.inflight,
        layout.temporary,
      ])
        mkdirSync(directory, { recursive: true, mode: 0o700 });
    } catch {
      return undefined;
    }
    return new ContentStore(root, options);
  }

  /** The primitive in use; it falls back to `copy` for good when the volume refuses another. */
  get activePrimitive(): Primitive {
    return this.primitive;
  }

  objectPath(digest: string, executable: boolean): string {
    return join(
      this.layout.objects,
      digest.slice(0, 2),
      objectName(digest, executable),
    );
  }

  /**
   * The hook an extraction calls for each small file it holds in memory. Paths
   * are taken relative to `prefix` (the payload's place in an archive entry's
   * name); files outside it are left to the extraction.
   */
  placer(prefix = ""): FilePlacer {
    return (file) =>
      file.path.startsWith(prefix)
        ? this.place({ ...file, path: file.path.slice(prefix.length) })
        : Promise.resolve(false);
  }

  /**
   * Place the file at `file.output` from the store, writing the object first
   * when it is missing or damaged. Returns false, with nothing left at the
   * output, when this file is not shared or the store cannot place it: the
   * caller writes it itself, and a store that failed is left alone for the
   * rest of the operation.
   */
  async place(file: FilePlacement): Promise<boolean> {
    if (this.broken || file.data.length === 0 || !isShareable(file.path)) {
      this.counts.declined++;
      return false;
    }
    try {
      await this.begin();
      const object = await this.ensure(file.digest, file.exec, file.data);
      await this.give(object, file.output, file.exec);
      this.placed.add(objectName(file.digest, file.exec));
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") throw error;
      await rm(file.output, { force: true }).catch(() => undefined);
      this.broken = true;
      this.counts.declined++;
      return false;
    }
  }

  /**
   * Remember which objects the release `id`@`version` placed, so a collection
   * keeps them while the release is the active or the rollback one. Written
   * whole or not at all; false when it could not be (the install is not
   * affected: the objects are then not pinned and a collection may remove
   * them).
   */
  record(id: string, version: string, home: string): boolean {
    if (!ID.test(id) || !VERSION.test(version)) return false;
    try {
      const directory = join(this.layout.refs, id);
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const path = join(directory, `${version}.json`);
      const temporary = join(this.layout.temporary, `ref-${randomUUID()}`);
      writeFileSync(
        temporary,
        JSON.stringify({
          schema: REF_SCHEMA,
          id,
          version,
          home,
          objects: [...this.placed].sort(),
        }),
      );
      renameSync(temporary, path);
      return true;
    } catch {
      return false;
    }
  }

  /** Finish the operation: nothing is in flight any more. Never throws. */
  end(): void {
    if (this.marker) rmSync(this.marker, { force: true });
    this.marker = undefined;
    this.beginning = undefined;
  }

  /** The operation is in flight until `end`: a collection does not sweep while it runs. */
  private begin(): Promise<void> {
    this.beginning ??= (async () => {
      const marker = join(this.layout.inflight, randomUUID());
      await (await open(marker, "wx")).close();
      this.marker = marker;
    })();
    return this.beginning;
  }

  private async directory(path: string): Promise<void> {
    if (this.directories.has(path)) return;
    await mkdir(path, { recursive: true, mode: 0o700 });
    this.directories.add(path);
  }

  /** The object for `digest`, verified, or written from `data`; once per object per operation. */
  private ensure(
    digest: string,
    executable: boolean,
    data: Buffer,
  ): Promise<string> {
    const path = this.objectPath(digest, executable);
    let pending = this.ensured.get(path);
    if (!pending) {
      pending = this.prepare(path, digest, executable, data);
      this.ensured.set(path, pending);
      pending.catch(() => this.ensured.delete(path));
    }
    return pending.then(() => path);
  }

  private async prepare(
    path: string,
    digest: string,
    executable: boolean,
    data: Buffer,
  ): Promise<void> {
    const state = await this.inspect(path, digest, data.length);
    if (state === "ok") {
      this.counts.reused++;
      return;
    }
    if (state === "damaged") {
      await rm(path, { force: true });
      this.counts.repaired++;
    }
    await this.directory(join(this.layout.objects, digest.slice(0, 2)));
    const temporary = join(this.layout.temporary, randomUUID());
    try {
      const file = await open(temporary, "wx", 0o600);
      try {
        await file.writeFile(data);
      } finally {
        await file.close();
      }
      await chmod(temporary, executable && !WINDOWS ? 0o555 : 0o444);
      try {
        // Another process may publish the same object first. On Windows
        // that makes this rename fail, since the object is read-only.
        await rename(temporary, path);
      } catch (error) {
        if ((await this.inspect(path, digest, data.length)) !== "ok")
          throw error;
        this.counts.reused++;
        return;
      }
      this.counts.created++;
    } finally {
      await rm(temporary, { force: true }).catch(() => undefined);
    }
  }

  /** Whether the object is absent, as its name says, or not. */
  private async inspect(
    path: string,
    digest: string,
    size: number,
  ): Promise<"ok" | "missing" | "damaged"> {
    let info: Awaited<ReturnType<typeof lstat>>;
    try {
      info = await lstat(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing";
      throw error;
    }
    if (!info.isFile() || info.size !== size) return "damaged";
    if (this.verify === "size") return "ok";
    return sha256(await readFile(path)) === digest ? "ok" : "damaged";
  }

  /** Create `output` from `object` by the primitive, copying where it cannot. */
  private async give(
    object: string,
    output: string,
    executable: boolean,
  ): Promise<void> {
    const mode = WINDOWS ? 0o666 : executable ? 0o755 : 0o644;
    if (this.primitive === "hardlink")
      try {
        await link(object, output);
        this.counts.linked++;
        return;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EEXIST") throw error;
        // A file system without links stops the attempts; a file that has
        // all the links it can have (EMLINK) is only copied itself.
        if (code && UNSUPPORTED.has(code)) this.primitive = "copy";
      }
    else if (this.primitive === "clone")
      try {
        await copyFile(
          object,
          output,
          constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE_FORCE,
        );
        await chmod(output, mode);
        this.counts.cloned++;
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") throw error;
        await rm(output, { force: true });
        this.primitive = "copy";
      }
    await copyFile(object, output, constants.COPYFILE_EXCL);
    // A copy keeps the object's read-only mode; the installed file is the
    // installation's to have, as a file written by extraction is.
    await chmod(output, mode);
    this.counts.copied++;
  }
}
