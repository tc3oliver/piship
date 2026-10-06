// Whether an install or update uses the shared file store, where it is, and
// how it places files. The one decision that depends on measurement is
// `defaultStoreMode`; everything else follows from it.
import {
  constants,
  copyFileSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { PiShipError } from "@piship/contracts";
import { searchToolCacheDirectory } from "../search-tools/index.js";
import { assertDisjointRoots, installHome } from "../state-paths.js";
import { ContentStore, type Primitive, storeLayout } from "./store.js";

/** `off` leaves every install and update as it was; the rest are `Primitive`s. */
export type StoreMode = Primitive | "off";

/**
 * What an install and an update do on `platform` when `PISHIP_STORE` is unset.
 *
 * `hardlink` on Windows, `off` everywhere else, because that is what the
 * measurements say (`docs/performance.md`). A store writes every object once
 * and then places from it, so it pays only where creating a file is expensive:
 * on Windows with Defender, hardlinking is 0.97x a direct extraction for a
 * first install (the store being filled) and 0.10x for a repeat install,
 * 0.17x for an update, and 0.70x for removal. On macOS every primitive costs
 * 2x to 6x more than writing the files, and Linux has no measurement showing
 * a gain, so both stay as they were. `copy` is never a candidate (it only
 * adds writes) and `clone` falls back to a copy on NTFS. An explicit
 * `PISHIP_STORE`, including `off`, always wins. This is the one place the
 * default is decided; `scripts/benchmark-store.mjs` produces the evidence.
 */
export function defaultStoreMode(
  platform: NodeJS.Platform = process.platform,
): StoreMode {
  return platform === "win32" ? "hardlink" : "off";
}

const MODES: readonly StoreMode[] = ["off", "copy", "clone", "hardlink"];

/**
 * The mode `PISHIP_STORE` names, or the default of `platform`; anything else
 * is refused.
 */
export function storeMode(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): StoreMode {
  const value = env.PISHIP_STORE?.trim().toLowerCase();
  if (!value) return defaultStoreMode(platform);
  const mode = MODES.find((candidate) => candidate === value);
  if (!mode)
    throw new PiShipError(
      "CONFIG_INVALID",
      `PISHIP_STORE=${env.PISHIP_STORE} is not one of ${MODES.join(", ")}`,
      {
        component: "install",
        userAction: "Unset PISHIP_STORE, or set it to one of those values",
      },
    );
  return mode;
}

/**
 * Where the store is: `PISHIP_STORE_HOME`, else `store` beside the
 * `runtime` cache and the search tool downloads in PiShip's user cache
 * directory (`PISHIP_CACHE_HOME`, or `piship` under `XDG_CACHE_HOME`,
 * `%LOCALAPPDATA%` on Windows, or `~/.cache`). On Windows that is
 * `%LOCALAPPDATA%\piship\store`.
 */
export function storeRoot(env: NodeJS.ProcessEnv = process.env): string {
  return env.PISHIP_STORE_HOME
    ? resolve(env.PISHIP_STORE_HOME)
    : join(dirname(searchToolCacheDirectory(env)), "store");
}

/**
 * Whether a clone from the store's volume to the install home's works: one
 * probe file, cloned with no fallback to a copy.
 */
function canClone(root: string, destination: string): boolean {
  const { temporary } = storeLayout(root);
  const source = join(temporary, `probe-${randomUUID()}`);
  const target = join(destination, `.piship-clone-probe-${randomUUID()}`);
  try {
    writeFileSync(source, "piship");
    mkdirSync(destination, { recursive: true });
    copyFileSync(
      source,
      target,
      constants.COPYFILE_EXCL | constants.COPYFILE_FICLONE_FORCE,
    );
    return true;
  } catch {
    return false;
  } finally {
    rmSync(source, { force: true });
    rmSync(target, { force: true });
  }
}

/**
 * The store an install or update places files from, or undefined when it
 * should write them itself: the mode is `off`, the store cannot be opened, or
 * the mode is `clone` and this machine cannot clone. Refuses a store inside,
 * around, or equal to PiShip's state, install, or bin home.
 */
export function openInstallStore(
  env: NodeJS.ProcessEnv = process.env,
): ContentStore | undefined {
  const mode = storeMode(env);
  if (mode === "off") return undefined;
  const root = storeRoot(env);
  assertDisjointRoots([["PISHIP_STORE_HOME", root]]);
  const store = ContentStore.open(root, { primitive: mode });
  if (!store) return undefined;
  if (mode === "clone" && !canClone(root, join(installHome(), "apps")))
    return undefined;
  return store;
}
