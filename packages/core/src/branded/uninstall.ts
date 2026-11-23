// `<command> uninstall [--without-logout] [--purge --yes]`: the branded way to remove an
// installed distribution, without finding the release directory's piship.mjs.
import { type Dirent, existsSync, lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { currentTarget } from "../compatibility.js";
import { readInstallReceipt, runtimeStateDirectory } from "../index.js";
import {
  purgeManager,
  removeEmptyPiShipDirectories,
  piSignedIn,
  STORED_API_KEY,
  signedInClasses,
} from "../install/purge.js";
import { appDirectory } from "../install/receipt.js";
import {
  uninstallAndPurgeDistribution,
  uninstallDistribution,
} from "../install/uninstall.js";
import { shellArg } from "../invocation.js";
import { type BrandedContext, usageRefusal } from "./context.js";
import { requireInstalled } from "./lifecycle.js";

const FLAGS = ["--purge", "--yes", "--without-logout", "--remove-edited-shim"];
/** The options `uninstall` accepts, as its usage and the branded help print them. */
export const UNINSTALL_OPTIONS =
  "[--without-logout] [--purge --yes] [--remove-edited-shim]";

/** Measuring a directory stops after this many entries or this long. */
const MEASURE_ENTRIES = 50_000;
const MEASURE_MS = 1500;

interface Measured {
  readonly bytes: number;
  /** The walk stopped early; the size is a lower bound. */
  readonly partial: boolean;
}

/** The size of a tree by lstat, never following a link, within a budget. */
function measure(path: string): Measured {
  const deadline = performance.now() + MEASURE_MS;
  let entries = 0;
  let bytes = 0;
  let partial = false;
  const walk = (directory: string): void => {
    let names: Dirent[];
    try {
      names = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of names) {
      if (partial) return;
      if (++entries > MEASURE_ENTRIES || performance.now() > deadline) {
        partial = true;
        return;
      }
      const child = join(directory, entry.name);
      if (entry.isDirectory()) walk(child);
      else
        try {
          bytes += lstatSync(child).size;
        } catch {
          // Gone while measuring.
        }
    }
  };
  walk(path);
  return { bytes, partial };
}

function size({ bytes, partial }: Measured): string {
  const text =
    bytes >= 1_048_576
      ? `${(bytes / 1_048_576).toFixed(1)} MiB`
      : `${Math.ceil(bytes / 1024)} KiB`;
  return partial ? `at least ${text}` : text;
}

/** What the state directory holds, in one line: the biggest parts first. */
function stateSummary(state: string): string {
  if (!existsSync(state)) return "nothing stored";
  const parts = readdirSync(state, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({
      name: entry.name,
      measured: measure(join(state, entry.name)),
    }))
    .filter((part) => part.measured.bytes > 0)
    .sort((a, b) => b.measured.bytes - a.measured.bytes)
    .slice(0, 4);
  const total = measure(state);
  return `${size(total)}${parts.length ? ` (${parts.map((part) => `${part.name} ${size(part.measured)}`).join(", ")})` : ""}`;
}

export interface UninstallCommandOptions {
  /** Test seam: the platform whose rules apply. */
  readonly platform?: NodeJS.Platform;
}

/**
 * Uninstall the installed distribution this command belongs to. Sessions and
 * settings stay unless `--purge --yes` is given; a distribution that is
 * still signed in is refused (as purge refuses it) until `<command> logout`
 * has revoked the sign-in, because once the install is gone there is no
 * command left to do it. `--without-logout` accepts leaving it.
 *
 * The running process holds a lease on the payload it removes, which an
 * uninstall started from the command itself does not count as another
 * session. Windows keeps the files of a running program open, so there the
 * exact command to run from a new terminal is printed instead.
 */
export async function runUninstall(
  ctx: BrandedContext,
  args: readonly string[],
  options: UninstallCommandOptions = {},
): Promise<void> {
  const { app } = ctx.metadata;
  const flags = new Set(args);
  const purge = flags.has("--purge");
  const usage = `Usage: ${app.command} uninstall ${UNINSTALL_OPTIONS}`;
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    ctx.out(
      `${usage}\n\nUninstall ${app.name} for this user. Sessions and settings stay unless --purge --yes also deletes them; while ${app.name} is still signed in, it is refused until ${app.command} logout, or --without-logout leaves the sign-in.`,
    );
    return;
  }
  if (
    flags.size !== args.length ||
    args.some((arg) => !FLAGS.includes(arg)) ||
    (flags.has("--yes") && !purge)
  )
    throw usageRefusal("uninstall", usage, args, FLAGS);
  requireInstalled(ctx, `${app.command} uninstall`);
  const id = app.id;
  const receipt = readInstallReceipt(id);
  const state = runtimeStateDirectory({ value: id });
  const withoutLogout = flags.has("--without-logout");
  const removeEditedShim = flags.has("--remove-edited-shim");
  if (purge && !flags.has("--yes"))
    throw new PiShipError(
      "CONFIG_INVALID",
      `${app.command} uninstall --purge also deletes ${app.name}'s data in ${state}`,
      {
        userAction: `Repeat it with --yes: ${app.command} uninstall --purge --yes`,
        usage: true,
      },
    );
  const live = signedInClasses(state);
  // A local-secret key never expires and has no remote side to revoke: only
  // logout deletes it from the secret store.
  if (
    !withoutLogout &&
    !purge &&
    live.length === 1 &&
    live[0] === STORED_API_KEY
  )
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `${app.name} still has its API key stored. Once it is uninstalled there is no ${app.command} left to delete it, and the key would remain in the secret store`,
      {
        userAction: `Run ${app.command} logout to delete the stored key, then ${app.command} uninstall again; or add --without-logout to uninstall and keep the key in the secret store`,
      },
    );
  if (live.some((item) => item !== STORED_API_KEY) && !withoutLogout && !purge)
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `${app.name} is still signed in (${live.join(", ")}). Once it is uninstalled there is no ${app.command} left to sign out with, and the sign-in would stay live until it expires`,
      {
        userAction: `Run ${app.command} logout, then ${app.command} uninstall again; or add --without-logout to uninstall and leave the sign-in`,
      },
    );
  // After the refusals above, so a Windows user still signs out first and
  // confirms --purge before being handed a command that removes the payload.
  const platform = options.platform ?? process.platform;
  if (platform === "win32") {
    const mjs = join(ctx.distributionDir, "piship.mjs");
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `Windows keeps the files of a running ${app.command} open, so it cannot remove itself. Nothing was changed`,
      {
        userAction: `Open a new terminal and run: node ${shellArg(mjs, platform)} uninstall ${id}${purge ? " --purge --yes" : ""}${withoutLogout ? " --without-logout" : ""}${removeEditedShim ? " --remove-edited-shim" : ""}`,
      },
    );
  }
  if (purge) {
    const installed = measure(appDirectory(id));
    const held = stateSummary(state);
    const shim = receipt.commandPath;
    const purged = await uninstallAndPurgeDistribution(id, {
      withoutLogout,
      removeEditedShim,
      ownSession: true,
    });
    if (purged.notRevoked)
      ctx.err(
        `Warning: ${purged.notRevoked.join(", ")} ${purged.notRevoked.length > 1 ? "were" : "was"} deleted locally but not revoked, and stays live at the identity provider or broker until it expires`,
      );
    if (purged.undeliveredAudit)
      ctx.err(
        `Warning: ${purged.undeliveredAudit} audit event(s) were still waiting in the local spool for the collector and were deleted with the state; they were never delivered`,
      );
    const count = purged.deletedSecrets.length;
    ctx.out(
      [
        `Uninstalled ${app.name} and deleted its data.`,
        `  removed  ${app.command} (${shim}) and the installed releases (${size(installed)})`,
        `  deleted  ${purged.state}: ${held}${count ? `, and ${count} secret-store entr${count === 1 ? "y" : "ies"}` : ""}`,
        purged.deletedApiKey
          ? "  deleted  the stored API key (only stored here: there is nothing to revoke)"
          : "",
      ]
        .filter(Boolean)
        .join("\n"),
    );
    removeEmptyPiShipDirectories();
    return;
  }
  ctx.out(uninstallKeepingState(id, { removeEditedShim, ownSession: true }));
}

/**
 * Uninstall `id` and keep its state, returning what was removed and kept,
 * Pi's own sign-in included. `<command> uninstall` and `piship uninstall`
 * print it alike. `purge`, asked after the uninstall, names a command that
 * can still purge it; otherwise the installed release's is named.
 */
export function uninstallKeepingState(
  id: string,
  options: {
    readonly removeEditedShim?: boolean;
    readonly ownSession?: boolean;
    readonly purge?: () => string | undefined;
  } = {},
): string {
  const receipt = readInstallReceipt(id);
  const { name, command } = receipt.app;
  const state = runtimeStateDirectory({ value: id });
  const signedIn = signedInClasses(state);
  const live = signedIn.filter((item) => item !== STORED_API_KEY);
  const key = signedIn.length !== live.length;
  const piAuth = join(state, "agent", "auth.json");
  const installed = measure(appDirectory(id));
  const held = stateSummary(state);
  const shim = receipt.commandPath;
  // Read before the receipt goes: purge then runs from what was installed.
  const release = receipt.releases.find(
    (item) => item.version === receipt.active,
  )?.release;
  const fromRelease = Boolean(release);
  const manager = purgeManager(id);
  // A Company Pack install has no release directory: its piship.mjs comes
  // with the runtime archive the pack was installed with.
  const runtime =
    release?.runtime && manager === "<release>/payload/piship.mjs"
      ? `piship-runtime-${release.runtime.pishipVersion}-${currentTarget()}`
      : undefined;
  uninstallDistribution(id, {
    ...(options.removeEditedShim ? { removeEditedShim: true } : {}),
    ...(options.ownSession ? { ownSession: true } : {}),
  });
  removeEmptyPiShipDirectories();
  const purge = options.purge?.();
  const purgeHint = purge
    ? `run: ${purge} purge ${shellArg(id)} --yes.`
    : runtime
      ? `extract the runtime archive ${runtime}.tar.gz you installed the pack with and run: node <extracted folder>/${runtime}/payload/piship.mjs purge ${id} --yes.`
      : `run purge from the ${fromRelease ? "release" : "build"} you installed: node ${manager} purge ${id} --yes${fromRelease ? "" : " in the directory you built in"}.`;
  const pi = piSignedIn(state);
  return [
    `Uninstalled ${name}.`,
    `  removed  ${command} (${shim}) and the installed releases (${size(installed)})`,
    `  kept     ${state}: sessions and settings, ${held}`,
    live.length
      ? `  signed in: ${live.join(", ")} ${live.length > 1 ? "stay" : "stays"} until ${live.length > 1 ? "they expire" : "it expires"} (uninstalled without logout)`
      : pi || key
        ? ""
        : "  signed out: no sign-in is stored",
    key
      ? "  kept     the stored API key, in the secret store; purge deletes it"
      : "",
    pi
      ? `  signed in: Pi's own sign-in (${piAuth}) stays with the kept data; purge deletes it`
      : "",
    `A later install of ${name} picks the kept data up again. To delete it, ${purgeHint} Next time, ${command} uninstall --purge --yes does both.`,
  ]
    .filter(Boolean)
    .join("\n");
}
