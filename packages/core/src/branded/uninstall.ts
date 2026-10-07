// `<command> uninstall [--purge --yes]`: the branded way to remove an
// installed distribution, without finding the release directory's piship.mjs.
import { type Dirent, existsSync, lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { PiShipError } from "@piship/contracts";
import { readInstallReceipt, runtimeStateDirectory } from "../index.js";
import { signedInClasses } from "../install/purge.js";
import { appDirectory } from "../install/receipt.js";
import {
  uninstallAndPurgeDistribution,
  uninstallDistribution,
} from "../install/uninstall.js";
import type { BrandedContext } from "./context.js";
import { requireInstalled } from "./lifecycle.js";

const FLAGS = ["--purge", "--yes", "--without-logout", "--remove-edited-shim"];

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
  const usage = `Usage: ${app.command} uninstall [--purge --yes] [--without-logout] [--remove-edited-shim]`;
  if (
    flags.size !== args.length ||
    args.some((arg) => !FLAGS.includes(arg)) ||
    (flags.has("--yes") && !purge)
  )
    throw new PiShipError("CONFIG_INVALID", usage);
  requireInstalled(ctx, `${app.command} uninstall`);
  const id = app.id;
  const receipt = readInstallReceipt(id);
  const state = runtimeStateDirectory({ value: id });
  const withoutLogout = flags.has("--without-logout");
  const removeEditedShim = flags.has("--remove-edited-shim");
  if ((options.platform ?? process.platform) === "win32") {
    const mjs = join(ctx.distributionDir, "piship.mjs");
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `Windows keeps the files of a running ${app.command} open, so it cannot remove itself. Nothing was changed`,
      {
        userAction: `Open a new terminal and run: node "${mjs}" uninstall ${id}${purge ? " --purge --yes" : ""}${withoutLogout ? " --without-logout" : ""}${removeEditedShim ? " --remove-edited-shim" : ""}`,
      },
    );
  }
  if (purge && !flags.has("--yes"))
    throw new PiShipError(
      "CONFIG_INVALID",
      `${app.command} uninstall --purge also deletes this distribution's data in ${state}`,
      {
        userAction: `Repeat it with --yes: ${app.command} uninstall --purge --yes`,
      },
    );
  const live = signedInClasses(state);
  if (live.length && !withoutLogout && !purge)
    throw new PiShipError(
      "CONFIG_INVALID",
      `${app.name} is still signed in (${live.join(", ")}). Once it is uninstalled there is no ${app.command} left to sign out with, and the sign-in would stay live until it expires`,
      {
        userAction: `Run ${app.command} logout, then ${app.command} uninstall again; or add --without-logout to uninstall and leave the sign-in`,
      },
    );
  const installed = measure(appDirectory(id));
  const held = stateSummary(state);
  const shim = receipt.commandPath;
  if (purge) {
    const purged = await uninstallAndPurgeDistribution(id, {
      withoutLogout,
      removeEditedShim,
      ownSession: true,
    });
    if (purged.notRevoked)
      ctx.err(
        `Warning: ${purged.notRevoked.join(", ")} ${purged.notRevoked.length > 1 ? "were" : "was"} deleted locally but not revoked, and stays live at the identity provider or broker until it expires`,
      );
    const count = purged.deletedSecrets.length;
    ctx.out(
      [
        `Uninstalled ${app.name} and deleted its data.`,
        `  removed  ${app.command} (${shim}) and the installed releases (${size(installed)})`,
        `  deleted  ${purged.state} (${held})${count ? `, and ${count} secret-store entr${count === 1 ? "y" : "ies"}` : ""}`,
      ].join("\n"),
    );
    return;
  }
  uninstallDistribution(id, { removeEditedShim, ownSession: true });
  ctx.out(
    [
      `Uninstalled ${app.name}.`,
      `  removed  ${app.command} (${shim}) and the installed releases (${size(installed)})`,
      `  kept     ${state}: sessions and settings, ${held}`,
      live.length
        ? `  signed in: ${live.join(", ")} stays until it expires (uninstalled without logout)`
        : "  signed out: no sign-in is stored",
      `A later install of ${app.name} picks the kept data up again. To delete it instead, use ${app.command} uninstall --purge --yes in place of a plain uninstall, or, after this one, node <the release you installed from>/payload/piship.mjs purge ${id} --yes.`,
    ].join("\n"),
  );
}
