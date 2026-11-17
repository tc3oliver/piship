// Governance group: what the runtime actually enforces. The seam table the
// lock was proven against, every action no seam enforces, the tool exposure
// a launch resolves, virtual models and Pi packages from the lock, the data
// lifecycle, and whether the manifest schema predates the current one.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { POLICY_ACTIONS } from "@piship/contracts";
import {
  inspectAgentFiles,
  packageEnvironment,
  releasesWithoutDataSweep,
} from "@piship/core";
import {
  enforcementStatus,
  manifestContainment,
  type PolicyContainment,
} from "@piship/policy";
import { DATA_CLASSES, LATEST_SCHEMA } from "@piship/schema";
import { policyContainment } from "../governance/engine.js";
import { routerPath } from "../launch/virtual-models.js";
import type { DoctorData } from "./data.js";
import type { DoctorSection } from "./report.js";

const DAY = 86_400;
const HOUR = 3_600;

/** False for a `.json` file that does not parse; true for any other file. */
function readsAsJson(agentDir: string, path: string): boolean {
  if (!path.endsWith(".json")) return true;
  try {
    JSON.parse(readFileSync(join(agentDir, ...path.split("/")), "utf8"));
    return true;
  } catch {
    return false;
  }
}

function duration(seconds: number): string {
  if (seconds % DAY === 0) return `${seconds / DAY}d`;
  if (seconds % HOUR === 0) return `${seconds / HOUR}h`;
  return `${seconds}s`;
}

/**
 * Containment as the session reports it when it was inspected, else as the
 * manifest declares it. A managed launch runs Pi offline.
 */
function containmentOf(data: DoctorData): PolicyContainment | undefined {
  const governance = data.governance;
  if (!governance) return undefined;
  const inspection = governance.inspection;
  return inspection
    ? {
        ...policyContainment(inspection.sandbox),
        piOffline: data.ctx.mode === "managed",
      }
    : manifestContainment(governance.manifest, data.ctx.mode);
}

export function governanceGroup(data: DoctorData, out: DoctorSection): void {
  const lock = data.ctx.metadata;
  if (lock.manifest.schema !== LATEST_SCHEMA)
    out.info(
      "manifest schema",
      `${lock.manifest.schema}; the maintainer runs piship migrate <manifest> --check, then --write, to adopt ${LATEST_SCHEMA}`,
    );
  if (lock.enforcement) {
    if (lock.enforcement.pi === data.piVersion)
      out.ok("seam table", `Pi ${lock.enforcement.pi}`);
    else
      out.warn(
        "seam table",
        `proven against Pi ${lock.enforcement.pi}, running Pi ${data.piVersion}; relock the distribution`,
      );
  }
  const containment = containmentOf(data);
  if (containment) {
    // session.export has its own line in the Policy group, per resource.
    const actions = POLICY_ACTIONS.filter(
      (action) => action !== "session.export",
    );
    const weak = actions
      .map(
        (action) => [action, enforcementStatus(action, containment)] as const,
      )
      .filter(([, status]) => status !== "enforced");
    out.ok(
      "enforced actions",
      `${actions.length - weak.length} of ${actions.length}`,
    );
    for (const [action, status] of weak) out.info(action, status);
  }
  const governance = data.governance;
  if (governance?.exposureError)
    out.bad("tool exposure", governance.exposureError);
  else if (governance?.exposure) {
    const exposure = governance.exposure;
    out.ok(
      "Codemode",
      exposure.codemodeOn ? `enforced (${exposure.codemode})` : "off",
    );
    out.ok("deferred tools", exposure.toolSearchOn ? "enforced" : "off");
    const byExposure = new Map<string, string[]>();
    for (const [tool, value] of Object.entries(exposure.tools))
      byExposure.set(value, [...(byExposure.get(value) ?? []), tool]);
    out.ok(
      "tool exposure",
      [...byExposure]
        .map(([value, tools]) => `${value}: ${tools.join(", ")}`)
        .join("; "),
    );
    if (lock.runtimeTools)
      out.info("extension tools", "exposure resolved and enforced at launch");
  }
  if (lock.virtualModels?.length) {
    // The router resolves as launch resolves it; one that names no built
    // extension cannot register the model, which then fails closed.
    for (const model of lock.virtualModels) {
      const detail = `router ${model.router}, routes ${model.routes.join(", ")}`;
      if (routerPath(lock, data.ctx.distributionDir, model.router))
        out.ok(`virtual ${model.id}`, detail);
      else
        out.bad(
          `virtual ${model.id}`,
          `${detail}; the router is not a declared extension of this build, so the model cannot be registered`,
        );
    }
  }
  if (lock.packages?.length) {
    // Doctor explicitly verifies every vendored file against the inventory.
    out.ok(
      "Pi packages",
      `${lock.packages.length} vendored, integrity verified by doctor`,
    );
    for (const item of lock.packages)
      out.info(
        `package ${item.id}`,
        `${item.source}${item.version ? ` ${item.version}` : ""}${item.commit ? ` ${item.commit.slice(0, 12)}` : ""} (${item.class}), ${item.files} files`,
      );
    // What the launch sets for the packages: values are manifest content, never
    // secrets, so they are shown as declared (a state path stays relative).
    for (const entry of packageEnvironment(lock, data.ctx.stateDir))
      out.info(
        `${entry.package} env`,
        `${entry.name}=${typeof entry.declared === "string" ? entry.declared : `<state>/${entry.declared.statePath}`}`,
      );
    for (const file of inspectAgentFiles(lock, data.ctx.agentDir)) {
      const mode = `${file.package} ${file.mode}`;
      if (file.state === "current")
        out.ok(`${mode} file`, `${file.path} as declared`);
      else if (
        file.state === "edited" &&
        !readsAsJson(data.ctx.agentDir, file.path)
      )
        out.warn(
          `${mode} file`,
          `${file.path} was edited and is no longer valid JSON, so ${file.package} cannot read it and runs on its own built-in defaults instead of the declared ones; fix it, or delete it to restore the declared default`,
        );
      else if (file.state === "edited")
        out.info(
          `${mode} file`,
          `${file.path} edited by the user and kept; delete it to restore the declared default`,
        );
      else if (file.state === "missing")
        out.info(
          `${mode} file`,
          `${file.path} not written yet; the next launch writes it`,
        );
      else
        out.warn(
          `${mode} file`,
          `${file.path} differs from the declared file; the next launch rewrites it`,
        );
    }
  }
  // Absent on a v1alpha6 lock means off; an older lock leaves Pi's setting.
  if (lock.enforcement || lock.cacheWarming) {
    const warming = lock.cacheWarming ?? { mode: "off", userOverride: false };
    out.ok(
      "cache warming",
      `${warming.mode}${warming.userOverride ? " (user may override)" : ""}`,
    );
  }
  if (governance?.runtimeError) out.bad("runtime", governance.runtimeError);
  else if (governance?.exposure)
    out.ok(
      "runtime mutation",
      "enforced per turn; a change that cannot be restored blocks the session",
    );
  const declared = lock.data?.declared;
  if (declared) {
    const retention = DATA_CLASSES.flatMap((dataClass) => {
      const item = declared.retention[dataClass];
      if (!item) return [];
      const bound = dataClass === "audit" ? "min" : "max";
      // No sweep applies a temp retention (launch.ts inertTempRetention).
      if (dataClass === "temp")
        return [`temp ${duration(item.retentionSeconds)} (not acted on)`];
      return [`${dataClass} ${duration(item.retentionSeconds)} ${bound}`];
    });
    out.ok(
      "data retention",
      retention.length ? retention.join(", ") : "no class declared",
    );
    const purge = `logout: ${declared.purge.onLogout.map((dataClass) => (dataClass === "temp" ? "temp (not acted on)" : dataClass)).join(", ") || "none"}; uninstall: ${declared.purge.onUninstall}${declared.purge.onUninstall === "all" ? " (not acted on yet: uninstall keeps state, purge deletes it)" : ""}`;
    if (
      declared.purge.onLogout.length &&
      (!lock.access || lock.access.credential.provider === "pi-native")
    )
      out.warn(
        "data purge",
        `${purge}; the logout purge never runs: sign-in is Pi's, and Pi's /logout purges nothing`,
      );
    else out.ok("data purge", purge);
    const older = releasesWithoutDataSweep(data.ctx);
    if (older.length)
      out.warn(
        "data retention",
        `installed release ${older.join(", ")} predates the data contract: rolled back to, it stops the retention sweep`,
      );
  } else if (lock.data)
    out.info("data retention", "not declared; nothing is swept");
}
