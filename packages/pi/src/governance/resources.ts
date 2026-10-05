// Declared and builtin resources of a governed session: trust, certified
// integrity, and the policy decision for each before it loads.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { PiShipError } from "@piship/contracts";
import { type GovernanceLock, treeDigest } from "@piship/core";
import { resourceTrustDecision } from "@piship/policy";
import type {
  DeclaredResource,
  GovernanceManifest,
  PackageResourceKind,
} from "@piship/schema";
import type { GovernanceSession } from "../governance-session.js";
import { KIND_ACTION, type ResourceEvidence } from "./options.js";

function sha256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Hash the installed files of one declared root inside the payload. */
export function payloadTree(resourceDir: string, declared: string): string {
  const root = join(resourceDir, ...declared.slice(2).split("/"));
  const files: { path: string; sha256: string }[] = [];
  const visit = (path: string) => {
    const stat = statSync(path);
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) visit(join(path, name));
      return;
    }
    const rel = relative(root, path).split(sep).join("/");
    files.push({
      path: rel === "" ? (declared.split("/").at(-1) ?? declared) : rel,
      sha256: sha256(readFileSync(path)),
    });
  };
  if (existsSync(root)) visit(root);
  return treeDigest(files);
}

export async function resolveResources(
  session: GovernanceSession,
): Promise<void> {
  const { lock, distributionDir, piVersion } = session.options;
  const resourceDir = join(distributionDir, "resources");
  const policy = session.manifest.policy;
  const certified = new Map(
    lock.governance.certified.map((entry) => [
      `${entry.kind}:${entry.path}`,
      entry,
    ]),
  );
  for (const item of session.manifest.resources.declared) {
    const record = await declaredResource(
      session,
      item,
      resourceDir,
      certified.get(`${item.kind}:${item.path}`),
      piVersion,
    );
    session.resources.push(record);
    if (!record.loaded) continue;
    const absolute = join(resourceDir, ...item.path.slice(2).split("/"));
    if (item.kind === "instructions")
      session.loader.instructions.push({
        path: absolute,
        content: readFileSync(absolute, "utf8"),
      });
    else session.loader[item.kind].push(absolute);
  }
  await packageResources(session);
  for (const name of session.manifest.resources.builtin) {
    const trust = resourceTrustDecision(policy, "builtin", "extensions");
    let loaded = trust.allowed;
    let reason = trust.reason;
    if (loaded) {
      const decision = await session.decide(
        "extension.load",
        `builtin:${name}`,
        session.startupChannel(),
      );
      loaded = decision.outcome === "allow";
      if (!loaded) reason = `policy ${decision.ruleId}`;
    }
    session.emit(loaded ? "resource.load" : "resource.denied", {
      resource: `builtin:${name}`,
      detail: { kind: "extensions", class: "builtin" },
    });
    if (loaded) session.loader.builtin.add(name);
    session.resources.push({
      kind: "extensions",
      class: "builtin",
      path: name,
      loaded,
      reason,
      integrity: "not-applicable",
    });
  }
}

/**
 * Files of the vendored Pi packages (spec §8.2): each locked resource enters
 * the loader on its own, after its package's trust class, its locked sha256,
 * and the policy decision for its kind. Pi never sees a package, so its
 * package manager installs nothing.
 */
/** The vendored root of a package: `pi-packages/<id>/{node_modules/<name>,package}`. */
export function packageRoot(
  distributionDir: string,
  manifest: GovernanceManifest,
  id: string,
): string {
  const declaration = manifest.resources.packages?.find(
    (item) => item.id === id,
  );
  return join(
    distributionDir,
    "pi-packages",
    id,
    ...(declaration?.source === "npm"
      ? ["node_modules", ...declaration.package.split("/")]
      : ["package"]),
  );
}

export function fileMatches(path: string, expected: string): boolean {
  return existsSync(path) && sha256(readFileSync(path)) === expected;
}

/**
 * The packages whose extensions are a capability provider: they load once the
 * provider's own decision has allowed it (`computeCapabilities`), not with
 * the package's other files.
 */
export function providerPackages(session: GovernanceSession): Set<string> {
  return new Set(
    session.options.lock.governance.providers.flatMap((item) =>
      item.package && item.class !== "builtin" ? [item.package] : [],
    ),
  );
}

async function packageResources(session: GovernanceSession): Promise<void> {
  const deferred = providerPackages(session);
  for (const entry of session.options.lock.packages ?? [])
    await loadPackageFiles(
      session,
      entry,
      (file) => !(deferred.has(entry.id) && file.kind === "extensions"),
    );
}

/** The files of one locked package that `include` selects, one decision each. */
export async function loadPackageFiles(
  session: GovernanceSession,
  entry: NonNullable<GovernanceSession["options"]["lock"]["packages"]>[number],
  include: (file: { readonly kind: PackageResourceKind }) => boolean,
): Promise<void> {
  const { distributionDir, piVersion } = session.options;
  const root = packageRoot(distributionDir, session.manifest, entry.id);
  const label = `${entry.id}@${entry.version ?? entry.commit ?? "local"}`;
  // A certified package carries evidence the lock was checked against;
  // like a certified resource, it loads only on the Pi versions and
  // platforms it was reviewed for.
  let incompatible: string | undefined;
  if (entry.class === "certified") {
    const evidence = session.manifest.resources.packages?.find(
      (item) => item.id === entry.id,
    )?.certified;
    if (
      !evidence ||
      (evidence.integrity !== entry.tree &&
        evidence.integrity !== entry.integrity)
    ) {
      session.metrics.recordLoadFailure("resource", "INTEGRITY_FAILED");
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `Certified package ${entry.id} does not match its reviewed evidence`,
        { userAction: "Re-lock and rebuild the distribution" },
      );
    }
    if (
      !evidence.pi.includes(piVersion) ||
      (evidence.platforms.length > 0 &&
        !evidence.platforms.includes(process.platform))
    )
      incompatible = `certified for Pi ${evidence.pi.join(", ")}${evidence.platforms.length ? ` on ${evidence.platforms.join(", ")}` : ""}; running Pi ${piVersion} on ${process.platform}`;
  }
  for (const file of entry.resources) {
    if (!include(file)) continue;
    const path = `packages/${entry.id}/${file.path}`;
    const resource = `${entry.class}:${path}`;
    const detail = { kind: file.kind, class: entry.class, package: label };
    const record = (loaded: boolean, reason: string) =>
      session.resources.push({
        kind: file.kind,
        class: entry.class,
        path,
        loaded,
        reason,
        integrity: loaded ? "verified" : "not-applicable",
        origin: label,
      });
    const trust = resourceTrustDecision(
      session.manifest.policy,
      entry.class,
      file.kind,
    );
    if (!trust.allowed) {
      session.emit("resource.denied", { resource, detail });
      record(false, trust.reason);
      continue;
    }
    const absolute = join(root, ...file.path.split("/"));
    if (!fileMatches(absolute, file.sha256)) {
      session.metrics.recordLoadFailure("resource", "INTEGRITY_FAILED");
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `Package ${entry.id} file ${file.path} does not match the lock`,
        { userAction: "Reinstall the distribution from a trusted artifact" },
      );
    }
    if (incompatible) {
      session.emit("resource.denied", { resource, detail });
      record(false, incompatible);
      continue;
    }
    const decision = await session.decide(
      KIND_ACTION[file.kind] ?? "resource.load",
      resource,
      session.startupChannel(),
    );
    if (decision.outcome !== "allow") {
      session.emit("resource.denied", { resource, detail });
      record(false, `policy ${decision.ruleId}`);
      continue;
    }
    session.emit("resource.load", {
      resource,
      policy: decision.policyId,
      rule: decision.ruleId,
      detail,
    });
    record(true, trust.reason);
    session.loader[file.kind].push(absolute);
  }
}

async function declaredResource(
  session: GovernanceSession,
  item: DeclaredResource,
  resourceDir: string,
  certified: GovernanceLock["certified"][number] | undefined,
  piVersion: string,
): Promise<ResourceEvidence> {
  const resource = `${item.class}:${item.path}`;
  const base = {
    kind: item.kind,
    class: item.class,
    path: item.path,
  } as const;
  const deny = (reason: string, extra: Partial<ResourceEvidence> = {}) => {
    session.emit("resource.denied", {
      resource,
      detail: { kind: item.kind, class: item.class },
    });
    return { ...base, loaded: false, reason, ...extra };
  };
  const trust = resourceTrustDecision(
    session.manifest.policy,
    item.class,
    item.kind,
  );
  if (!trust.allowed) return deny(trust.reason);
  let integrity: ResourceEvidence["integrity"] = "not-applicable";
  let compatible = true;
  if (item.class === "certified") {
    if (!certified) {
      session.metrics.recordLoadFailure("resource", "INTEGRITY_FAILED");
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `No certified evidence is locked for ${item.path}`,
        { userAction: "Re-lock and rebuild the distribution" },
      );
    }
    const found = payloadTree(resourceDir, item.path);
    if (found !== certified.integrity) {
      session.metrics.recordLoadFailure("resource", "INTEGRITY_FAILED");
      throw new PiShipError(
        "INTEGRITY_FAILED",
        `Certified resource ${item.path} does not match its reviewed integrity`,
        { userAction: "Reinstall the distribution from a trusted artifact" },
      );
    }
    integrity = "verified";
    const evidence = certified.evidence;
    compatible =
      evidence.pi.includes(piVersion) &&
      (evidence.platforms.length === 0 ||
        evidence.platforms.includes(process.platform));
    if (!compatible)
      return deny(
        `certified for Pi ${evidence.pi.join(", ")}${evidence.platforms.length ? ` on ${evidence.platforms.join(", ")}` : ""}; running Pi ${piVersion} on ${process.platform}`,
        { integrity, compatible },
      );
  }
  const decision = await session.decide(
    KIND_ACTION[item.kind] ?? "resource.load",
    resource,
    session.startupChannel(),
  );
  if (decision.outcome !== "allow")
    return deny(`policy ${decision.ruleId}`, { integrity, compatible });
  session.emit("resource.load", {
    resource,
    policy: decision.policyId,
    rule: decision.ruleId,
    detail: { kind: item.kind, class: item.class },
  });
  return {
    ...base,
    loaded: true,
    reason: trust.reason,
    integrity,
    compatible,
  };
}
