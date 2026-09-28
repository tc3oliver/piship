// Declared and builtin resources of a governed session: trust, certified
// integrity, and the policy decision for each before it loads.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { PiShipError } from "@piship/contracts";
import { type GovernanceLock, treeDigest } from "@piship/core";
import { resourceTrustDecision } from "@piship/policy";
import type { DeclaredResource } from "@piship/schema";
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
