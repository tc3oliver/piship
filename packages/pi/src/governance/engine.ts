// Policy engine construction: distribution, team, project, and user rules,
// the project the session runs in, and the sandbox configuration.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { PiShipError, redact } from "@piship/contracts";
import {
  type ProjectIdentity,
  type ProjectResourceCandidate,
  PolicyEngine,
  discoverProjectResources,
  identifyProject,
  parseRuleList,
  projectGitControlDirectories,
  projectGitControlFiles,
  projectGitControlLinks,
  projectGitControlUnverified,
  readProjectRestrictions,
} from "@piship/policy";
import { type ContainmentReport, enforcesPathPolicy } from "@piship/sandbox";
import type { PolicyRule } from "@piship/schema";
import type { GovernanceOptions } from "./options.js";

/** The user's `config/policy.json`; an invalid file names itself. */
export function readUserRules(stateDir: string): PolicyRule[] {
  const path = join(stateDir, "config", "policy.json");
  if (!existsSync(path)) return [];
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new PiShipError(
      "CONFIG_INVALID",
      "The user policy file is not valid JSON",
      { userAction: `Fix or remove ${path}` },
    );
  }
  try {
    return [
      ...parseRuleList(value, path, {
        narrowingOnly: false,
        layer: "user-preference",
      }).rules,
    ];
  } catch (error) {
    if (!(error instanceof PiShipError)) throw error;
    throw new PiShipError(error.code, error.message, {
      component: "policy",
      userAction: `Fix or remove the rule in ${path}; the distribution's own policy is not affected`,
    });
  }
}

async function readTeamRules(
  distributionDir: string,
  adapter: string | undefined,
): Promise<PolicyRule[]> {
  if (!adapter) return [];
  const path = join(
    distributionDir,
    "resources",
    ...adapter.slice(2).split("/"),
  );
  let exported: unknown;
  try {
    const module = (await import(pathToFileURL(path).href)) as {
      default?: unknown;
      rules?: unknown;
    };
    const source = module.rules ?? module.default;
    exported = typeof source === "function" ? await source() : source;
  } catch (error) {
    // A required policy that cannot load fails closed.
    throw new PiShipError(
      "CONFIG_UNAVAILABLE",
      `The policy adapter could not be loaded: ${redact(String((error as Error)?.message ?? error))}`,
      { component: "policy" },
    );
  }
  return withIgnored(
    parseRuleList(exported, `the policy adapter ${adapter}`, {
      narrowingOnly: true,
      layer: "team-project",
    }),
  );
}

/** Keep ignored allow rules so the engine reports them in explain and doctor. */
function withIgnored(parsed: {
  readonly rules: readonly PolicyRule[];
  readonly ignored: readonly { readonly rule: PolicyRule }[];
}): PolicyRule[] {
  return [...parsed.rules, ...parsed.ignored.map((item) => item.rule)];
}

export function discoverProject(options: GovernanceOptions, homeDir: string) {
  const manifest = options.lock.governance.manifest;
  const project = identifyProject(options.cwd, manifest.policy.projectTrust, {
    homeDir,
  });
  const candidates = discoverProjectResources(project, manifest.policy, {
    homeDir,
  });
  return { project, candidates };
}

export function sandboxConfig(options: GovernanceOptions) {
  const sandbox = options.lock.governance.manifest.sandbox;
  return {
    ...sandbox,
    filesystem: {
      ...sandbox.filesystem,
      read: { deny: [...sandbox.filesystem.read.deny, options.stateDir] },
    },
  };
}

/**
 * The git files that classify the project and the git trees that run
 * outside the sandbox (hooks) stay read-only for tool subprocesses. A `.git`
 * directory itself stays writable so git keeps working inside the sandbox.
 * The list also holds the user's and the machine's own git config wherever it
 * lies (`~/.gitconfig`, `/etc/gitconfig`, and what they include): a sandbox
 * that may write the directory holding one must not plant a hooks path in it.
 * PiShip's file tools do not refuse those files (`builtinDenial`), so the
 * user's git configuration stays editable by the agent's edit tool.
 * `links` are the symbolic links on the way to those paths, which the sandbox
 * cannot hold in place.
 */
export function gitProtection(root: string): {
  files: string[];
  directories: string[];
  links?: string[];
  unverified?: string;
} {
  const isDirectory = (path: string) => {
    try {
      return statSync(path).isDirectory();
    } catch {
      return false;
    }
  };
  const unverified = projectGitControlUnverified(root);
  const links = projectGitControlLinks(root);
  return {
    files: projectGitControlFiles(root, { scope: "sandbox" }).filter(
      (path) => !isDirectory(path),
    ),
    directories: projectGitControlDirectories(root),
    ...(links.length ? { links } : {}),
    ...(unverified === undefined ? {} : { unverified }),
  };
}

/**
 * What the sandbox contains, as the policy engine reports planes. Filesystem
 * actions count as sandbox-enforced only when the backend enforces PiShip's
 * whole path policy (both path planes); one plane alone, or a remote
 * backend's host isolation, does not count.
 */
export function policyContainment(report: ContainmentReport) {
  const enforced = report.level === "enforced";
  return {
    filesystem: enforced && enforcesPathPolicy(report.planes),
    network: enforced && report.planes.includes("network-deny"),
    shell: enforced,
  };
}

export async function buildEngine(
  options: GovernanceOptions,
  project: ProjectIdentity,
  candidates: readonly ProjectResourceCandidate[],
  report: ContainmentReport,
  tmpDir: string,
  homeDir: string,
): Promise<PolicyEngine> {
  const manifest = options.lock.governance.manifest;
  const projectRules = readProjectRestrictions(candidates);
  return new PolicyEngine({
    policy: manifest.policy,
    teamRules: await readTeamRules(
      options.distributionDir,
      manifest.policy.adapter,
    ),
    projectRules: withIgnored(projectRules),
    // The engine reports ignored rules itself; this keeps the rest (a
    // restriction file that could not be read).
    diagnostics: projectRules.diagnostics.filter(
      (item) => item.ruleId === undefined,
    ),
    userRules: readUserRules(options.stateDir),
    // Managed: the distribution owns the policy, so user rules only narrow.
    userRuleMode:
      options.lock.deployment.mode === "managed"
        ? "narrowing"
        : "replace-default",
    context: {
      workspaceRoot: project.root,
      homeDir,
      tmpDir,
      containment: policyContainment(report),
    },
  });
}
