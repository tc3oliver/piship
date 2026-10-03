import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { checkVariableName, LATEST_SCHEMA } from "@piship/schema";
import { PI_VERSION } from "./compatibility.js";
import { distributionStateDirectory } from "./state-paths.js";

/**
 * Governance and lifecycle sections shared by both init templates: explicit
 * safe defaults for the deployment mode, and updates disabled until a source
 * and release keys are configured (as `piship migrate` writes them).
 */
function initGovernance(managed: boolean, id: string): string {
  // Workspace-provided items (.pi, .agents, AGENTS.md, .mcp.json) stay
  // unloaded outside trusted projects, as in the v0.1 personal alpha.
  const projectTrust = `  # Relax per dimension, or add company.match entries, to trust projects.
  projectTrust:
    external: &isolated
      passiveContext: deny
      instructions: deny
      skills: deny
      agents: deny
      hooks: deny
      extensions: deny
      mcp: deny
      providers: deny
    unknown: *isolated
`;
  const policy = managed
    ? `# Unmatched actions ask the person; headless runs resolve ask to deny.
policy:
  default: ask
${projectTrust}  defaults:
    - id: distribution.models
      action: model.use
      resource: "${id}/**"
      effect: allow
    - id: distribution.instructions
      action: instruction.load
      resource: "company:**"
      effect: allow
    - id: workspace.read
      action: filesystem.read
      resource: "workspace/**"
      effect: allow
`
    : `policy:
  default: allow
${projectTrust}`;
  return `${policy}# No MCP servers until they are declared and reviewed.
mcp:
  mode: ${managed ? "allowlist" : "off"}
# Set required: true to fail the launch when the OS sandbox is unavailable.
sandbox:
  required: false
audit:
${
  managed
    ? `  enabled: true
  sinks:
    - id: local
      type: file
      required: false
`
    : `  enabled: false
`
}# Updates stay disabled until updates.source and updates.trust.bootstrap are set.
updates:
  channel: stable
  channels: [stable]
  rollback: true
`;
}
export function initDistribution(
  directory: string,
  options: { managed?: boolean } = {},
): string {
  const root = resolve(directory);
  if (existsSync(root) && readdirSync(root).length)
    throw new Error(`Directory is not empty: ${root}`);
  const id = basename(root).toLowerCase();
  distributionStateDirectory({ value: id });
  mkdirSync(join(root, "resources"), { recursive: true });
  const header = `schema: ${LATEST_SCHEMA}
app:
  id: ${id}
  name: ${id}
  command: ${id}
  version: 1.0.0
runtime:
  pi: "${PI_VERSION}"
`;
  if (options.managed) {
    const candidate = id.toUpperCase().replaceAll("-", "_");
    // Variable names that look like secret material are rejected by the schema.
    const prefix = checkVariableName(`${candidate}_OIDC_ISSUER`)
      ? "DISTRIBUTION"
      : candidate;
    writeFileSync(
      join(root, "piship.yaml"),
      `${header}deployment:
  mode: managed
variables:
  - ${prefix}_OIDC_ISSUER
  - ${prefix}_OIDC_CLIENT_ID
  - ${prefix}_CREDENTIAL_BROKER_URL
  - ${prefix}_LLM_GATEWAY_URL
identity:
  mode: oidc
  oidc:
    issuer: \${${prefix}_OIDC_ISSUER}
    clientId: \${${prefix}_OIDC_CLIENT_ID}
    flow: authorization_code_pkce
    scopes: [openid, profile, email]
    redirectUri: http://127.0.0.1:8765/callback
credential:
  provider: http-broker
  broker:
    endpoint: \${${prefix}_CREDENTIAL_BROKER_URL}
  storage:
    provider: system
  refresh:
    beforeExpiry: 5m
inference:
  provider: openai-compatible
  baseUrl: \${${prefix}_LLM_GATEWAY_URL}
models:
  default: example/coder
  allowed:
    - example/coder
  catalog:
    example/coder:
      name: Example Coder
      contextWindow: 128000
      maxOutputTokens: 8192
      tools: true
network:
  publicFallback: deny
resources:
  instructions:
    company:
      - ./resources/AGENTS.md
${initGovernance(true, id)}`,
    );
  } else
    writeFileSync(
      join(root, "piship.yaml"),
      `${header}deployment:
  mode: personal
# Pi-native providers and auth, kept in this distribution's isolated state.
identity:
  mode: none
credential:
  provider: pi-native
inference:
  provider: pi-native
resources:
  instructions:
    user:
      - ./resources/AGENTS.md
${initGovernance(false, id)}`,
    );
  writeFileSync(join(root, "resources", "AGENTS.md"), `# ${id}\n`);
  return join(root, "piship.yaml");
}
