import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { checkVariableName, LATEST_SCHEMA } from "@piship/schema";
import { pishipCommand } from "./invocation.js";
import { isDistributionId, suggestDistributionId } from "./state-paths.js";

/**
 * Governance and lifecycle sections shared by both init templates: explicit
 * safe defaults for the deployment mode, and updates disabled until a source
 * and release keys are configured (as `piship migrate` writes them).
 */
function initGovernance(managed: boolean, id: string): string {
  // Managed: workspace-provided items (.pi, .agents, AGENTS.md, .mcp.json)
  // stay unloaded outside trusted projects. Personal: the person's own
  // projects must work, so instructions and skills load (an unknown origin,
  // such as a repository with no remote, is asked once per launch) and
  // anything that starts code asks. Hooks, agents, and providers stay denied.
  const projectTrust = managed
    ? `  # Relax per dimension, or add company.match entries, to trust projects.
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
`
    : `  # Your own projects load their AGENTS.md and skills. Anything that starts
  # code (extensions, MCP servers) asks first, and hooks, agents, and
  # providers stay denied. \`ask\` is answered on the terminal before Pi
  # starts and resolves to deny for a headless run. Relax or tighten per
  # dimension; add company.match entries to trust a repository outright.
  projectTrust:
    external:
      passiveContext: allow
      instructions: allow
      skills: allow
      agents: deny
      hooks: deny
      extensions: ask
      mcp: ask
      providers: deny
    unknown:
      passiveContext: allow
      instructions: ask
      skills: ask
      agents: deny
      hooks: deny
      extensions: ask
      mcp: ask
      providers: deny
`;
  const policy = managed
    ? `# Unmatched actions ask the person; headless runs resolve ask to deny.
policy:
  default: ask
${projectTrust}  defaults:
    - id: distribution.models
      action: model.select
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
${
  managed
    ? `  # Governed MCP: only listed servers start, and only their allowed tools
  # are callable. Each also needs policy allow rules for mcp.server.start
  # (the server ID) and mcp.tool.call (<server>:<tool>).
  #   servers:
  #     docs:
  #       transport: streamable-http
  #       url: https://mcp.example.internal/docs
  #       tools:
  #         search: direct
  #         "*": hidden
`
    : ""
}# Set required: true to fail the launch when the OS sandbox is unavailable.
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
  # A company collector: list its variable under variables, and set
  # required: true to fail the launch when it is unreachable.
  #   - id: collector
  #     type: http
  #     url: \${AUDIT_COLLECTOR_URL}
  #     required: false
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
/**
 * Create a distribution repository from the personal template (the default)
 * or the managed one. `personal` and `managed` are mutually exclusive.
 */
export function initDistribution(
  directory: string,
  options: { personal?: boolean; managed?: boolean; id?: string } = {},
): string {
  if (options.personal && options.managed)
    throw new Error(
      "Choose one of --personal or --managed: a distribution is either personal or managed.",
    );
  const root = resolve(directory);
  if (existsSync(root) && readdirSync(root).length)
    throw new Error(`Directory is not empty: ${root}`);
  const id = options.id ?? basename(root).toLowerCase();
  if (!isDistributionId(id)) {
    const suggestion = suggestDistributionId(id);
    const quoted = JSON.stringify(id);
    throw new Error(
      options.id === undefined
        ? `The directory name ${quoted} is not a valid distribution id, which must start with a lowercase letter and contain only lowercase letters, digits and single hyphens. ${suggestion ? `Keep the directory and name the distribution: ${pishipCommand()} init ${directory} --id ${suggestion}` : `Name it with --id <id>`}`
        : `${quoted} is not a valid distribution id: it must start with a lowercase letter and contain only lowercase letters, digits and single hyphens.${suggestion ? ` Try --id ${suggestion}` : ""}`,
    );
  }
  mkdirSync(join(root, "resources"), { recursive: true });
  const header = `schema: ${LATEST_SCHEMA}
app:
  id: ${id}
  name: ${id}
  command: ${id}
  version: 1.0.0
# runtime.pi is left out on purpose: the build uses the Pi version this
# PiShip pins, so a PiShip upgrade does not break the manifest. State it
# ("runtime: {pi: ...}") only to refuse any other Pi.
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
# Company-specific endpoints are runtime variables: the lock never holds
# them, and each must be set in the environment that starts the command
# (piship validate lists them). Replace one with a fixed https URL to drop
# the variable, and remove it from this list.
#   ${prefix}_OIDC_ISSUER              OIDC issuer URL
#   ${prefix}_OIDC_CLIENT_ID           public OIDC client ID (PKCE, no secret)
#   ${prefix}_CREDENTIAL_BROKER_URL    credential broker endpoint
#   ${prefix}_CREDENTIAL_REVOKE_URL    credential broker revoke endpoint
#   ${prefix}_LLM_GATEWAY_URL          OpenAI-compatible LLM gateway base URL
# The contract each service must follow: docs/enterprise-integration.md.
variables:
  - ${prefix}_OIDC_ISSUER
  - ${prefix}_OIDC_CLIENT_ID
  - ${prefix}_CREDENTIAL_BROKER_URL
  - ${prefix}_CREDENTIAL_REVOKE_URL
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
    revokeEndpoint: \${${prefix}_CREDENTIAL_REVOKE_URL}
  storage:
    provider: system
  refresh:
    beforeExpiry: 5m
inference:
  provider: openai-compatible
  baseUrl: \${${prefix}_LLM_GATEWAY_URL}
  # openai-completions or openai-responses, whichever the gateway speaks.
  api: openai-completions
# The models people may use: replace example/coder with the gateway's model
# IDs. Every allowed ID needs a catalog entry.
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
  # HTTP(S)_PROXY and NO_PROXY from the launch environment.
  proxy:
    inheritEnvironment: true
  # A company CA bundle, an absolute path on each machine:
  #   tls:
  #     additionalCA: [/etc/ssl/certs/company-ca.pem]
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
      `${header}  # fd and rg ship in the payload, pinned and digest-checked. Without them
  # Pi downloads them on the first prompt and waits 24 to 30 seconds. \`piship
  # lock\` downloads them once per release target, so it needs network access
  # to github.com (listed under release.sources below).
  searchTools:
    mode: bundled
deployment:
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
${initGovernance(false, id)}release:
  sources: [https://registry.npmjs.org, https://github.com]
`,
    );
  writeFileSync(join(root, "resources", "AGENTS.md"), `# ${id}\n`);
  return join(root, "piship.yaml");
}
