// Probes a built developer distribution (examples/developer) with the Pi it
// vendors, without a model. Run with the workspace as the working directory:
//
//   node developer-probe.mjs permissions <payload> <agentDir> <cases.json>
//   node developer-probe.mjs claude <payload> <agentDir>
//
// Both build a Pi SDK session from the payload's own files (the same
// extension files the launcher hands to Pi, the same agent directory), so they
// show what the vendored packages do, not what PiShip's launcher does around
// them. They print one JSON document.
//
// permissions: loads only the permission provider, with the configuration the
//   launcher seeded in <agentDir>, and emits a tool_call for each case
//   ([toolName, input] pairs; a tool the provider does not know is registered
//   as a stand-in). Reports whether the provider allowed it, asked (there is no
//   UI here, so an ask is "confirmation unavailable"), or denied it.
// claude: loads pi-code and reports what it read from the workspace's Claude
//   Code configuration.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [mode, payload, agentDir, casesFile] = process.argv.slice(2);
const workspace = process.cwd();
process.env.PI_CODING_AGENT_DIR = agentDir;
const pi = await import(
  pathToFileURL(
    join(
      payload,
      "node_modules",
      "@earendil-works",
      "pi-coding-agent",
      "dist",
      "index.js",
    ),
  ).href
);
const lock = JSON.parse(readFileSync(join(payload, "piship.lock"), "utf8"));

/** The extension files of a vendored package, as the lock inventories them. */
function packageExtensions(id) {
  const item = lock.packages.find((entry) => entry.id === id);
  const declared = lock.governance.manifest.resources.packages.find(
    (entry) => entry.id === id,
  );
  const root = join(
    payload,
    "pi-packages",
    id,
    "node_modules",
    ...declared.package.split("/"),
  );
  return item.resources
    .filter((resource) => resource.kind === "extensions")
    .map((resource) => join(root, ...resource.path.split("/")));
}

async function session(options) {
  const settingsManager = pi.SettingsManager.inMemory({
    retry: { enabled: false },
  });
  const resourceLoader = new pi.DefaultResourceLoader({
    cwd: workspace,
    agentDir,
    settingsManager,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
    ...options,
  });
  await resourceLoader.reload();
  const errors = resourceLoader.getExtensions().errors;
  if (errors.length) throw new Error(JSON.stringify(errors));
  const { session: created } = await pi.createAgentSession({
    cwd: workspace,
    agentDir,
    settingsManager,
    sessionManager: pi.SessionManager.inMemory(workspace),
    resourceLoader,
  });
  await created.bindExtensions({});
  return { session: created, resourceLoader };
}

if (mode === "permissions") {
  const cases = JSON.parse(readFileSync(casesFile, "utf8"));
  const real = new Set(["bash", "read", "write", "edit", "grep", "find", "ls"]);
  const standIns = [
    ...new Set(cases.map((item) => item[0]).filter((name) => !real.has(name))),
  ];
  const eventBus = pi.createEventBus();
  const decisions = [];
  eventBus.on("permissions:decision", (event) => decisions.push(event));
  const { session: probed } = await session({
    additionalExtensionPaths: packageExtensions("pi-permission-system"),
    extensionFactories: [
      {
        name: "stand-in-tools",
        factory: (api) => {
          for (const name of standIns)
            api.registerTool({
              name,
              label: name,
              description: name,
              parameters: {
                type: "object",
                properties: {},
                additionalProperties: true,
              },
              execute: async () => ({
                content: [{ type: "text", text: "ok" }],
              }),
            });
        },
      },
    ],
    eventBus,
  });
  const results = [];
  let id = 0;
  for (const [toolName, input] of cases) {
    decisions.length = 0;
    const outcome = await probed.extensionRunner.emitToolCall({
      type: "tool_call",
      toolCallId: `probe-${++id}`,
      toolName,
      input,
    });
    const last = decisions.at(-1);
    results.push({
      toolName,
      input,
      verdict: !outcome?.block
        ? "allow"
        : last?.resolution === "confirmation_unavailable"
          ? "ask"
          : "deny",
      reason: outcome?.reason ?? null,
    });
  }
  console.log(JSON.stringify(results));
} else if (mode === "claude") {
  const root = workspace;
  const { session: probed, resourceLoader } = await session({
    additionalExtensionPaths: packageExtensions("pi-code"),
    // PiShip hands the project's root CLAUDE.md to Pi's loader as an instruction.
    agentsFilesOverride: () => ({
      agentsFiles: existsSync(join(root, "CLAUDE.md"))
        ? [
            {
              path: join(root, "CLAUDE.md"),
              content: readFileSync(join(root, "CLAUDE.md"), "utf8"),
            },
          ]
        : [],
    }),
  });
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const runner = probed.extensionRunner;
  const start = JSON.stringify(
    await runner.emitBeforeAgentStart("hello", undefined, {
      cwd: root,
      contextFiles: resourceLoader.getAgentsFiles().agentsFiles,
      customPrompt: undefined,
      selectedTools: [],
      toolSnippets: {},
      promptGuidelines: [],
    }),
  );
  const scoped = JSON.stringify(
    await runner.emitToolResult({
      type: "tool_result",
      toolCallId: "probe-rule",
      toolName: "read",
      input: { path: "src/example.ts" },
      content: [{ type: "text", text: "export const example = 1;" }],
      details: undefined,
      isError: false,
    }),
  );
  console.log(
    JSON.stringify({
      commands: runner
        .getRegisteredCommands()
        .map((item) => item.invocationName),
      skills: resourceLoader.getSkills().skills.map((item) => item.name),
      // In the prompt: CLAUDE.md, its @import, a rule without paths, the agents.
      prompt: start,
      // Appended to the result of a read: the rule scoped to src/**/*.ts.
      scopedRule: scoped,
      hookMarker: existsSync(join(root, ".fixture-hook-ran"))
        ? readFileSync(join(root, ".fixture-hook-ran"), "utf8").trim()
        : null,
    }),
  );
} else if (mode === "browser") {
  // pi-browser-use starts chrome-devtools-mcp and a headless Chrome at
  // session_start and registers its tools then.
  const { session: probed } = await session({
    additionalExtensionPaths: packageExtensions("pi-browser-use"),
  });
  const registered = () =>
    probed
      .getAllTools()
      .map((item) => item.name)
      .filter((name) => name.startsWith("browser_"));
  for (let wait = 0; wait < 30 && registered().length === 0; wait += 1)
    await new Promise((resolve) => setTimeout(resolve, 500));
  const tools = registered();
  try {
    // Stops the browser it started.
    await probed.extensionRunner.emit({
      type: "session_shutdown",
      reason: "quit",
    });
  } catch {
    // The tools are what is reported.
  }
  console.log(JSON.stringify({ node: process.version, tools }));
} else throw new Error(`unknown mode ${mode}`);
process.exit(0);
