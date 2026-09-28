// Reads PiShip's token-free enterprise context and exposes it as a tool.
// The context carries identity, model, and configuration decisions only;
// it never contains access tokens or runtime credentials.
const CONTEXT = Symbol.for("piship.enterprise-context/v1");

interface EnterpriseContext {
  readonly distribution: { readonly id: string; readonly mode: string };
  readonly identity: {
    readonly subject: string;
    readonly email?: string;
  } | null;
  readonly inference: {
    readonly selectedModel?: string;
    readonly models: readonly { readonly id: string }[];
  };
}

function current(): EnterpriseContext | undefined {
  return (globalThis as Record<symbol, unknown>)[CONTEXT] as
    | EnterpriseContext
    | undefined;
}

interface ToolApi {
  registerTool(tool: {
    name: string;
    label: string;
    description: string;
    parameters: unknown;
    execute(): Promise<{
      content: { type: "text"; text: string }[];
      details: unknown;
    }>;
  }): void;
}

export default function enterpriseContext(pi: ToolApi) {
  pi.registerTool({
    name: "demo_context",
    label: "Demo context",
    description:
      "Report the signed-in subject and the effective model chosen by the distribution.",
    parameters: { type: "object", properties: {}, additionalProperties: false },
    async execute() {
      const context = current();
      const summary = {
        distribution: context?.distribution.id ?? null,
        mode: context?.distribution.mode ?? null,
        subject: context?.identity?.subject ?? null,
        email: context?.identity?.email ?? null,
        selectedModel: context?.inference.selectedModel ?? null,
        allowedModels: context?.inference.models.map((model) => model.id) ?? [],
      };
      return {
        content: [{ type: "text", text: JSON.stringify(summary) }],
        details: summary,
      };
    },
  });
}
