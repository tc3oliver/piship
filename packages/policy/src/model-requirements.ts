// Capability model requirements against a model's verified metadata. The one
// comparison behind both the launch check (MODEL_INCOMPATIBLE) and the
// `compatible` axis of the capability report.
import type { ModelDefinition } from "@piship/contracts";
import type {
  CapabilityConfig,
  CapabilityModelRequirements,
} from "@piship/schema";

/** The model a capability report checks requirements against. */
export interface ModelEvidence {
  /** Model ID as the report shows it. */
  readonly id: string;
  /** Verified metadata; absent means unknown, which meets no requirement. */
  readonly metadata?: ModelDefinition;
}

export interface ModelIncompatibility {
  readonly capability: string;
  readonly reasons: readonly string[];
}

/**
 * Compare a model's verified metadata with one capability's requirements.
 * Unknown metadata never satisfies a requirement.
 */
export function modelRequirementGaps(
  model: ModelDefinition | undefined,
  requirements: CapabilityModelRequirements,
): string[] {
  const capabilities = model?.capabilities;
  const gaps: string[] = [];
  const flag = (
    required: boolean | undefined,
    value: boolean | undefined,
    what: string,
  ) => {
    if (!required || value === true) return;
    gaps.push(
      value === false
        ? `${what} is not supported`
        : `${what} support is unknown`,
    );
  };
  flag(requirements.tools, capabilities?.tools, "tool calling");
  flag(
    requirements.structuredOutput,
    capabilities?.structuredOutput,
    "structured output",
  );
  if (requirements.minContextWindow !== undefined) {
    const window = capabilities?.contextWindow;
    if (window === undefined) gaps.push("the context window is unknown");
    else if (window < requirements.minContextWindow)
      gaps.push(
        `the context window ${window} is below the required ${requirements.minContextWindow}`,
      );
  }
  for (const input of requirements.input ?? []) {
    if (!capabilities?.input) {
      gaps.push("the accepted input types are unknown");
      break;
    }
    if (!capabilities.input.includes(input))
      gaps.push(`${input} input is not accepted`);
  }
  return gaps;
}

/** Enabled capabilities whose model requirements the model does not meet. */
export function incompatibleCapabilities(
  model: ModelDefinition | undefined,
  capabilities: readonly CapabilityConfig[],
): ModelIncompatibility[] {
  return capabilities
    .filter((item) => item.enabled && item.requirements)
    .map((item) => ({
      capability: item.name,
      reasons: modelRequirementGaps(
        model,
        item.requirements as CapabilityModelRequirements,
      ),
    }))
    .filter((item) => item.reasons.length > 0);
}
