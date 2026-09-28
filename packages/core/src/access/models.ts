import { PiShipError } from "@piship/contracts";
import { buildModelDefinitions } from "@piship/inference";
import type { ModelEvidence, ModelIncompatibility } from "@piship/policy";
import { readPreferences, resolveEffectiveConfig } from "../config.js";
import { accessStatePaths } from "./state.js";
import type { AccessOptions } from "./types.js";

/**
 * The model launch would select, with its manifest catalog metadata, read
 * without contacting an identity provider, broker, or gateway. Offline reports
 * (`capabilities`, `doctor`) check capability requirements against it with the
 * same comparison launch uses; `--model` or a credential entitlement can still
 * change what launch selects.
 */
export function configuredModel(
  options: Pick<AccessOptions, "app" | "access" | "stateDir">,
): ModelEvidence {
  const access = options.access;
  const config = resolveEffectiveConfig(
    access,
    options.app.theme,
    readPreferences(accessStatePaths(options.stateDir).preferences),
  );
  const id = config.values.model;
  // Pi-native inference: Pi owns the catalog and PiShip has no verified metadata.
  if (!access || access.inference.provider === "pi-native")
    return { id: id ?? "(selected by Pi)" };
  if (!id) return { id: "(no default model)" };
  const [metadata] = buildModelDefinitions(
    options.app.id,
    access.models.catalog.filter((entry) => entry.id === id),
    { allowed: [id] },
  );
  return { id: `${options.app.id}/${id}`, ...(metadata ? { metadata } : {}) };
}

export function modelIncompatible(
  model: string,
  gaps: readonly ModelIncompatibility[],
  compatible: readonly string[],
): PiShipError {
  return new PiShipError(
    "MODEL_INCOMPATIBLE",
    `Model ${model} does not meet the model requirements of ${gaps
      .map((gap) => `capability ${gap.capability} (${gap.reasons.join("; ")})`)
      .join(", ")}`,
    {
      component: "inference",
      retryable: false,
      userAction: compatible.length
        ? `Choose a compatible model with --model: ${compatible.join(", ")}`
        : `No allowed model meets these requirements; ask the distribution owner to update the model catalog or capabilities.${gaps[0]?.capability ?? "<name>"}.requirements`,
      sanitizedDetail: {
        model,
        capabilities: gaps.map((gap) => ({
          capability: gap.capability,
          reasons: [...gap.reasons],
        })),
      },
    },
  );
}
