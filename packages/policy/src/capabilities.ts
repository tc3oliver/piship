// Capability state: six independent axes per capability. An axis is
// computed from its own evidence only, so combinations such as
// `compatible: no` with `healthy: yes` stay representable.
import { redact } from "@piship/contracts";
import {
  BUILTIN_PROVIDERS,
  CAPABILITY_CONTRACTS,
  SUPPORTED_CAPABILITY_CONTRACTS,
  type CapabilityConfig,
  type CapabilityName,
  type CapabilityProviderRef,
  type PolicyConfig,
} from "@piship/schema";
import {
  modelRequirementGaps,
  type ModelEvidence,
} from "./model-requirements.js";
import { providerTrustDecision, type ProviderTrustDecision } from "./trust.js";

export type AxisValue = "yes" | "no" | "n/a";

export const CAPABILITY_AXES = [
  "supported",
  "resolved",
  "enabled",
  "compatible",
  "healthy",
  "effective",
] as const;
export type CapabilityAxis = (typeof CAPABILITY_AXES)[number];

export interface AxisState {
  readonly value: AxisValue;
  /** Present for every `no` and `n/a`. */
  readonly reason?: string;
}

export interface CapabilityState {
  readonly name: CapabilityName;
  readonly contract: string;
  readonly provider?: string;
  readonly axes: Readonly<Record<CapabilityAxis, AxisState>>;
}

export interface VerificationResult {
  readonly ok: boolean;
  readonly reason?: string;
}

export interface CapabilityStateInput {
  readonly capabilities: readonly CapabilityConfig[];
  /** Provider trust by provider id; computed from `policy` when absent. */
  readonly providerTrust?: Readonly<Record<string, ProviderTrustDecision>>;
  readonly policy?: Pick<PolicyConfig, "providerTrust">;
  /** Integrity/verification results by provider id (builtin providers need none). */
  readonly verification?: Readonly<Record<string, VerificationResult>>;
  /** Reviewed compatibility evidence from the resolved provider lock. */
  readonly providerCertification?: Readonly<
    Record<string, NonNullable<CapabilityProviderRef["certified"]>>
  >;
  readonly piVersion: string;
  readonly platform: string;
  /** Contracts implemented by this release (default SUPPORTED_CAPABILITY_CONTRACTS). */
  readonly supportedContracts?: readonly string[];
  /** Runtime health by capability; absent means not checked. */
  readonly health?: Readonly<
    Partial<Record<CapabilityName, VerificationResult>>
  >;
  /**
   * Capabilities whose provider the policy refused to load, with the reason.
   * A policy refusal is reported on the `enabled` axis, not as ill health.
   */
  readonly policyDenied?: Readonly<Partial<Record<CapabilityName, string>>>;
  /**
   * The selected model that enabled capabilities' `requirements` are checked
   * against, with the comparison launch uses. Absent: no model is known, which,
   * like unknown metadata, meets no requirement.
   */
  readonly model?: ModelEvidence;
}

interface ContractId {
  readonly name: string;
  readonly major: number;
}

export function parseContract(contract: string): ContractId | undefined {
  const match = /^(.+)\/v(\d+)$/.exec(contract);
  if (!match?.[1] || match[2] === undefined) return undefined;
  return { name: match[1], major: Number(match[2]) };
}

/** Same contract name and major version. */
export function contractsCompatible(a: string, b: string): boolean {
  const left = parseContract(a);
  const right = parseContract(b);
  return (
    left !== undefined &&
    right !== undefined &&
    left.name === right.name &&
    left.major === right.major
  );
}

const yes: AxisState = { value: "yes" };
const no = (reason: string): AxisState => ({
  value: "no",
  reason: redact(reason),
});
const na = (reason: string): AxisState => ({ value: "n/a", reason });

function supportedAxis(
  contract: string,
  supported: readonly string[],
): AxisState {
  if (supported.includes(contract)) return yes;
  if (supported.some((item) => contractsCompatible(item, contract))) return yes;
  const sameName = supported.find(
    (item) => parseContract(item)?.name === parseContract(contract)?.name,
  );
  return no(
    sameName
      ? `Contract ${contract} has an unsupported major version (this release implements ${sameName})`
      : `Contract ${contract} is not implemented in this release`,
  );
}

function enabledAxis(
  name: CapabilityName,
  config: CapabilityConfig | undefined,
  input: CapabilityStateInput,
): AxisState {
  if (!config) return no("Not declared in the manifest");
  if (!config.enabled) return no("Disabled in the manifest");
  const denied = input.policyDenied?.[name];
  return denied === undefined
    ? yes
    : no(`The policy does not allow its provider: ${denied}`);
}

function implementsContract(
  provider: CapabilityProviderRef,
  contract: string,
): boolean {
  const declared =
    provider.class === "builtin"
      ? (BUILTIN_PROVIDERS[provider.id] ?? [])
      : provider.implements;
  return declared.some(
    (item) => parseContract(item)?.name === parseContract(contract)?.name,
  );
}

function resolvedAxis(
  config: CapabilityConfig | undefined,
  contract: string,
  input: CapabilityStateInput,
): AxisState {
  const provider = config?.provider;
  if (!provider)
    return config?.enabled
      ? no("No provider is selected")
      : na("No provider is selected");
  if (provider.class === "builtin" && !BUILTIN_PROVIDERS[provider.id])
    return no(`Unknown builtin provider ${provider.id}`);
  if (!implementsContract(provider, contract))
    return no(`Provider ${provider.id} does not implement ${contract}`);
  const trust =
    input.providerTrust?.[provider.id] ??
    (input.policy
      ? providerTrustDecision(input.policy, provider.class)
      : undefined);
  if (!trust) return no(`No trust decision for provider ${provider.id}`);
  if (!trust.allowed) return no(trust.reason);
  if (provider.class === "builtin") return yes;
  const verification = input.verification?.[provider.id];
  if (!verification)
    return no(`Integrity of provider ${provider.id} is not verified`);
  if (!verification.ok)
    return no(
      verification.reason ??
        `Integrity verification failed for provider ${provider.id}`,
    );
  return yes;
}

function compatibleAxis(
  config: CapabilityConfig | undefined,
  contract: string,
  input: CapabilityStateInput,
): AxisState {
  // The same comparison as the launch check, so the report and launch agree.
  if (config?.enabled && config.requirements) {
    const gaps = modelRequirementGaps(
      input.model?.metadata,
      config.requirements,
    );
    if (gaps.length)
      return no(
        `Model ${input.model?.id ?? "(unknown)"} does not meet the model requirements: ${gaps.join("; ")}`,
      );
  }
  const provider = config?.provider;
  if (!provider) return na("No provider is selected");
  const declared =
    provider.class === "builtin"
      ? (BUILTIN_PROVIDERS[provider.id] ?? [])
      : provider.implements;
  const sameName = declared.filter(
    (item) => parseContract(item)?.name === parseContract(contract)?.name,
  );
  if (
    sameName.length > 0 &&
    !sameName.some((item) => contractsCompatible(item, contract))
  )
    return no(
      `Provider ${provider.id} implements ${sameName.join(", ")}, not major version of ${contract}`,
    );
  const evidence =
    input.providerCertification?.[provider.id] ?? provider.certified;
  if (evidence) {
    if (!evidence.pi.includes(input.piVersion))
      return no(
        `Provider ${provider.id} was reviewed for Pi ${evidence.pi.join(", ")}, not ${input.piVersion}`,
      );
    if (
      evidence.platforms.length > 0 &&
      !evidence.platforms.includes(input.platform)
    )
      return no(
        `Provider ${provider.id} does not support platform ${input.platform}`,
      );
  }
  return yes;
}

function healthyAxis(
  name: CapabilityName,
  input: CapabilityStateInput,
): AxisState {
  const result = input.health?.[name];
  if (!result) return na("No runtime health check was run");
  return result.ok ? yes : no(result.reason ?? "Runtime health check failed");
}

function effectiveAxis(
  axes: Omit<Record<CapabilityAxis, AxisState>, "effective">,
): AxisState {
  for (const axis of [
    "supported",
    "resolved",
    "enabled",
    "compatible",
  ] as const)
    if (axes[axis].value !== "yes")
      return no(`${axis}: ${axes[axis].reason ?? axes[axis].value}`);
  if (axes.healthy.value === "no")
    return no(`healthy: ${axes.healthy.reason ?? "no"}`);
  return yes;
}

/** Compute the six axes for every known capability contract. */
export function computeCapabilityStates(
  input: CapabilityStateInput,
): CapabilityState[] {
  const supported = input.supportedContracts ?? SUPPORTED_CAPABILITY_CONTRACTS;
  return (Object.keys(CAPABILITY_CONTRACTS) as CapabilityName[]).map((name) => {
    const contract = CAPABILITY_CONTRACTS[name];
    const config = input.capabilities.find((item) => item.name === name);
    const axes = {
      supported: supportedAxis(contract, supported),
      resolved: resolvedAxis(config, contract, input),
      enabled: enabledAxis(name, config, input),
      compatible: compatibleAxis(config, contract, input),
      healthy: healthyAxis(name, input),
    };
    return {
      name,
      contract,
      ...(config?.provider ? { provider: config.provider.id } : {}),
      axes: { ...axes, effective: effectiveAxis(axes) },
    };
  });
}

function pad(text: string, width: number): string {
  return text.length >= width ? text : text + " ".repeat(width - text.length);
}

/** Render the capability table with one reason line per `no`. */
export function formatCapabilities(states: readonly CapabilityState[]): string {
  const headers = [
    "CAPABILITY",
    "PROVIDER",
    ...CAPABILITY_AXES.map((a) => a.toUpperCase()),
  ];
  const rows = states.map((state) => [
    state.name,
    state.provider ?? "-",
    ...CAPABILITY_AXES.map((axis) => state.axes[axis].value),
  ]);
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => (row[index] ?? "").length)),
  );
  const line = (cells: readonly string[]) =>
    cells
      .map((cell, index) => pad(cell, widths[index] ?? 0))
      .join("  ")
      .trimEnd();
  const out = [line(headers), ...rows.map(line)];
  const reasons: string[] = [];
  for (const state of states)
    for (const axis of CAPABILITY_AXES) {
      const value = state.axes[axis];
      if (value.value === "no" && axis !== "effective")
        reasons.push(
          `  ${state.name} ${axis}: ${redact(value.reason ?? "no")}`,
        );
    }
  if (reasons.length > 0) out.push("", "Reasons:", ...reasons);
  return out.join("\n");
}
