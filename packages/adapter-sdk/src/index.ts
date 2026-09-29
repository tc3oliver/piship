// The supported surface for writing PiShip adapters. Everything here is a
// curated re-export of a public PiShip package or a thin wrapper around one;
// an adapter imports nothing else from PiShip.

/** The adapter kinds a distribution can supply, and the conformance kits cover. */
export const ADAPTER_KINDS = [
  "identity",
  "credential",
  "sandbox",
  "audit-sink",
] as const;
export type AdapterKind = (typeof ADAPTER_KINDS)[number];

export type { AdapterContext, ResolvedEndpoints } from "@piship/contracts";
export type { CustomBackendContext, SandboxBackend } from "@piship/sandbox";
