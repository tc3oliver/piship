// Conformance kits for PiShip adapters. A kit imports only
// @piship/adapter-sdk, so a company can test its adapter without PiShip
// internals. Each kit lives in its own file and is exported here; this
// module holds the report shape they share.
import type { AdapterKind } from "@piship/adapter-sdk";

/** A behavior the kit could not exercise, such as one that needs a harness hook, is `skipped`. */
export type ConformanceStatus = "passed" | "failed" | "skipped";

export interface ConformanceResult {
  /** The behavior checked, such as `refresh` or `environment filtering`. */
  readonly behavior: string;
  readonly status: ConformanceStatus;
  /** Why the behavior failed or was skipped. Never holds a secret. */
  readonly reason?: string;
}

export interface ConformanceReport {
  readonly kind: AdapterKind;
  readonly results: readonly ConformanceResult[];
}
export * from "./audit.js";
export * from "./credential.js";
