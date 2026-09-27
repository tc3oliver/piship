/** Pi package integration lives here. Only the upstream public entrypoint is allowed. */
import type { createAgentSession } from "@earendil-works/pi-coding-agent";

export const PINNED_PI_VERSION = "0.87.1" as const;
export type PiVersion = typeof PINNED_PI_VERSION;
export type PiSessionFactory = typeof createAgentSession;
