import type { Collector } from "../collector.js";
import type { AnyLock } from "../types.js";

export function distribution(out: Collector, b: AnyLock, a: AnyLock): void {
  out.scalar("distribution", "id", b.app?.id, a.app?.id, [
    "high",
    "Different distribution; compare releases of one distribution only.",
  ]);
  out.scalar("distribution", "version", b.app?.version, a.app?.version, [
    "low",
    "Release version change.",
  ]);
  out.scalar("distribution", "command", b.app?.command, a.app?.command, [
    "medium",
    "Users launch the distribution under a different command.",
  ]);
  out.scalar("distribution", "name", b.app?.name, a.app?.name, [
    "low",
    "Display name change.",
  ]);
  out.scalar("distribution", "banner", b.app?.banner, a.app?.banner, [
    "low",
    "Display banner change.",
  ]);
  out.scalar("distribution", "theme", b.app?.theme, a.app?.theme, [
    "low",
    "Default theme change.",
  ]);
  out.scalar(
    "distribution",
    "deployment mode",
    b.deployment?.mode,
    a.deployment?.mode,
    ["high", "Deployment mode changes which controls are enforced."],
  );
  out.scalar(
    "schema",
    "manifest schema",
    b.manifest?.schema,
    a.manifest?.schema,
    ["medium", "Manifest schema changed; requires migration review."],
  );
  out.scalar("schema", "lock schema", b.schema, a.schema, [
    "medium",
    "Lock schema changed; requires migration review.",
  ]);
  out.scalar("pi", "Pi runtime", b.runtime?.version, a.runtime?.version, [
    "high",
    "Pi runtime changed; extension, tool, and session behavior may differ.",
  ]);
  out.scalar(
    "piship",
    "PiShip version",
    b.runtime?.pishipVersion,
    a.runtime?.pishipVersion,
    ["medium", "PiShip runtime changed; launch and governance code differ."],
  );
}
