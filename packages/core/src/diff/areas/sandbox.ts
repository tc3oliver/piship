import type { GovernanceManifest } from "@piship/schema";
import type { Collector } from "../collector.js";

export function sandbox(
  out: Collector,
  b: GovernanceManifest,
  a: GovernanceManifest,
): void {
  const x = b.sandbox;
  const y = a.sandbox;
  out.scalar("sandbox", "sandbox required", x?.required, y?.required, (_, r) =>
    r === "false"
      ? ["high", "Sandbox no longer fails closed when unavailable."]
      : ["medium", "Sandbox becomes required."],
  );
  out.scalar(
    "sandbox",
    "sandbox provider",
    x?.provider ?? "native",
    y?.provider ?? "native",
    () => ["high", "Commands run in a different sandbox backend."],
  );
  for (const field of [
    "adapter",
    "endpoint",
    "router",
    "namespace",
    "template",
    "workdir",
    "user",
  ] as const)
    out.scalar("sandbox", `sandbox ${field}`, x?.[field], y?.[field], () => [
      "medium",
      "Changes where or how the sandbox backend runs commands.",
    ]);
  out.scalar(
    "sandbox",
    "sandbox credential",
    x?.credential ?? "none",
    y?.credential ?? "none",
    (_, r) =>
      r === "runtime"
        ? ["high", "Sends the runtime credential to the sandbox endpoint."]
        : [
            "medium",
            "Stops sending the runtime credential to the sandbox endpoint.",
          ],
  );
  // An absent httpTransport and http-allowed are the same default.
  out.transport(
    "sandbox",
    "sandbox httpTransport",
    x?.endpoint === undefined
      ? undefined
      : { transport: x.httpTransport, url: x.endpoint },
    y?.endpoint === undefined
      ? undefined
      : { transport: y.httpTransport, url: y.endpoint },
    (_, v) =>
      v === "http-allowed"
        ? [
            "high",
            "Sandbox endpoint may be reached over plain HTTP to a private or internal host; commands, their output, and files sent to the sandbox are unencrypted and can be altered in transit.",
          ]
        : ["low", "Sandbox endpoint is reached over https only."],
  );
  out.set(
    "sandbox",
    "sandbox filesystem.read.deny",
    x?.filesystem?.read?.deny,
    y?.filesystem?.read?.deny,
    ["medium", "Denies reading an additional path."],
    ["high", "Sandboxed processes may read this path."],
  );
  out.set(
    "sandbox",
    "sandbox filesystem.write.allow",
    x?.filesystem?.write?.allow,
    y?.filesystem?.write?.allow,
    ["high", "Sandboxed processes may write an additional path."],
    ["medium", "Removes a writable path."],
  );
  out.scalar(
    "sandbox",
    "sandbox network",
    x?.network?.mode,
    y?.network?.mode,
    (_, m) =>
      m === "allow"
        ? ["high", "Sandboxed processes may reach the network."]
        : ["medium", "Sandboxed processes lose network access."],
  );
  out.scalar(
    "sandbox",
    "sandbox network.egress",
    x?.network?.egress,
    y?.network?.egress,
    (_, e) =>
      e
        ? ["high", "Declares that IT owns egress; PiShip does not verify it."]
        : ["medium", "Withdraws the declaration that IT owns egress."],
  );
  out.set(
    "sandbox",
    "sandbox environment.allow",
    x?.environment?.allow,
    y?.environment?.allow,
    ["high", "Passes an additional environment variable into the sandbox."],
    ["medium", "Passes fewer environment variables into the sandbox."],
  );
  out.scalar(
    "sandbox",
    "sandbox workspace",
    x?.workspace ?? "local",
    y?.workspace ?? "local",
    (_, w) =>
      w === "remote"
        ? [
            "high",
            "The project is uploaded to the sandbox backend, which holds the only live copy; the host tree changes only on sandbox pull.",
          ]
        : ["medium", "The project stays on this host instead of the sandbox."],
  );
  for (const [field, fallback] of [
    ["maxTotalMiB", 200],
    ["maxFileMiB", 50],
  ] as const)
    out.scalar(
      "sandbox",
      `sandbox remote.seed.${field}`,
      x?.remote?.seed?.[field] ?? fallback,
      y?.remote?.seed?.[field] ?? fallback,
      (b, a) =>
        Number(a) > Number(b)
          ? ["medium", "More of the project may be uploaded to the sandbox."]
          : ["low", "Less of the project is uploaded to the sandbox."],
    );
  out.scalar(
    "sandbox",
    "sandbox remote.pull.protectedFiles",
    x?.remote?.pull?.protectedFiles ?? "skip",
    y?.remote?.pull?.protectedFiles ?? "skip",
    (_, v) =>
      v === "refuse"
        ? [
            "low",
            "sandbox pull refuses a whole patch that touches a protected file.",
          ]
        : [
            "medium",
            "sandbox pull applies the rest of a patch and skips protected files.",
          ],
  );
  out.scalar(
    "sandbox",
    "sandbox remote.pull.confirm",
    x?.remote?.pull?.confirm ?? "optional",
    y?.remote?.pull?.confirm ?? "optional",
    (_, v) =>
      v === "required"
        ? ["low", "sandbox pull needs an interactive review; --yes is refused."]
        : ["medium", "sandbox pull --yes applies a patch without a prompt."],
  );
  out.scalar(
    "sandbox",
    "sandbox remote.refresh",
    x?.remote?.refresh ?? "auto",
    y?.remote?.refresh ?? "auto",
    (_, v) =>
      v === "off"
        ? ["low", "Host edits no longer reach the sandbox during a session."]
        : ["medium", "Host edits are uploaded to the sandbox at each turn."],
  );
  out.scalar(
    "sandbox",
    "sandbox remote.setup",
    x?.remote?.setup ?? "",
    y?.remote?.setup ?? "",
    (_, v) =>
      v
        ? ["high", "Runs a command in the sandbox after the upload."]
        : ["low", "No setup command runs in the sandbox."],
  );
  out.scalar(
    "sandbox",
    "sandbox remote.setupTimeoutSeconds",
    x?.remote?.setupTimeoutSeconds ?? 900,
    y?.remote?.setupTimeoutSeconds ?? 900,
    (b, a) =>
      Number(a) > Number(b)
        ? ["low", "The setup command may run longer."]
        : ["low", "The setup command is cut off sooner."],
  );
  const caches = (sandbox: typeof x) =>
    sandbox?.remote?.cache ??
    (sandbox?.remote?.setup && sandbox.provider === "e2b-compatible"
      ? "snapshot"
      : "off");
  out.scalar("sandbox", "sandbox remote.cache", caches(x), caches(y), (_, v) =>
    v === "snapshot"
      ? [
          "medium",
          "The sandbox is saved after setup and later sessions start from it.",
        ]
      : ["low", "Every session runs the setup command again."],
  );
  out.scalar(
    "sandbox",
    "sandbox remote.cacheKeyFiles",
    (x?.remote?.cacheKeyFiles ?? []).join(", "),
    (y?.remote?.cacheKeyFiles ?? []).join(", "),
    () => [
      "low",
      "The files that decide when the saved setup is rebuilt changed.",
    ],
  );
  out.scalar(
    "sandbox",
    "sandbox lifetimeSeconds",
    x?.lifetimeSeconds ?? 3600,
    y?.lifetimeSeconds ?? 3600,
    (b, a) =>
      Number(a) > Number(b)
        ? ["low", "The sandbox may live longer."]
        : ["low", "The sandbox is reclaimed sooner."],
  );
}
