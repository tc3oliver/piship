// Sandbox: filesystem, network, and child environment boundaries.
import type { SandboxConfig } from "../governance.js";
import {
  bool,
  envName,
  fail,
  isRecord,
  list,
  oneOf,
  optionalRecord,
  plainString,
  unsafe,
} from "./fields.js";

export const DEFAULT_SANDBOX_READ_DENY = [
  "~/.ssh",
  "~/.aws",
  "~/.gnupg",
  "~/.config/gcloud",
  "~/.azure",
  "~/.kube",
  "~/.docker",
  "~/.netrc",
  "~/.npmrc",
  "~/.pi",
] as const;
export const DEFAULT_SANDBOX_WRITE_ALLOW = ["workspace", "tmp"] as const;
export const DEFAULT_SANDBOX_ENVIRONMENT = [
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TERM",
  "TZ",
  "SHELL",
  "TMPDIR",
] as const;

function sandboxPath(value: unknown, path: string): string {
  const item = plainString(value, path, 1024);
  const root = item.split("/")[0];
  const absolute = item.startsWith("/");
  if (
    !(absolute || root === "~" || root === "workspace" || root === "tmp") ||
    item.includes("\\") ||
    item
      .split("/")
      .slice(absolute ? 1 : 0)
      .some(
        (segment, index, all) =>
          segment === "." ||
          segment === ".." ||
          (!segment && index < all.length - 1),
      )
  )
    unsafe(
      path,
      "Use workspace, tmp, ~/..., or an absolute path without . or .. segments",
    );
  return item.length > 1 && item.endsWith("/") ? item.slice(0, -1) : item;
}

export function parseSandbox(value: unknown): SandboxConfig {
  const sandbox = optionalRecord(value, "sandbox", [
    "required",
    "filesystem",
    "network",
    "environment",
  ]);
  const required = bool(sandbox.required, "sandbox.required", false);
  const filesystem = optionalRecord(sandbox.filesystem, "sandbox.filesystem", [
    "read",
    "write",
  ]);
  const read = optionalRecord(filesystem.read, "sandbox.filesystem.read", [
    "deny",
  ]);
  const write = optionalRecord(filesystem.write, "sandbox.filesystem.write", [
    "allow",
  ]);
  const network = isRecord(sandbox.network) ? sandbox.network : {};
  const hostnames =
    "Hostname allowlists are not enforced at the sandbox boundary; use deny or allow (network.allowHosts governs PiShip-managed requests)";
  if (network.mode === "allowlist") fail("sandbox.network.mode", hostnames);
  for (const key of ["allow", "allowHosts", "hosts"])
    if (network[key] !== undefined) fail(`sandbox.network.${key}`, hostnames);
  const networkSection = optionalRecord(sandbox.network, "sandbox.network", [
    "mode",
  ]);
  const environment = optionalRecord(
    sandbox.environment,
    "sandbox.environment",
    ["allow"],
  );
  return {
    required,
    filesystem: {
      read: {
        deny:
          read.deny === undefined
            ? [...DEFAULT_SANDBOX_READ_DENY]
            : list(read.deny, "sandbox.filesystem.read.deny", sandboxPath),
      },
      write: {
        allow:
          write.allow === undefined
            ? [...DEFAULT_SANDBOX_WRITE_ALLOW]
            : list(write.allow, "sandbox.filesystem.write.allow", sandboxPath),
      },
    },
    network: {
      mode: oneOf(
        networkSection.mode,
        "sandbox.network.mode",
        ["deny", "allow"] as const,
        required ? "deny" : "allow",
      ),
    },
    environment: {
      allow:
        environment.allow === undefined
          ? [...DEFAULT_SANDBOX_ENVIRONMENT]
          : list(environment.allow, "sandbox.environment.allow", envName),
    },
  };
}
