// Sandbox: filesystem, network, and child environment boundaries.
import {
  SANDBOX_PROVIDERS,
  type SandboxConfig,
  type SandboxProvider,
} from "../governance.js";
import { HTTP_TRANSPORTS } from "../http-transport.js";
import {
  bool,
  conflict,
  envName,
  fail,
  isRecord,
  list,
  modulePath,
  oneOf,
  optionalRecord,
  plainString,
  referenceUrl,
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

/** Backend fields and the providers that accept them. */
const BACKEND_FIELDS: Readonly<
  Record<string, readonly Exclude<SandboxProvider, "native">[]>
> = {
  adapter: ["custom"],
  endpoint: ["custom", "e2b-compatible", "kubernetes-agent-sandbox"],
  router: ["kubernetes-agent-sandbox"],
  namespace: ["kubernetes-agent-sandbox"],
  template: ["e2b-compatible", "kubernetes-agent-sandbox"],
  workdir: ["e2b-compatible", "kubernetes-agent-sandbox"],
  user: ["e2b-compatible"],
  credential: ["custom", "e2b-compatible", "kubernetes-agent-sandbox"],
};
const KUBERNETES_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const TEMPLATE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const SANDBOX_USER = /^[a-z_][a-z0-9_-]{0,31}$/;

function remoteWorkdir(value: unknown, path: string): string {
  const item = plainString(value, path, 1024);
  if (
    !item.startsWith("/") ||
    item.includes("\\") ||
    item
      .split("/")
      .slice(1)
      .some(
        (segment, index, all) =>
          segment === "." ||
          segment === ".." ||
          (!segment && index < all.length - 1),
      )
  )
    unsafe(path, "Use an absolute POSIX path without . or .. segments");
  return item;
}

/** The backend fields, validated for the provider; empty for native. */
function parseBackend(
  sandbox: Readonly<Record<string, unknown>>,
  required: boolean,
  variables: readonly string[],
): Omit<SandboxConfig, "required" | "filesystem" | "network" | "environment"> {
  const provider = oneOf(
    sandbox.provider,
    "sandbox.provider",
    SANDBOX_PROVIDERS,
    "native",
  );
  for (const [field, providers] of Object.entries(BACKEND_FIELDS))
    if (
      sandbox[field] !== undefined &&
      (provider === "native" || !providers.includes(provider))
    )
      conflict(
        `sandbox.${field}`,
        `${field} applies only to the ${providers.join(", ")} provider${providers.length > 1 ? "s" : ""}`,
      );
  if (provider === "native" && sandbox.httpTransport !== undefined)
    conflict(
      "sandbox.httpTransport",
      "httpTransport applies only to the custom, e2b-compatible, kubernetes-agent-sandbox providers",
    );
  if (provider === "native") return {};
  if (!required)
    conflict(
      "sandbox.provider",
      `The ${provider} backend is used only by a required sandbox; set sandbox.required: true`,
    );
  if (provider === "custom" && sandbox.adapter === undefined)
    fail("sandbox.adapter", "The custom provider needs an adapter module");
  if (provider !== "custom" && sandbox.endpoint === undefined)
    fail("sandbox.endpoint", `The ${provider} provider needs an endpoint`);
  if (provider === "kubernetes-agent-sandbox") {
    if (sandbox.router === undefined)
      fail(
        "sandbox.router",
        "The kubernetes-agent-sandbox provider needs the sandbox router URL",
      );
    if (sandbox.template === undefined)
      fail(
        "sandbox.template",
        "The kubernetes-agent-sandbox provider needs the warm pool name",
      );
  }
  const text = (field: string, pattern: RegExp, message: string) => {
    const item = plainString(sandbox[field], `sandbox.${field}`, 128);
    if (!pattern.test(item)) fail(`sandbox.${field}`, message);
    return item;
  };
  const credential = oneOf(
    sandbox.credential,
    "sandbox.credential",
    ["none", "runtime", "stored"] as const,
    "none",
  );
  // A stored credential is bound to the endpoint's origin; without an
  // endpoint there is nothing to bind it to.
  if (credential === "stored" && sandbox.endpoint === undefined)
    fail(
      "sandbox.endpoint",
      "sandbox.credential: stored needs the endpoint the credential is sent to",
    );
  const httpTransport = oneOf(
    sandbox.httpTransport,
    "sandbox.httpTransport",
    HTTP_TRANSPORTS,
    "https",
  );
  const plainHttp = httpTransport === "http-allowed";
  if (plainHttp && sandbox.endpoint === undefined)
    conflict(
      "sandbox.httpTransport",
      "httpTransport applies to the sandbox endpoint (and router); this sandbox declares no endpoint",
    );
  // As for MCP servers: the runtime credential goes over plain HTTP only to
  // the inference gateway itself, never to another service on its origin.
  if (plainHttp && credential === "runtime")
    conflict(
      "sandbox.httpTransport",
      // No `credential: <word>` text: the CLI redactor reads it as a value.
      "http-allowed cannot be combined with sandbox.credential set to runtime; the runtime credential is never sent to the sandbox over plain HTTP",
    );
  return {
    provider,
    ...(sandbox.adapter === undefined
      ? {}
      : { adapter: modulePath(sandbox.adapter, "sandbox.adapter") }),
    ...(sandbox.endpoint === undefined
      ? {}
      : {
          endpoint: referenceUrl(
            sandbox.endpoint,
            "sandbox.endpoint",
            variables,
            plainHttp,
          ),
        }),
    ...(sandbox.router === undefined
      ? {}
      : {
          router: referenceUrl(
            sandbox.router,
            "sandbox.router",
            variables,
            plainHttp,
          ),
        }),
    ...(sandbox.namespace === undefined
      ? {}
      : {
          namespace: text(
            "namespace",
            KUBERNETES_NAME,
            "Use a Kubernetes namespace name",
          ),
        }),
    ...(sandbox.template === undefined
      ? {}
      : {
          template: text(
            "template",
            provider === "kubernetes-agent-sandbox"
              ? KUBERNETES_NAME
              : TEMPLATE_ID,
            provider === "kubernetes-agent-sandbox"
              ? "Use a Kubernetes resource name"
              : "Use a template ID or name",
          ),
        }),
    ...(sandbox.workdir === undefined
      ? {}
      : { workdir: remoteWorkdir(sandbox.workdir, "sandbox.workdir") }),
    ...(sandbox.user === undefined
      ? {}
      : {
          user: text(
            "user",
            SANDBOX_USER,
            "Use a POSIX user name such as user or root",
          ),
        }),
    ...(credential === "none" ? {} : { credential }),
    ...(plainHttp ? { httpTransport } : {}),
  };
}

export function parseSandbox(
  value: unknown,
  variables: readonly string[] = [],
  /** piship/v1alpha6 and later: `sandbox.httpTransport`. */
  v6 = false,
): SandboxConfig {
  const sandbox = optionalRecord(value, "sandbox", [
    "required",
    "provider",
    ...Object.keys(BACKEND_FIELDS),
    ...(v6 ? ["httpTransport"] : []),
    "filesystem",
    "network",
    "environment",
  ]);
  const required = bool(sandbox.required, "sandbox.required", false);
  const backend = parseBackend(sandbox, required, variables);
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
    ...backend,
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
