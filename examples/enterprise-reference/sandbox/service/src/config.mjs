// Configuration from the environment only. `loadConfig` throws with the
// variable's name, never its value.
import { realpathSync, statSync } from "node:fs";
import { delimiter, isAbsolute } from "node:path";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1"]);
const NAME = /^[a-z0-9][a-z0-9_.-]{0,40}$/;

/** A resolved directory that exists; throws with `name` otherwise. */
function directory(name, value) {
  let real;
  try {
    real = realpathSync(value);
    if (!statSync(real).isDirectory()) throw new Error("not a directory");
  } catch {
    throw new Error(`${name} names a directory that does not exist`);
  }
  return real;
}

export function loadConfig(env) {
  const text = (name, fallback, pattern, what) => {
    const value =
      env[name] === undefined || env[name] === "" ? fallback : env[name];
    if (value === undefined) throw new Error(`${name} is required`);
    if (typeof value !== "string" || !pattern.test(value))
      throw new Error(`${name} must be ${what}`);
    return value;
  };
  const number = (name, fallback, { min, max, integer = true }) => {
    const value = env[name];
    if (value === undefined || value === "") return fallback;
    const parsed = Number(value);
    if (
      !Number.isFinite(parsed) ||
      (integer && !Number.isInteger(parsed)) ||
      parsed < min ||
      parsed > max
    )
      throw new Error(`${name} must be a number from ${min} to ${max}`);
    return parsed;
  };

  const cpus = () => {
    const value = text(
      "SANDBOX_CPUS",
      "2",
      /^\d{1,2}(?:\.\d{1,2})?$/,
      "a number such as 2 or 0.5",
    );
    if (!(Number(value) > 0))
      throw new Error("SANDBOX_CPUS must be greater than 0");
    return value;
  };

  // The service binds loopback and nothing else. Reaching it from another
  // machine is the job of a TLS-terminating proxy the organization runs in
  // front of it; there is deliberately no switch for a wider bind here.
  const listenHost = env.SANDBOX_LISTEN_HOST || "127.0.0.1";
  if (!LOOPBACK_HOSTS.has(listenHost))
    throw new Error("SANDBOX_LISTEN_HOST must be 127.0.0.1 or ::1");
  const listenPort = number("SANDBOX_LISTEN_PORT", 18075, {
    min: 1,
    max: 65535,
  });

  const rootsText = env.SANDBOX_WORKSPACE_ROOTS;
  if (!rootsText) throw new Error("SANDBOX_WORKSPACE_ROOTS is required");
  const roots = [
    ...new Set(
      rootsText
        .split(delimiter)
        .filter((entry) => entry !== "")
        .map((entry) => {
          if (!isAbsolute(entry))
            throw new Error("SANDBOX_WORKSPACE_ROOTS must list absolute paths");
          const real = directory("SANDBOX_WORKSPACE_ROOTS", entry);
          if (real === "/")
            throw new Error(
              "SANDBOX_WORKSPACE_ROOTS must not list the filesystem root",
            );
          return real;
        }),
    ),
  ];
  if (roots.length === 0)
    throw new Error("SANDBOX_WORKSPACE_ROOTS must list at least one directory");

  const registry = env.SANDBOX_REGISTRY;
  if (!registry || !isAbsolute(registry))
    throw new Error("SANDBOX_REGISTRY must be an absolute path");

  const allowNetwork = text(
    "SANDBOX_ALLOW_NETWORK",
    "bridge",
    /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/,
    "a Docker network name",
  );
  // The host's network and another container's would put the sandbox on
  // interfaces it must not share; `none` is what `deny` already means.
  if (allowNetwork === "host" || allowNetwork === "none")
    throw new Error("SANDBOX_ALLOW_NETWORK must not be host or none");

  const listenAddress =
    listenHost === "::1"
      ? `[::1]:${listenPort}`
      : `${listenHost}:${listenPort}`;
  const allowedHosts = new Set([
    listenAddress,
    `localhost:${listenPort}`,
    ...(env.SANDBOX_ALLOWED_HOSTS ?? "")
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),
  ]);

  // The service's own user: it labels every container it starts, and the
  // start-up sweep removes only containers that carry both this and the
  // instance name.
  const uid = process.getuid?.() ?? 0;
  return {
    listenHost,
    listenPort,
    allowedHosts,
    uid,
    // One name per service on a Docker daemon: the default is this user's and
    // this port's, so two services with no name set do not share one. A name
    // set by the operator must be unique to the service the same way.
    instance: text(
      "SANDBOX_INSTANCE",
      `reference-${uid}-${listenPort}`,
      NAME,
      "a short lowercase name",
    ),
    registry,
    workspaceRoots: roots,
    image: text(
      "SANDBOX_IMAGE",
      undefined,
      /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,254}$/,
      "an image reference",
    ),
    shell: text(
      "SANDBOX_SHELL",
      "/bin/sh",
      /^\/[A-Za-z0-9._/-]{1,100}$/,
      "an absolute path in the image",
    ),
    docker: env.SANDBOX_DOCKER || "docker",
    allowNetwork,
    memory: text(
      "SANDBOX_MEMORY",
      "1g",
      /^[1-9]\d{0,5}[mg]$/,
      "like 512m or 1g",
    ),
    cpus: cpus(),
    tmpSize: text(
      "SANDBOX_TMP_SIZE",
      "256m",
      /^[1-9]\d{0,4}[mg]$/,
      "like 256m",
    ),
    pids: number("SANDBOX_PIDS", 512, { min: 16, max: 32_768 }),
    // A sandbox idle this long is removed, and none lives longer than the
    // maximum, whoever is using it. A command that runs counts as activity.
    idleSeconds: number("SANDBOX_IDLE_SECONDS", 3600, { min: 1, max: 604_800 }),
    maxLifetimeSeconds: number("SANDBOX_MAX_LIFETIME_SECONDS", 43_200, {
      min: 1,
      max: 604_800,
    }),
    maxExecSeconds: number("SANDBOX_MAX_EXEC_SECONDS", 3600, {
      min: 1,
      max: 86_400,
    }),
    maxOutputBytes: number("SANDBOX_MAX_OUTPUT_BYTES", 64 * 1024 * 1024, {
      min: 1024,
      max: 1024 * 1024 * 1024,
    }),
    maxPerKey: number("SANDBOX_MAX_PER_KEY", 8, { min: 1, max: 1000 }),
    maxTotal: number("SANDBOX_MAX_TOTAL", 32, { min: 1, max: 10_000 }),
    maxExecsPerSandbox: number("SANDBOX_MAX_EXECS", 8, { min: 1, max: 1000 }),
    sweepMs: number("SANDBOX_SWEEP_MS", 5000, { min: 50, max: 60_000 }),
  };
}
