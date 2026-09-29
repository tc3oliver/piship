#!/usr/bin/env node
// Reference credential broker for the PiShip enterprise reference stack.
// Configuration comes from the environment only; see README.md. No
// dependencies beyond Node 22.
import { createServer } from "node:http";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createBroker } from "./src/broker.mjs";
import { createLiteLLMAdmin } from "./src/litellm.mjs";
import { createLogger } from "./src/log.mjs";
import { createTokenVerifier } from "./src/token.mjs";

/** Read and check the configuration. Throws with the variable's name, never its value. */
export function loadConfig(env) {
  const required = (name) => {
    const value = env[name];
    if (typeof value !== "string" || value.length === 0)
      throw new Error(`${name} is required`);
    return value;
  };
  const url = (name) => {
    const value = required(name);
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error(`${name} must be a URL`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:")
      throw new Error(`${name} must be an http(s) URL`);
    if (parsed.username || parsed.password)
      throw new Error(`${name} must not embed credentials`);
    return value;
  };
  const allowInsecureBackchannel = (() => {
    const value = env.BROKER_ALLOW_INSECURE_BACKCHANNEL;
    if (value === undefined || value === "" || value === "false") return false;
    if (value === "true") return true;
    throw new Error("BROKER_ALLOW_INSECURE_BACKCHANNEL must be true or false");
  })();
  /**
   * A URL the broker fetches and trusts: the JWKS decides which tokens are
   * genuine, and LiteLLM admin calls carry the master key. It must be https,
   * except on a loopback host, or on a single-label host name (a container
   * network name such as `keycloak`) when BROKER_ALLOW_INSECURE_BACKCHANNEL
   * is true.
   */
  const backchannelUrl = (name) => {
    const value = url(name);
    const { protocol, hostname } = new URL(value);
    if (protocol === "https:") return value;
    const loopback =
      hostname === "localhost" ||
      hostname === "[::1]" ||
      (isIP(hostname) === 4 && hostname.startsWith("127."));
    const containerName =
      isIP(hostname) === 0 &&
      /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(hostname);
    if (loopback || (allowInsecureBackchannel && containerName)) return value;
    throw new Error(
      `${name} must be an https URL (http only for a loopback host, or for a container network name with BROKER_ALLOW_INSECURE_BACKCHANNEL=true)`,
    );
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
  /** A comma-separated list of IP addresses; empty when unset. */
  const addresses = (name) => {
    const value = env[name];
    if (value === undefined || value.trim() === "") return [];
    const list = value.split(",").map((entry) => entry.trim());
    if (!list.every((entry) => isIP(entry) !== 0))
      throw new Error(`${name} must be a comma-separated list of IP addresses`);
    return list;
  };
  const masterKey = required("LITELLM_MASTER_KEY");
  if (!masterKey.startsWith("sk-") || masterKey.length < 16)
    throw new Error("LITELLM_MASTER_KEY must be an sk- key");
  const budgetDuration = env.BROKER_USER_BUDGET_DURATION || "30d";
  if (!/^\d{1,4}[smhd]$/.test(budgetDuration))
    throw new Error("BROKER_USER_BUDGET_DURATION must look like 30d");
  return {
    listenHost: env.BROKER_LISTEN_HOST || "127.0.0.1",
    listenPort: number("BROKER_LISTEN_PORT", 8080, { min: 1, max: 65535 }),
    issuer: url("BROKER_ISSUER"),
    jwksUrl: backchannelUrl("BROKER_JWKS_URL"),
    audience: env.BROKER_AUDIENCE || "piship-reference-broker",
    authorizedParty: env.BROKER_AUTHORIZED_PARTY || "acmecode",
    distribution: env.BROKER_DISTRIBUTION || "acmecode",
    litellmUrl: backchannelUrl("BROKER_LITELLM_URL"),
    masterKey,
    gatewayBaseUrl: url("BROKER_GATEWAY_BASE_URL"),
    // Lifetime of an issued key; capped at 24 hours.
    keyTtlSeconds: number("BROKER_KEY_TTL_SECONDS", 8 * 3600, {
      min: 600,
      max: 86_400,
    }),
    userMaxBudget: number("BROKER_USER_MAX_BUDGET", 10, {
      min: 0.000001,
      max: 1_000_000,
      integer: false,
    }),
    userBudgetDuration: budgetDuration,
    userTpmLimit: number("BROKER_USER_TPM_LIMIT", 0, {
      min: 0,
      max: 100_000_000,
    }),
    userRpmLimit: number("BROKER_USER_RPM_LIMIT", 0, {
      min: 0,
      max: 1_000_000,
    }),
    keyMaxParallelRequests: number("BROKER_KEY_MAX_PARALLEL_REQUESTS", 0, {
      min: 0,
      max: 10_000,
    }),
    maxKeysPerUser: number("BROKER_MAX_KEYS_PER_USER", 3, { min: 1, max: 50 }),
    acquireLimitPerMinute: number("BROKER_ACQUIRE_LIMIT_PER_MINUTE", 20, {
      min: 1,
      max: 10_000,
    }),
    clockToleranceSeconds: number("BROKER_CLOCK_TOLERANCE_SECONDS", 30, {
      min: 0,
      max: 300,
    }),
    revokeLimitPerMinute: number("BROKER_REVOKE_LIMIT_PER_MINUTE", 60, {
      min: 1,
      max: 10_000,
    }),
    revokeMaxConcurrent: number("BROKER_REVOKE_MAX_CONCURRENT", 16, {
      min: 1,
      max: 1000,
    }),
    trustedProxies: addresses("BROKER_TRUSTED_PROXIES"),
  };
}

/** Build the request listener and its dependencies from a config. */
export function createBrokerServer(
  config,
  { fetch = globalThis.fetch, write } = {},
) {
  const log = createLogger({ write, secrets: [config.masterKey] });
  const verifier = createTokenVerifier({
    issuer: config.issuer,
    audience: config.audience,
    authorizedParty: config.authorizedParty,
    jwksUrl: config.jwksUrl,
    clockToleranceSeconds: config.clockToleranceSeconds,
    fetch,
  });
  const litellm = createLiteLLMAdmin({
    baseUrl: config.litellmUrl,
    masterKey: config.masterKey,
    fetch,
  });
  const server = createServer(createBroker(config, { verifier, litellm, log }));
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  return { server, log };
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  let config;
  try {
    config = loadConfig(process.env);
  } catch (error) {
    process.stderr.write(`broker: ${error.message}\n`);
    process.exit(2);
  }
  const { server, log } = createBrokerServer(config);
  server.listen(config.listenPort, config.listenHost, () => {
    log("broker.listening", {
      listen: `${config.listenHost}:${config.listenPort}`,
    });
  });
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
