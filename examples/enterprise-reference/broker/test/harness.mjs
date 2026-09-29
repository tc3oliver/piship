// Starts a broker between a fake Keycloak and a fake LiteLLM, and captures
// its log lines so tests can scan them for secrets.
import { once } from "node:events";
import { createBrokerServer, loadConfig } from "../server.mjs";
import {
  AUDIENCE,
  CLIENT,
  ISSUER,
  MASTER_KEY,
  startFakeKeycloak,
  startFakeLiteLLM,
} from "./fakes.mjs";

export const GATEWAY_BASE_URL = "http://127.0.0.1:14000/v1";

export async function startHarness(overrides = {}) {
  const keycloak = await startFakeKeycloak();
  const litellm = await startFakeLiteLLM();
  const config = loadConfig({
    BROKER_ISSUER: ISSUER,
    BROKER_JWKS_URL: keycloak.jwksUrl,
    BROKER_AUDIENCE: AUDIENCE,
    BROKER_AUTHORIZED_PARTY: CLIENT,
    BROKER_DISTRIBUTION: "acmecode",
    BROKER_LITELLM_URL: litellm.url,
    LITELLM_MASTER_KEY: MASTER_KEY,
    BROKER_GATEWAY_BASE_URL: GATEWAY_BASE_URL,
    ...overrides,
  });
  const logLines = [];
  const { server } = createBrokerServer(config, {
    write: (line) => logLines.push(line),
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}`;

  /** POST an acquire the way PiShip's http-broker client does. */
  async function acquire(
    token,
    {
      body = { distribution: "acmecode", purpose: "inference" },
      key,
      headers = {},
    } = {},
  ) {
    const response = await fetch(`${url}/v1/credential`, {
      method: "POST",
      headers: {
        ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
        "content-type": "application/json",
        accept: "application/json",
        ...(key === undefined ? {} : { "idempotency-key": key }),
        ...headers,
      },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    const text = await response.text();
    return {
      status: response.status,
      headers: response.headers,
      text,
      json: text ? JSON.parse(text) : null,
    };
  }

  async function revoke(
    credential,
    credentialId = null,
    distribution = "acmecode",
  ) {
    const response = await fetch(`${url}/v1/revoke`, {
      method: "POST",
      headers: {
        ...(credential === undefined
          ? {}
          : { authorization: `Bearer ${credential}` }),
        "content-type": "application/json",
      },
      body: JSON.stringify({ credential_id: credentialId, distribution }),
    });
    const text = await response.text();
    return {
      status: response.status,
      headers: response.headers,
      text,
      json: text ? JSON.parse(text) : null,
    };
  }

  return {
    url,
    config,
    keycloak,
    litellm,
    logLines,
    acquire,
    revoke,
    async close() {
      await new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      });
      await keycloak.close();
      await litellm.close();
    },
  };
}
