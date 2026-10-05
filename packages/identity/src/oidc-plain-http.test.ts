// identity.oidc.httpTransport: http-allowed: an endpoint the discovery
// document names may be plain HTTP only to a private or internal host,
// including the authorization endpoint the browser opens.
import {
  createManagedFetch,
  DEFAULT_NETWORK_POLICY,
  type ManagedFetch,
} from "@piship/contracts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error The deterministic fixture is plain JavaScript.
import { startLocalServices } from "../../../examples/demo-company/fixtures/local-services.mjs";
import { OidcPkceIdentityProvider } from "./index.js";

type Services = Awaited<ReturnType<typeof startLocalServices>>;
let services: Services;
beforeEach(async () => {
  services = await startLocalServices();
});
afterEach(async () => {
  await services.close();
});

/** The managed fetch, with the discovery document's endpoints rewritten. */
function rewriting(metadata: Record<string, string>): ManagedFetch {
  const fetch = createManagedFetch(DEFAULT_NETWORK_POLICY);
  return async (url, init) => {
    const response = await fetch(url, init);
    if (!url.toString().endsWith("/.well-known/openid-configuration"))
      return response;
    const body = {
      ...((await response.json()) as Record<string, unknown>),
      ...metadata,
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
}

const provider = (metadata: Record<string, string>, plainHttp: boolean) =>
  new OidcPkceIdentityProvider({
    issuer: services.issuer,
    clientId: services.clientId,
    scopes: ["openid"],
    redirectUri: "http://127.0.0.1/callback",
    fetch: rewriting(metadata),
    ...(plainHttp ? { plainHttp } : {}),
  });

describe("OIDC discovery with httpTransport: http-allowed", () => {
  it("accepts plain-HTTP endpoints on private or internal hosts", async () => {
    const config = await provider(
      {
        authorization_endpoint: "http://keycloak.corp.internal/auth",
        end_session_endpoint: "http://10.0.0.8/logout",
      },
      true,
    ).configuration();
    expect(config.serverMetadata().authorization_endpoint).toBe(
      "http://keycloak.corp.internal/auth",
    );
  });

  it("refuses a plain-HTTP endpoint on a public host, including the browser's", async () => {
    await expect(
      provider(
        { authorization_endpoint: "http://login.acme.example/auth" },
        true,
      ).configuration(),
    ).rejects.toMatchObject({
      code: "CONFIG_INVALID",
      message: expect.stringContaining(
        "authorization_endpoint is plain HTTP to login.acme.example, which is public",
      ),
    });
    await expect(
      provider({ jwks_uri: "http://8.8.8.8/jwks" }, true).configuration(),
    ).rejects.toMatchObject({ code: "CONFIG_INVALID" });
  });
});
