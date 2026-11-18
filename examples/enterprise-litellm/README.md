# Enterprise LiteLLM example

Starting files for connecting a managed PiShip distribution to a [LiteLLM](https://docs.litellm.ai/) proxy through a company credential broker. The contract they implement is the [enterprise integration contract](../../docs/enterprise-integration.md). This is not a buildable example: it has no lock or resources. `litellm-config.yaml` is run unchanged by the [enterprise reference stack](../enterprise-reference/README.md), which tests it against LiteLLM v1.103.0 with a real Keycloak and a reference broker; the managed `piship.yaml` here is not run against any service, and nothing in this directory has been tested against a production LiteLLM, identity provider, or broker.

| File | Purpose |
| --- | --- |
| [`piship.yaml`](piship.yaml) | Managed access sections for `piship/v1`; passes `piship validate` |
| [`litellm-config.yaml`](litellm-config.yaml) | LiteLLM proxy config whose `model_name` values match `models.allowed` |

What you still provide:

- **An OIDC client**: public, Authorization Code + PKCE `S256`, redirect `http://127.0.0.1:8765/callback`, and a refresh token.
- **A broker** in front of LiteLLM: it validates the identity access token, calls `POST /key/generate` with the master key, and returns the `http-broker` response; its revoke endpoint calls `POST /key/delete` for the presented key. See [connecting a LiteLLM gateway](../../docs/enterprise-integration.md#connecting-a-litellm-gateway).
- **HTTPS** for the proxy and broker, and the enterprise CA in `network.tls.additionalCA` if needed.
- **Accurate `models.catalog` metadata**: LiteLLM's `GET /v1/models` supplies only the IDs.
- **LiteLLM's environment** (`litellm-config.yaml` reads the first three; LiteLLM reads the salt key itself):
  - `LITELLM_MASTER_KEY`: the admin key the broker uses; LiteLLM requires it to start with `sk-`.
  - `DATABASE_URL`: a persistent PostgreSQL. The reference stack keeps it on tmpfs, which loses every key and spend record on restart.
  - `OPENAI_API_KEY`, or your provider's keys if you change the models' `litellm_params`.
  - `LITELLM_SALT_KEY`: encrypts the provider credentials LiteLLM stores; it cannot change while the database exists.

Set the runtime variables before `login`:

| Variable | Value |
| --- | --- |
| `ACMECODE_OIDC_ISSUER` | IdP issuer URL |
| `ACMECODE_OIDC_CLIENT_ID` | Public client ID |
| `ACMECODE_CREDENTIAL_BROKER_URL` | Broker acquire endpoint |
| `ACMECODE_CREDENTIAL_REVOKE_URL` | Broker revoke endpoint |
| `ACMECODE_LLM_GATEWAY_URL` | LiteLLM base URL with `/v1`, for example `https://llm.corp.example/v1` |

To build a distribution, copy `piship.yaml` into your distribution repository, add resources and governance as in the [demo company example](../demo-company/README.md), then run `node <piship>/packages/cli/dist/bin.js lock piship.yaml` and `node <piship>/packages/cli/dist/bin.js build piship.yaml` from a PiShip checkout built with `npm ci && npm run build` ([running the CLI from your own repository](../../docs/enterprise-integration.md#running-the-cli-from-your-own-repository)).
