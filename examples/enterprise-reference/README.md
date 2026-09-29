# Enterprise reference stack

A local, runnable version of the company services a managed PiShip distribution talks to: an OIDC identity provider, an LLM gateway with its database, and a model upstream. It is the tested successor of [`examples/enterprise-litellm`](../enterprise-litellm/README.md), whose LiteLLM config it runs unchanged, and it implements the gateway side of the [enterprise integration contract](../../docs/enterprise-integration.md).

This is reference infrastructure for tests and local exploration, not a production deployment. It includes the [reference credential broker](broker/README.md) but no distribution yet: that is later v0.7 work. Nothing here needs an Internet model provider or a paid API key.

| Service | Image (pinned by index digest) | Host port (default) | Role |
| --- | --- | --- | --- |
| `keycloak` | `quay.io/keycloak/keycloak:26.7.4` | `127.0.0.1:18080` | OIDC identity provider, realm `piship-reference` |
| `postgres` | `postgres:17.11-alpine3.24` | `127.0.0.1:15432` | LiteLLM's database |
| `litellm` | `ghcr.io/berriai/litellm:v1.103.0` | `127.0.0.1:14000` | OpenAI-compatible gateway: virtual keys, model access, spend |
| `mock-upstream` | `node:22.23.3-alpine3.24` running [`mock-upstream/server.mjs`](mock-upstream/server.mjs) | `127.0.0.1:18090` | Deterministic OpenAI-compatible model provider behind LiteLLM |
| `broker` | `node:22.23.3-alpine3.24` running [`broker/server.mjs`](broker/server.mjs) | `127.0.0.1:18070` | Credential broker: Keycloak access token in, scoped LiteLLM virtual key out ([broker](broker/README.md)) |

Every port is published on `127.0.0.1` only. No service uses a named volume: PostgreSQL keeps its data on tmpfs and Keycloak in its container, so `docker compose down` discards every user, key, and spend record.

## Run it

Needs Docker with Compose v2 and Node 22.19 or later (for the helper scripts). From this directory:

```sh
node scripts/generate-env.mjs     # once: writes .env with random secrets
docker compose up --wait          # returns when every service is healthy
docker compose down               # stops and removes everything
```

`docker compose up --wait` returns only after all five healthchecks pass (Keycloak serves the imported realm's discovery document, PostgreSQL accepts connections, LiteLLM's `/health/readiness` reports the database connected, and the mock and the broker answer `/health`); there are no sleeps. It exits non-zero if a service becomes unhealthy. Add `--wait-timeout 300` in automation.

Use a project name (`docker compose -p <name> ...`) to run a copy beside another one, with different ports in its `.env`.

## The generated env file

`scripts/generate-env.mjs` writes `.env` next to `compose.yaml` with mode `600`. It is git-ignored (the repository's `.env` rule) and holds every secret the stack uses; `compose.yaml` and the configs hold none, and Compose refuses to start without it.

| Variable | Contents |
| --- | --- |
| `KEYCLOAK_PORT`, `LITELLM_PORT`, `MOCK_UPSTREAM_PORT`, `POSTGRES_PORT`, `BROKER_PORT` | Host ports on `127.0.0.1`. Defaults 18080, 14000, 18090, 15432, 18070 (an older `.env` without `BROKER_PORT` gets 18070); set any of them in the environment before generating to choose others |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak bootstrap `admin` password |
| `POSTGRES_PASSWORD` | Password of the `litellm` database user |
| `LITELLM_MASTER_KEY` | LiteLLM admin key (`sk-` prefix). Only a broker should hold it |
| `LITELLM_SALT_KEY` | Encrypts credentials LiteLLM stores in its database |
| `MOCK_UPSTREAM_API_KEY` | The "provider key" LiteLLM sends upstream; the mock rejects anything else with 401 |
| `REFERENCE_ALICE_PASSWORD`, `REFERENCE_BOB_PASSWORD` | Passwords of the two realm users |

The script refuses to replace an existing `.env`; `--force` replaces it (safe while the stack is down, since no state outlives it). It never prints a value. Do not print, commit, or share `.env`.

Set `LITELLM_IMAGE` to pull LiteLLM from a mirror, and only by the same digest, for example `docker.io/litellm/litellm:v1.103.0@sha256:bd089afdcd35b894b14a93f9743cdc8b591f82da1a38dd43a010a7b0c9de5fd7`, which carries the same index digest as the GitHub Container Registry image.

## Identity provider (Keycloak)

The realm is imported from [`keycloak/piship-reference-realm.json`](keycloak/piship-reference-realm.json) on every start; the user passwords are `${...}` placeholders that Keycloak fills from the environment at import.

| Setting | Value |
| --- | --- |
| Issuer | `http://127.0.0.1:<KEYCLOAK_PORT>/realms/piship-reference`, the same for the host and for containers |
| Client | `acmecode`: public (no secret), Authorization Code only (implicit, direct access grants, device flow, and service accounts off) |
| PKCE | Required, `S256` only: a request without a challenge or with `plain` is refused |
| Redirect URI | `http://127.0.0.1/callback`, port-less, which Keycloak matches for any loopback port (RFC 8252 section 7.3). `localhost` is refused |
| Access token | RS256, 5 minutes. `aud` includes `piship-reference-broker` for the broker to check; `groups` lists the user's groups |
| Refresh | `offline_access` is allowed; refresh tokens rotate (`revokeRefreshToken`) |
| Users | `alice` (group `engineering`) and `bob` (group `support`). The groups are the input for model entitlement |

Keycloak runs in development mode (`start-dev`, plain HTTP, its built-in database). A service in the compose network reaches the back channel (token, JWKS) at `http://keycloak:8080/realms/piship-reference`; discovery requested there lists `jwks_uri` on that host, while the issuer stays the loopback URL above. The admin console is at `http://127.0.0.1:<KEYCLOAK_PORT>/admin` as `admin`.

To get a token as a test would:

```sh
ACCESS_TOKEN=$(node scripts/get-token.mjs alice)       # or --response for the whole JSON
```

[`scripts/get-token.mjs`](scripts/get-token.mjs) runs the same Authorization Code + PKCE `S256` flow PiShip runs, on a random loopback port, submitting the login form directly instead of opening a browser and reading the code from the redirect's `Location` header. No password grant or other shortcut is enabled. Its output is a live credential: capture it, do not print it.

## Gateway (LiteLLM)

LiteLLM runs [`../enterprise-litellm/litellm-config.yaml`](../enterprise-litellm/litellm-config.yaml) as is, mounted read-only: model names `acme/coder` and `acme/general`, the master key and database URL from the environment. Its `openai/*` models reach the mock because `OPENAI_BASE_URL` points at `http://mock-upstream:8080/v1`, and `OPENAI_API_KEY` is `MOCK_UPSTREAM_API_KEY`. The bundled model price map is used (`LITELLM_LOCAL_MODEL_COST_MAP`), so startup makes no Internet request for it.

Only LiteLLM open-source features are used. Key regeneration and auto-rotation and per-model budgets are Enterprise-only in LiteLLM and appear nowhere here. Rotation is "generate a new key for the same `user_id`, then delete the old one".

The [broker](broker/README.md) issues keys. To issue one by hand with the master key, as the broker does:

```sh
set -a; . ./.env; set +a
curl -s -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H 'content-type: application/json' \
  -d '{"models":["acme/coder"],"duration":"1h","user_id":"alice"}' \
  http://127.0.0.1:$LITELLM_PORT/key/generate          # returns {"key": ...}; do not print it in logs
```

With that key, `GET /v1/models` lists only `acme/coder`, a request for `acme/general` is refused with a `key_model_access_denied` error (code 403), and `POST /v1/chat/completions` returns `Reference mock reply from gpt-4.1.`, streamed or not.

Observed LiteLLM behavior tests should expect (v1.103.0, this config):

- An upstream 401, 403, 429, 500, or 503 reaches the client with the same status and an OpenAI-style error of type `authentication_error`, `permission_error`, `throttling_error`, or `internal_server_error`. The upstream's `retry-after` on a 429 is not passed on.
- LiteLLM calls the upstream three times for a 403, 429, or 5xx (two retries) and once for a 401. A single queued failure (`count: 1`) is therefore absorbed and the client gets 200; queue at least three, or use the message marker, to see the error.
- After an upstream failure the model's only deployment is in a cooldown for 5 seconds. Requests for that model during it fail with 429 `No deployments available for selected model` and `retry-after: 5`, whatever the upstream would answer. Wait out the cooldown between error cases, or alternate models.

## Credential broker

[`broker/`](broker/README.md) implements PiShip's `http-broker` contract: `POST /v1/credential` with the user's Keycloak access token returns a LiteLLM virtual key limited to the models of the user's groups (`engineering`: `acme/coder` and `acme/general`; `support`: `acme/coder`), on one LiteLLM user per `(iss, sub)` with a per-user budget and no team; `POST /v1/revoke` with that key deletes it. It holds the master key and no other secret. `node broker/live-check.mjs` runs the happy path against the stack; `node --test broker/test/*.test.mjs` is its contract test, which needs no Docker.

## Tests against the stack

`npm run test:reference` at the repository root runs the tests that need this stack (Docker with Compose v2, and `npm ci && npm run build` done); `npm test` leaves them out. Each file starts its own copy of the stack and stops it when it ends, also after a failure, so nothing needs to be running first, and no `.env` beside `compose.yaml` is used or written:

- a Compose project of its own, `piship-reftest-<file>-<random>`, with the `.env` generated by `scripts/generate-env.mjs` into a temporary directory that is deleted afterwards;
- host ports `KEYCLOAK_PORT=28080`, `LITELLM_PORT=24000`, `MOCK_UPSTREAM_PORT=28090`, `POSTGRES_PORT=25432`, `BROKER_PORT=28070` on `127.0.0.1`, so a stack on the default ports can keep running. Set any of these variables in the environment to use others;
- broker settings for the file (a small budget, rate limits) in a Compose override file beside that `.env`;
- `docker compose up --wait --wait-timeout 300` to start, `docker compose down` to stop.

The files run one at a time. Each took 20 to 80 s on the machine measured below (usage continuity the longest, since it waits for spend records four times), about 15 s of it starting the stack.

| File under `tests/enterprise-reference/` | Shows, from LiteLLM's own records and answers |
| --- | --- |
| `usage-continuity.test.ts` | One employee's credentials A, B and C (minted by the broker from alice's real Keycloak token) accrue one spend total against one user budget; rotating to a fourth key (the broker deletes the oldest, keeping 3) and revoking another keeps the spend, the budget, and its reset date; bob has his own; once alice's spend reaches the budget the gateway refuses her next request on every key, including one issued afterwards, while bob's still pass |
| `gateway-rate-limits.test.ts` | Requests per minute and tokens per minute on the employee's LiteLLM user are enforced by the gateway, on every key of that employee |
| `gateway-concurrency-entitlement.test.ts` | The key's `max_parallel_requests` and its `models` list are enforced by the gateway; refused requests never reach the upstream |
| `team-member-budget.test.ts` | Decision D-01's check: a team-member budget (`max_budget_in_team`) is enforced across all of the member's team keys, while the member's personal budget is not applied to team keys. The broker issues keys without a team; this file sets a team up with the master key |

Spend is read with the master key from `/spend/users`, `/spend/logs`, `/user/info`, `/key/info` and `/team/info`, polled until it lands. Tokens, keys and the master key stay in the test's memory; response bodies are scrubbed of key and token shapes before any assertion.

Observed with LiteLLM v1.103.0 and this config (its error bodies for these limits are not documented; the tests assert on the status, the error type and a stable part of the message):

| Limit | Refusal |
| --- | --- |
| User budget | 429 `budget_exceeded`, `Budget has been exceeded! User=<user_id> ...` or `ExceededBudget: User=<user_id> over budget ...`. Immediate: LiteLLM counts spend in memory as requests finish, so the request after the one that reaches the budget is refused, well before the spend records are written |
| Requests per minute (user) | 429 `throttling_error`, `retry-after: 60`, `Rate limit exceeded for user: <user_id>. Limit type: requests. Current limit: <n>, ...`. The window starts at the first request |
| Tokens per minute (user) | 429 `throttling_error`, `retry-after: 60`, `... Limit type: tokens ...`. LiteLLM reserves an estimate (input characters / 4 plus an output allowance) before the request and corrects it to the real usage afterwards, so where the limit falls depends on timing, and the refusal can report tokens remaining |
| Max parallel requests (key) | 429 `throttling_error`, `Rate limit exceeded for api_key: <key hash>. Limit type: max_parallel_requests ...`. A slot is freed when a request finishes: 10 requests at once with a limit of 2 saw 2 to 6 pass |
| Model outside the key's list | 403 `key_model_access_denied`, `The requested model '<model>' is not available for this API key ...` |
| Team-member budget | 429 `budget_exceeded`, `Budget has been exceeded! TeamMember=<user_id>:<team_id> ...` |

Also observed:

- Spend records (user and key spend, spend logs, team-member spend) appeared 5 to 18 s after the requests.
- While a request runs, LiteLLM reserves its maximum possible cost against the user's budget (for `acme/coder` about $0.26, the model's maximum output at gpt-4.1 prices), shrunk to what is left of the budget. A user with less budget left than that can have only one request in flight: concurrent ones are refused as `budget_exceeded` while the recorded spend is still under the budget.
- LiteLLM treats `budget_duration: 30d`, the broker's default, as monthly: the budget resets on the first of each month at 00:00 UTC, not 30 days after the user was created, so a user's first period is shorter. `1d` and `7d` are likewise aligned to midnight and to Monday.

## Mock upstream

[`mock-upstream/server.mjs`](mock-upstream/server.mjs) has no dependencies. It answers `GET /v1/models` (`gpt-4.1`, `gpt-4.1-mini`) and `POST /v1/chat/completions`, streaming (server-sent events, with a usage chunk when `stream_options.include_usage` is set) or not. The reply is `Reference mock reply from <model>.`, and token usage is counted from whitespace-separated words, so the same request always gets the same answer.

Failures on request:

| Trigger | Effect |
| --- | --- |
| A user message containing `[mock:status=NNN]` (401, 403, 429, or 5xx) | That request fails with that status and an OpenAI-style error body, every time it is sent, so LiteLLM's retries see the same answer. A 429 carries `retry-after` |
| `POST /__mock/faults` with `{"status": 503, "count": 2, "retryAfter": 1}` | The next `count` completion requests fail, whatever their content |
| `DELETE /__mock/faults` | Clears queued failures |
| `GET /__mock/requests` | Model, stream flag, and status of the last 100 completion requests: what LiteLLM actually sent upstream |

The OpenAI endpoints require `Authorization: Bearer <MOCK_UPSTREAM_API_KEY>`; the `/__mock` control endpoints and `/health` have no authentication, which is why the port is on loopback only.

## Measured startup

On macOS 27.0 arm64 (Apple M4 Max) under OrbStack (Docker Engine 29.4.0, Compose 5.1.2), with the images already present:

| Step | Time |
| --- | --- |
| `docker compose up --wait`, from nothing to all four services healthy | 11.7 s, 12.1 s, and 14.7 s (three runs) |
| LiteLLM healthy after its container started (184 Prisma migrations applied to the empty database) | 8 to 11 s |
| `docker compose down` | 2.5 s |
| Sign-in with `scripts/get-token.mjs` | 0.1 to 0.6 s |
| Non-streaming completion through LiteLLM | about 0.4 s |

All four images have native `linux/arm64` and `linux/amd64` builds; nothing ran under emulation. Image sizes on this machine (compressed / unpacked): Keycloak 266 MB / 756 MB, LiteLLM 398 MB / 1.66 GB, PostgreSQL 115 MB / 416 MB, Node 61 MB / 233 MB. Resident memory when idle: LiteLLM about 810 MiB, Keycloak about 680 MiB, PostgreSQL about 115 MiB, mock about 23 MiB.

These figures are from one developer machine. Running on GitHub's `ubuntu-latest` is proven only by the reference E2E workflow (V07-54), not by this measurement.
