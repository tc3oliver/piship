# Enterprise reference stack

A local, runnable version of the company services a managed PiShip distribution talks to: an OIDC identity provider, an LLM gateway with its database, and a model upstream. It is the tested successor of [`examples/enterprise-litellm`](../enterprise-litellm/README.md), whose LiteLLM config it runs unchanged, and it implements the gateway side of the [enterprise integration contract](../../docs/enterprise-integration.md).

This is reference infrastructure for tests and local exploration, not a production deployment. It includes the [reference credential broker](broker/README.md), [AcmeCode](#acmecode-reference-distribution), a managed distribution wired to the stack, and a [container sandbox](#reference-container-sandbox) that distribution can run its commands in. Nothing here needs an Internet model provider or a paid API key.

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
| Users | `alice` (group `/engineering`) and `bob` (group `/support`). The groups are the input for model entitlement |

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

[`broker/`](broker/README.md) implements PiShip's `http-broker` contract: `POST /v1/credential` with the user's Keycloak access token returns a LiteLLM virtual key limited to the models of the user's groups (`/engineering`: `acme/coder` and `acme/general`; `/support`: `acme/coder`), on one LiteLLM user per `(iss, sub)` with a per-user budget and no team; `POST /v1/revoke` with that key deletes it. It holds the master key and no other secret. `node broker/live-check.mjs` runs the happy path against the stack; `node --test broker/test/*.test.mjs` is its contract test, which needs no Docker.

## Tests against the stack

`npm run test:reference` at the repository root runs the tests that need this stack (Docker with Compose v2, and `npm ci && npm run build` done); `npm test` leaves them out. Each file starts its own copy of the stack and stops it when it ends, also after a failure, so nothing needs to be running first, and no `.env` beside `compose.yaml` is used or written:

- a Compose project of its own, `piship-reftest-<pid>-<file>-<random>`, with the `.env` generated by `scripts/generate-env.mjs` into a temporary directory, `piship-reftest-<pid>-*`, that is deleted afterwards;
- host ports `KEYCLOAK_PORT=28080`, `LITELLM_PORT=24000`, `MOCK_UPSTREAM_PORT=28090`, `POSTGRES_PORT=25432`, `BROKER_PORT=28070` on `127.0.0.1`, so a stack on the default ports can keep running (`gateway-evidence.test.ts` uses 58080, 54000, 58090, 55433 and 58070). Set any of these variables in the environment to use others;
- broker settings for the file (a small budget, rate limits) in a Compose override file beside that `.env`;
- `docker compose up --wait --wait-timeout 300` to start, `docker compose down` to stop, also on Ctrl-C or when vitest terminates the worker.

A worker killed outright cannot stop its stack. Before the next run starts a stack, the suite's global setup (`tests/enterprise-reference/global-setup.ts`) runs `docker compose down` on every `piship-reftest-<pid>-*` project, and deletes every such temporary directory, whose process `<pid>` no longer exists; a run still going on elsewhere keeps its stack. It never removes volumes or prunes.

The files run one at a time. Each took 20 to 80 s on the machine measured below (usage continuity the longest, since it waits for spend records four times), about 15 s of it starting the stack; `gateway-evidence.test.ts` took 170 to 230 s, most of it LiteLLM's and Pi's retry backoff.

| File under `tests/enterprise-reference/` | Shows, from LiteLLM's own records and answers |
| --- | --- |
| `usage-continuity.test.ts` | One employee's credentials A, B and C (minted by the broker from alice's real Keycloak token) accrue one spend total against one user budget; rotating to a fourth key (the broker deletes the oldest, keeping 3) and revoking another keeps the spend, the budget, and its reset date; bob has his own; once alice's spend reaches the budget the gateway refuses her next request on every key, including one issued afterwards, while bob's still pass |
| `gateway-rate-limits.test.ts` | Requests per minute and tokens per minute on the employee's LiteLLM user are enforced by the gateway, on every key of that employee |
| `gateway-concurrency-entitlement.test.ts` | The key's `max_parallel_requests` and its `models` list are enforced by the gateway; refused requests never reach the upstream |
| `team-member-budget.test.ts` | Decision D-01's check: a team-member budget (`max_budget_in_team`) is enforced across all of the member's team keys, while the member's personal budget is not applied to team keys. The broker issues keys without a team; this file sets a team up with the master key |
| `gateway-evidence.test.ts` | How LiteLLM refuses a missing, malformed, unknown, deleted, expired or blocked key, and that PiShip's inference client reads each as `CREDENTIAL_REVOKED`; the installed AcmeCode distribution (signed in as alice) renewing a key the gateway blocked or expired at launch, and reporting `CREDENTIAL_REVOKED` when the broker is down for the renewal; `/v1/models` listing only a key's models, and PiShip offering the intersection of allowlist, entitlement and live list, also in `acmecode-reference models`; a streamed answer (chunks, `stop`, usage, `[DONE]`) and one the upstream cuts; upstream 401, 403, 429 and 5xx through LiteLLM (status, body, retries, cooldown) and how PiShip's status mapping and its in-session reading of Pi's error messages take them, through `acmecode-reference --smoke-model` |

Spend is read with the master key from `/spend/users`, `/spend/logs`, `/user/info`, `/key/info` and `/team/info`, polled until it lands. Tokens, keys and the master key stay in the test's memory; response bodies are scrubbed of key and token shapes before any assertion.

Observed with LiteLLM v1.103.0 and this config (its error bodies for these limits are not documented; the tests assert on the status, the error type and a stable part of the message):

| Limit | Refusal |
| --- | --- |
| User budget | 429 `budget_exceeded`, `Budget has been exceeded! User=<user_id> ...` or `ExceededBudget: User=<user_id> over budget ...`. Immediate: LiteLLM counts spend in memory as requests finish, so the request after the one that reaches the budget is refused, well before the spend records are written |
| Requests per minute (user) | 429 `throttling_error`, `retry-after: 60`, `Rate limit exceeded for user: <user_id>. Limit type: requests. Current limit: <n>, ...`. The window starts at the first request |
| Tokens per minute (user) | 429 `throttling_error`, `retry-after: 60`, `... Limit type: tokens ...`. LiteLLM reserves an estimate (input characters / 4 plus an output allowance) before the request and corrects it to the real usage afterwards, so where the limit falls depends on timing, and the refusal can report tokens remaining |
| Max parallel requests (key) | 429 `throttling_error`, `Rate limit exceeded for api_key: <key hash>. Limit type: max_parallel_requests ...`. A slot is freed when a request finishes: 10 requests at once with a limit of 2 saw 2 to 6 pass while the mock answered in milliseconds, and exactly 2 when each is held 500 ms (`[mock:delay=500]`), as the test does |
| Model outside the key's list | 403 `key_model_access_denied`, `The requested model '<model>' is not available for this API key ...` |
| Team-member budget | 429 `budget_exceeded`, `Budget has been exceeded! TeamMember=<user_id>:<team_id> ...` |

Gateway authentication and upstream failures, observed the same way (`gateway-evidence.test.ts` pins each body):

| Case | LiteLLM's answer | PiShip |
| --- | --- | --- |
| No key, malformed key (no `sk-`), blocked key | 401 `auth_error`, `Authentication Error, No api key passed in.`, `LiteLLM Virtual Key expected. Received=<masked>, expected to start with 'sk-'.`, `Authentication Error, Key is blocked. ...` | `CREDENTIAL_REVOKED` from the model list; at launch the stored key is renewed once |
| Unknown or deleted key | 401 `token_not_found_in_db`, `Authentication Error, Invalid proxy server token passed. Received API Key = sk-...<last 4>, Key Hash (Token) =<hash>. Unable to find token ...` | as above |
| Expired key | 401 `expired_key`, `Authentication Error - Expired Key. Key Expiry time <time> and current time <time>`, `param` the key's last four characters | as above |
| Upstream 401 | 401 `authentication_error`, `litellm.AuthenticationError: ... Incorrect API key provided.. Received Model Group=<model> ...`, no retry; the deployment is then cooled down for 5 s | `GATEWAY_UNREACHABLE`, not retryable (the provider refused, by the `litellm.` prefix); in a session the credential is not marked rejected and not renewed |
| During that cooldown, any key | 429 `all_deployments_in_cooldown`, `retry-after: 5`, `No deployments available for selected model, Try again in 5 seconds. ...`; not sent upstream | `GATEWAY_RATE_LIMITED`, retry after 5 s |
| Upstream 403 | 403 `permission_error`, `litellm.APIError: ...`, after 3 attempts | `GATEWAY_UNREACHABLE`, not retryable; not a model denial, so no entitlement re-read (which would mint a new key). The gateway's own model denial, `key_model_access_denied`, stays `MODEL_DENIED` |
| Upstream 429 | 429 `throttling_error`, `litellm.RateLimitError: ...`, after 3 attempts; the upstream `retry-after` only as `llm_provider-retry-after` | `GATEWAY_RATE_LIMITED`, retry time from `llm_provider-retry-after` (1 s here); Pi retries |
| Upstream 500, 502, 503, 504 | That status, `internal_server_error`, `litellm.InternalServerError`, `BadGatewayError`, `ServiceUnavailableError`, `Timeout`, after 3 attempts (4 to 5 s); no cooldown | `GATEWAY_UNREACHABLE`, retryable; Pi retries 3 times |
| Stream cut by the upstream | 200, the chunks sent so far, then `data: {"error": {"message": "litellm.APIConnectionError: ... Response payload is not completed ...", "type": null, "code": "500"}}` and no `[DONE]`; not retried | Pi retries; if it persists, the request ends as an error with the partial text, never as an answer |

In a session Pi sends the request, and its error message is the status and LiteLLM's error object (`503: {"message": ...}`), or the message alone for a stream error event. `--smoke-model` reports a failed request with the code of that status and body (an upstream 503 or 401 is `GATEWAY_UNREACHABLE`), and a stream error event, which has no status, as `GATEWAY_PROTOCOL_ERROR`. `GET /v1/models` never reaches the upstream: LiteLLM answers it from its own configuration. The launch check and `doctor` (`reachable (<n> listed; model providers not contacted)`) therefore show the gateway reachable and the key accepted, and an upstream failure appears only when a request is sent, as in this table; `gateway-evidence.test.ts` checks that the model list stays 200 while the upstream fails.

Also observed:

- Spend records (user and key spend, spend logs, team-member spend) appeared 5 to 18 s after the requests.
- While a request runs, LiteLLM reserves its maximum possible cost against the user's budget (for `acme/coder` about $0.26, the model's maximum output at gpt-4.1 prices), shrunk to what is left of the budget. A user with less budget left than that can have only one request in flight: concurrent ones are refused as `budget_exceeded` while the recorded spend is still under the budget.
- LiteLLM treats `budget_duration: 30d`, the broker's default, as monthly: the budget resets on the first of each month at 00:00 UTC, not 30 days after the user was created, so a user's first period is shorter. `1d` and `7d` are likewise aligned to midnight and to Monday.

## Mock upstream

[`mock-upstream/server.mjs`](mock-upstream/server.mjs) has no dependencies. It answers `GET /v1/models` (`gpt-4.1`, `gpt-4.1-mini`) and `POST /v1/chat/completions`, streaming (server-sent events, with a usage chunk when `stream_options.include_usage` is set) or not. The reply is `Reference mock reply from <model>.`, and token usage is counted from whitespace-separated words, so the same request always gets the same answer.

Failures and delays on request:

| Trigger | Effect |
| --- | --- |
| A user message containing `[mock:status=NNN]` (401, 403, 429, or 5xx) | That request fails with that status and an OpenAI-style error body, every time it is sent, so LiteLLM's retries see the same answer. A 429 carries `retry-after` |
| A user message containing `[mock:delay=MS]` (0 to 10000) | That request is answered MS milliseconds late (with the failure above, if both are given), so it holds a gateway concurrency slot for that long |
| A user message containing `[mock:cut=N]` (1 to 50) in a streamed request | The stream stops after its first N events: the connection is closed with no `finish_reason`, usage chunk, or `[DONE]`, as an upstream failing mid-answer does. A request that is not streamed is answered normally |
| `POST /__mock/faults` with `{"status": 503, "count": 2, "retryAfter": 1}` | The next `count` completion requests fail, whatever their content |
| `POST /__mock/faults` with `{"cut": 3, "count": 1}` | The next `count` streamed completion requests are cut after 3 events |
| `POST /__mock/faults` with `{"toolCall": {"name": "bash", "arguments": {"command": "ls"}}, "count": 1}` | The next `count` streamed completion requests are answered with that tool call (finish reason `tool_calls`) instead of text. A client that runs tools sends the result back as its next request, which takes the next queued call or, with the queue empty, the plain reply; queue several calls, in order, to script several turns. A client that only sends its own prompt cannot put a marker in a message, so this queue is how a test makes the mock ask for a tool. A request that is not streamed is answered normally |
| `DELETE /__mock/faults` | Clears queued failures |
| `GET /__mock/requests` | Model, stream flag, status, `cut` (when cut), and `toolCall` (the tool's name, when one was asked for) of the last 100 completion requests: what LiteLLM actually sent upstream |

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

These figures are from one developer machine. Running on GitHub's `ubuntu-latest` is proven by the [Reference E2E workflow](#reference-e2e-workflow), which records its own pull and startup times in the run's job summary.

## AcmeCode reference distribution

[`piship.yaml`](piship.yaml) is a managed AcmeCode distribution (`piship/v1alpha4`) wired to this stack, locked in [`piship.lock`](piship.lock). It has the shape of [`examples/demo-company`](../demo-company/README.md): the same sections in the same order, the same `acme-engineering` policy without its handbook rules, the required OS sandbox, a local audit sink, and the signed-channel and release sections. It points at the stack instead of the demo's loopback fixtures:

| Section | Value |
| --- | --- |
| `app` | ID `acmecode-reference`, command `acmecode-reference`. Both differ from the demo company's `acmecode`, so the two never share a state directory, secret-store entries (`piship:<id>:*`), or launcher; the broker serves this ID (`BROKER_DISTRIBUTION` in `compose.yaml`), and model IDs in the Pi runtime read `acmecode-reference/<model>` |
| `identity.oidc` | Issuer `${ACMECODE_OIDC_ISSUER}` (the Keycloak realm), public client `acmecode`, scopes `openid profile email`, redirect `http://127.0.0.1/callback` (port-less, so PiShip listens on an ephemeral loopback port and Keycloak matches it) |
| `credential` | `http-broker` at `${ACMECODE_CREDENTIAL_BROKER_URL}` with revoke at `${ACMECODE_CREDENTIAL_REVOKE_URL}` (the reference broker), stored in the platform secret store (`provider: system`) |
| `inference` | `openai-compatible` at `${ACMECODE_LLM_GATEWAY_URL}` (LiteLLM), with the live model catalog |
| `models` | Upper bound `acme/coder` and `acme/general`, LiteLLM's `model_name` values. The broker narrows it per user (below) |

The URLs are runtime variables, so the lock is the same whatever ports the stack uses. For a stack started with the default `.env`:

| Variable | Value |
| --- | --- |
| `ACMECODE_OIDC_ISSUER` | `http://127.0.0.1:18080/realms/piship-reference` |
| `ACMECODE_CREDENTIAL_BROKER_URL` | `http://127.0.0.1:18070/v1/credential` |
| `ACMECODE_CREDENTIAL_REVOKE_URL` | `http://127.0.0.1:18070/v1/revoke` |
| `ACMECODE_LLM_GATEWAY_URL` | `http://127.0.0.1:14000/v1` |

`ACMECODE_UPDATE_SOURCE` is read only by `update`. Use the ports in your `.env` if you changed them.

A manifest cannot reach outside its own directory (resource paths start with `./` and may not contain `..` or symlinks), so this distribution cannot reuse the demo's resources by path. [`resources/`](resources) is a copy of the two it needs, the company instructions and the `acme-review` skill. It leaves out the demo's handbook MCP server, certified skill, and enterprise-context extension: none of them touches the stack. The release targets are Linux x64 and macOS arm64: the stack runs in Linux containers and the required sandbox has an adapter on those two only. The manifest pins no release key, as the demo does; a release is built from a copy that pins one (`piship keygen`).

### Users and entitlements

Sign in as `alice` or `bob`; their passwords are `REFERENCE_ALICE_PASSWORD` and `REFERENCE_BOB_PASSWORD` in `.env`. Keycloak's groups become model entitlement at the broker, so the two users get different keys and different `models` lists from the same distribution:

| User | Group | Models |
| --- | --- | --- |
| `alice` | `engineering` | `acme/coder`, `acme/general` |
| `bob` | `support` | `acme/coder` |

For Bob, `--model acme/general` is refused by PiShip with `MODEL_UNAVAILABLE` (not included in the runtime credential entitlement), and a request for it with his key is refused by LiteLLM with `key_model_access_denied`. Signing in as the other user, without a logout, revokes the first user's key at LiteLLM and their identity tokens at Keycloak, and clears their model selection.

### Try it

With Node 22.19 or later and Docker, from the repository root:

```sh
npm ci
npm run build
( cd examples/enterprise-reference && node scripts/generate-env.mjs && docker compose up --wait )

export ACMECODE_OIDC_ISSUER=http://127.0.0.1:18080/realms/piship-reference
export ACMECODE_CREDENTIAL_BROKER_URL=http://127.0.0.1:18070/v1/credential
export ACMECODE_CREDENTIAL_REVOKE_URL=http://127.0.0.1:18070/v1/revoke
export ACMECODE_LLM_GATEWAY_URL=http://127.0.0.1:14000/v1

npm exec -- piship build examples/enterprise-reference/piship.yaml
node dist/acmecode-reference/piship.mjs install dist/acmecode-reference
~/.local/bin/acmecode-reference login              # sign in as alice on the Keycloak page
~/.local/bin/acmecode-reference models
~/.local/bin/acmecode-reference --smoke-model
~/.local/bin/acmecode-reference login              # sign in as bob, without a logout
~/.local/bin/acmecode-reference models             # acme/general is no longer available
~/.local/bin/acmecode-reference logout
node dist/acmecode-reference/piship.mjs uninstall acmecode-reference
( cd examples/enterprise-reference && docker compose down )
```

The launcher is named `acmecode-reference` (`app.command`), so it installs beside the demo company example's `acmecode` without replacing it, and uninstalling one leaves the other. The two share nothing: the launcher, and the state and secret-store entries (kept apart by the distribution ID, `acmecode-reference`), differ. The reference tests read the command from the manifest.

`login` prints the sign-in URL and opens a browser; `PISHIP_NO_BROWSER=1` only prints it. The credential is stored with the platform secret store: the macOS Keychain, or the Linux Secret Service (it needs a running, unlocked keyring and `secret-tool`). Without one, `login` fails with `SECRET_STORE_UNAVAILABLE`. To use the restricted plaintext file store, edit a copy of the manifest to `storage: {provider: file, acknowledgePlaintext: true}`, run `piship lock` on it, and build the copy.

### Tests

`npm run test:reference` (after `npm run build`, with Docker running) runs the tests in [`tests/`](tests), each against a stack it starts and removes itself:

| File | What it runs |
| --- | --- |
| [`distribution-flow.test.ts`](tests/distribution-flow.test.ts) | The managed clean-machine flow of decision D-11 for one user: build from the committed lock, install, sign Alice in on the real Keycloak authorization page (PKCE `S256`, loopback redirect), credential exchange at the broker (checked against LiteLLM's own key record), storage in the secret store, `models`, `--smoke-model` (streamed through LiteLLM to the mock upstream), session resume, renewal of a key the gateway rejected, `doctor`, commands the model asks for (queued at the mock upstream as tool calls) run inside the sandbox, with each escape refused, `update` through a signed channel and `rollback` (session, identity, and credential kept), a scan of the state directory, install home, and output for every secret, `logout` (key and identity tokens revoked, store empty), and `uninstall` and `purge` (store empty, audit trail in order). The copy of the distribution it installs allows shell commands in Build mode and pins a release key of its own (the committed manifest asks before each command and pins none); the update host is a loopback directory |
| [`user-switching.test.ts`](tests/user-switching.test.ts) | Alice to Bob without a logout: Alice's key and identity tokens revoked, Bob gets none of her key, entitlement, model selection, or history, and no trace of her secrets is left; a model Bob is not entitled to is refused by PiShip and by the gateway; Alice signs back in to a new key and her own history; and a distribution whose model list is narrower than the entitlement stays narrower |

Each file starts its stack under a Compose project of its own, `piship-reftest-<pid>-distribution-<random>`, as the files under `tests/enterprise-reference/` do, on loopback ports 38080 (Keycloak), 34000 (LiteLLM), 38090 (mock), 35432 (PostgreSQL), and 38070 (broker), so they run beside a stack on the default ports. Set `KEYCLOAK_PORT`, `LITELLM_PORT`, `MOCK_UPSTREAM_PORT`, `POSTGRES_PORT`, `BROKER_PORT` to change the ports. The generated env file and the installed distribution live in temporary directories named `piship-reftest-<pid>-*`. The stack is stopped and the directories removed when the file ends, when the worker exits, and on Ctrl-C or termination; a worker killed outright leaves them to the suite's global setup, which removes them at the start of the next run. A second run at the same time fails to bind the ports rather than stopping the first run's stack. The tests never print a token, key, or password.

Secret store: the platform store writes to the login keychain or keyring of whoever runs the tests, so, like the platform-store test, the tests use it only with `PISHIP_LIVE_SECRET_STORE=1` (the CI check jobs set it) and then never fall back to a file. On macOS they refuse it unless `CI` is also set: the Keychain is resolved through the real `HOME`, which cannot be isolated, so on a developer's Mac the run would write to and delete from that user's login keychain. Without it, they build a copy of the distribution with the restricted plaintext file store; the store in use is named in the title of the credential test and in the first line of the output. On macOS in CI the platform-store run keeps the real `HOME`; every other run isolates `HOME`. The distribution's own ID keeps its entries apart from those of an installed `acmecode`.

Measured on macOS 27.0 arm64 (Apple M4 Max) under OrbStack with the images already present and the file store: `distribution-flow.test.ts` 47 s and `user-switching.test.ts` 62 s, each including the stack start and stop. A platform-store run on macOS (`PISHIP_LIVE_SECRET_STORE=1`) has not been recorded: the Keychain refuses writes from a session without user interaction, and then the tests fail with `SECRET_STORE_UNAVAILABLE` instead of using a file. The Reference E2E workflow runs the tests on Ubuntu with the Linux Secret Service.

## Reference container sandbox

[`sandbox/`](sandbox/README.md) is the custom sandbox of the reference distribution, written the way an organization that runs its own sandbox service would write it. The [service](sandbox/service/server.mjs) (Node built-ins and the `docker` command line, `127.0.0.1` only) starts a container per session for the user whose key asked, with the user's project bind-mounted at `/workspace`; the [adapter](sandbox/acme-container-sandbox.mjs) is one file on `@piship/adapter-sdk` that lets PiShip use it. Its workspace is `shared`, so the agent's file tools and its shell see the same files, and PiShip verifies that before the first command of a session.

The reference manifest above is unchanged: it keeps the native OS sandbox. The variant is a second manifest and lock, [`sandbox/piship.yaml`](sandbox/piship.yaml), in a directory of its own (a lock is `piship.lock` next to its manifest, and a manifest cannot reach outside its directory). It is the reference manifest with `sandbox.provider: custom`, the adapter, `endpoint: ${ACMECODE_SANDBOX_URL}`, and `credential: stored`, and one more runtime variable; a unit test keeps everything else equal to the reference manifest, and the lock is kept current by the example-lock test. It is the same distribution, with the same ID, command, and state: install this build or the other.

| Part | What it shows |
| --- | --- |
| Credential | `sandbox.credential: stored`: each user runs `sandbox login` and enters the API key the organization issued (`sandbox/scripts/generate-key.mjs`, which records only a hash). PiShip binds it to the signed-in user and to the origin of the endpoint; the adapter sends it only there, and reports a 401 so PiShip marks it rejected. The service answers 401 without it and gives a user only that user's sandboxes ([why stored](sandbox/README.md#the-credential)) |
| Isolation | An unprivileged container of the workspace owner's user: no capabilities, no new privileges, a read-only root filesystem, resource limits, no network when the profile denies it, only the workspace mounted, and `.git` read-only so no git control file can be changed. It is a container, not a VM, and shares the host's kernel ([what it does and does not isolate](sandbox/README.md#what-it-does-and-does-not-isolate)) |
| Workspace | Declared `shared`; PiShip's two-way sentinel finds both directions immediate, and its git control probe finds every protected path read-only |
| Conformance | The [sandbox conformance kit](../../docs/adapter-sdk.md#sandbox-conformance-kit) passes all 16 behaviors against the service with real containers: none failed, none skipped |

The kit's behaviors, all `passed`: availability, capabilities, prepare, execute, environment filtering, secret leakage, filesystem claims, network claims, timeout, cancellation, cleanup, dispose, fail-closed behavior, workspace consistency, git control protection, workspace re-check. The kit is not vacuous against this service: seeded by hand while the service was written, a writable `.git` mount failed only `git control protection`, a network that stayed on with the profile denying it failed only `network claims`, and a cancel that only killed the `docker exec` client failed `timeout` and `cancellation`. No test seeds them again; each is pinned by its own test instead ([which](sandbox/README.md#conformance)).

[`tests/sandbox.test.ts`](tests/sandbox.test.ts) runs it all, without the stack, with `npm run test:reference` (Docker required): the service as a user starts it on `127.0.0.1:48075` with keys from `generate-key.mjs`, the container as `docker inspect` shows it, the kit, and a governed session opened on the payload built from the committed manifest and lock, whose first sandboxed command is preceded by the workspace check. Measured on macOS 27.0 arm64 (Apple M4 Max) under OrbStack (Docker Engine 29.4.0): the file takes 85 to 120 s (other work was running on the machine), of which the kit is about 25 to 30 s and the build of the distribution about 12 s. Its containers carry the service's instance label, `piship-reftest-<pid>-sandbox-<random>`, and are removed when the file ends, also after a failure; the reference suite's global setup removes those of a run killed outright, and the service such a run leaves exits by itself, removing its containers, because the test owns it through a pipe (`SANDBOX_EXIT_ON_STDIN_END=1`) and a start refuses to count an answer that names another instance. The contract tests (`node --test test/*.test.mjs` in `sandbox/`) need no Docker.

## Reference E2E workflow

[`.github/workflows/reference-e2e.yml`](../../.github/workflows/reference-e2e.yml) (`Reference E2E`) runs everything above on a clean `ubuntu-latest` runner. It is part of `Release qualification`, whose `Release candidate` waits for it, and also runs nightly and by `workflow_dispatch`; it is not a pull request gate. One job, in order:

1. Install bubblewrap (AcmeCode requires the OS sandbox) and GNOME Keyring with `secret-tool`, then `npm ci` and `npm run build`.
2. Generate an `.env` outside the workspace, pull the images, `docker compose up --wait --wait-timeout 300`, and run `node broker/live-check.mjs` against the stack. The pull and startup times go into the job summary. The stack is then stopped and its `.env` deleted.
3. `node --test test/*.test.mjs` in `broker/`, the broker's contract tests, `node --test scripts/test/*.test.mjs`, the log scrubber's tests, `node --test mock-upstream/test/*.test.mjs`, the mock upstream's queued tool calls, and `node --test test/*.test.mjs` in `sandbox/`, the [container sandbox](#reference-container-sandbox)'s contract tests
4. `npm run test:reference` on a private D-Bus session with an unlocked GNOME Keyring, set up as in the `CI` check job, and `PISHIP_LIVE_SECRET_STORE=1`: AcmeCode stores its credential in the Linux Secret Service and fails with `SECRET_STORE_UNAVAILABLE` rather than use a file. It runs `tests/sandbox.test.ts` too, which needs no stack: it starts the container sandbox service and its own containers.

Every step that can hang has a `timeout-minutes`. When a step fails, the run uploads `reference-e2e-logs` (kept 14 days): the container logs of the step-2 stack and of every stack a test file started, and the log of the sandbox service. The workflow's stack and the test stacks write their logs only through [`scripts/scrub-logs.mjs`](scripts/scrub-logs.mjs), which replaces every value of 8 characters or more in the stack's `.env` except the ports (every generated secret is 36 characters or longer), anything shaped like a LiteLLM key (`sk-...`), a JWT, or a `Bearer` or `Basic` authorization value, and the value of an OAuth `code`, `state`, or `session_state` parameter. It knows these shapes only: it is a filter for this stack's logs, not a general secret scanner. The `.env` itself is never uploaded. The tests keep logs only when `PISHIP_REFERENCE_LOG_DIR` names a directory, one file per stack, `<project>-<time>.log`; the workflow sets it. A failed nightly run opens or updates the `Nightly Reference E2E is failing` issue.

What the job does not cover: the update host and its signing key belong to the test, not to the stack, so `update` and `rollback` prove PiShip's lifecycle on an installed distribution that signs in against the live stack, not anything of the stack; the commands the sandbox runs are scripted through the mock upstream, so they prove the sandbox and the policy, not what a real model would ask for. The same flow runs against local fixtures on Linux, macOS, and Windows (where the sandbox step is reported as not run, since Windows has no native sandbox backend) in Portable E2E.

## Live provider qualification

Everything above runs against the mock upstream. [`.github/workflows/live-provider.yml`](../../.github/workflows/live-provider.yml) (`Live provider`) routes the reference LiteLLM to a real model provider instead and sends one request through AcmeCode, to show that the gateway path works with a live provider. It depends on the provider's availability and a paid key, so it runs only when a maintainer dispatches it: it is not part of the pull request gate, of Reference E2E, or of Release qualification, and its result is evidence only in that run's job summary.

The live routing is two files beside `compose.yaml`, which stays unchanged:

| File | Role |
| --- | --- |
| [`compose.live-provider.yaml`](compose.live-provider.yaml) | Compose override: mounts the config below in place of `../enterprise-litellm/litellm-config.yaml` and passes the `LIVE_PROVIDER_*` variables to LiteLLM. Selected with `COMPOSE_FILE=compose.yaml:compose.live-provider.yaml` or a second `-f` |
| [`litellm-live-provider.yaml`](litellm-live-provider.yaml) | The enterprise-litellm config with `acme/coder` and `acme/general` both routed to `LIVE_PROVIDER_MODEL` at `LIVE_PROVIDER_BASE_URL` with `LIVE_PROVIDER_API_KEY` |

| Variable | Contents |
| --- | --- |
| `LIVE_PROVIDER_API_KEY` | The provider's API key. Required; read from the environment of the command that starts the stack, never from a file |
| `LIVE_PROVIDER_BASE_URL` | The provider's API base URL. Default `https://api.openai.com/v1`; set it for any other provider |
| `LIVE_PROVIDER_MODEL` | A LiteLLM model string, whose prefix picks the protocol: `openai/<model>` for OpenAI or any OpenAI-compatible API, `anthropic/<model>` for Anthropic. Default `openai/gpt-4.1-mini` |

The workflow reads the three from secrets of the same names, into the environment of its one request step only. That step runs [`tests/live-provider.test.ts`](tests/live-provider.test.ts), which is skipped unless `PISHIP_LIVE_PROVIDER=1`: it starts the stack with the override, installs AcmeCode, signs Alice in on Keycloak, acquires her key at the broker, runs `acmecode-reference --model acme/coder --smoke-model` (the prompt asks for a short greeting), checks for a non-empty reply that ended with `stop`, and signs out. AcmeCode's environment never holds a `LIVE_PROVIDER_*` variable. The test writes the gateway model, exit status, stop reason, reply length, and request time to `PISHIP_LIVE_PROVIDER_RESULT`, never the reply, the provider, or its model, and the workflow puts them in the job summary.

Dispatch inputs:

| Input | Effect |
| --- | --- |
| `provider` | The provider name shown in the job summary. Free text; nothing else uses it |
| `redact-provider` | Default `true`: the summary shows `redacted` instead of the name. The summary is the only place the workflow writes the name, so this covers everything the run prints; the inputs themselves are visible on the run page whatever this says, so leave `provider` empty when the name must not appear at all |

The job log of a public repository is public, so the workflow prints nothing derived from the provider. When a provider answers with an error, LiteLLM's logs and AcmeCode's output name the provider, its host, and its model in forms (`OpenAIException`, a model name without its `openai/` prefix, `api.openai.com`) that secret masking and [`scripts/scrub-logs.mjs`](scripts/scrub-logs.mjs) do not catch. So no step prints or uploads container logs, the test never puts AcmeCode's output or the provider's key in a failure message, and a failed run shows only the test's messages, the result JSON, and the container states. To find out why a request failed, run the test locally.

### Protecting the provider key

A repository secret is available to a run of this workflow from any branch, so the three secrets live in the GitHub environment `live-provider` instead, and the `live` job names it (`environment: live-provider`). Set it up once:

1. In the repository's Settings, Environments, create the environment `live-provider`.
2. Under Deployment branches and tags, allow only protected branches (or Selected branches with `main`). Optionally add a required reviewer, so every run waits for approval.
3. Add `LIVE_PROVIDER_API_KEY` and `LIVE_PROVIDER_MODEL`, and optionally `LIVE_PROVIDER_BASE_URL` (the default is `https://api.openai.com/v1`), as secrets of that environment, and keep no repository secret of the same names.

The environment must exist and be restricted before the first run: a job that names an environment that does not exist makes GitHub create it without protection rules. A run from a branch the environment does not allow is refused before any step starts.

To run it locally, with Docker and after `npm run build`, set the variables and `PISHIP_LIVE_PROVIDER=1` for `npx vitest run --config vitest.reference.config.ts examples/enterprise-reference/tests/live-provider.test.ts` at the repository root, without printing the key or leaving it in your shell history. It uses the same ports and project as the other tests in `tests/`.

