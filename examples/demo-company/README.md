# Demo company distribution example

AcmeCode is a fictional managed distribution on `piship/v1alpha2`. It signs users in with OIDC, obtains a runtime credential from an `http-broker`, and sends inference to an OpenAI-compatible gateway with a three-model allowlist, an enforced theme, and private-only networking. It contains no private data or credentials. The endpoints are `ACMECODE_*` runtime variables, so the lock stays machine-independent.

The managed surface is a **candidate**: it is verified with the deterministic local fixtures below, not with a live identity provider or gateway. See [compatibility](../../docs/compatibility.md).

## Deterministic local path

`fixtures/local-services.mjs` starts a loopback OIDC provider, credential broker, and gateway. It auto-approves every sign-in for a fictional demo user and returns canned replies. It is test infrastructure, not a real identity provider, and not evidence of a live integration.

The demo uses the system secret store (`credential.storage.provider: system`). On Linux this needs a running, unlocked Secret Service and `secret-tool`; macOS uses Keychain and Windows uses Credential Manager. Without one, `login` fails with `SECRET_STORE_UNAVAILABLE`. To use the plaintext file fallback instead, edit a copy of this example to set `storage: {provider: file, acknowledgePlaintext: true}`; the example itself does not opt in.

In a first terminal, from the repository root with Node.js 22.19.0 or newer:

```bash
npm ci
npm run build
node examples/demo-company/fixtures/local-services.mjs
```

It prints `export ACMECODE_...=...` lines (`set` lines on Windows) and keeps running. Pass `--port <n>` for a fixed port. In a second terminal, paste those lines, then:

```bash
npm exec -- piship validate examples/demo-company/piship.yaml
npm exec -- piship lock examples/demo-company/piship.yaml
npm exec -- piship build examples/demo-company/piship.yaml
node dist/acmecode/piship.mjs install dist/acmecode
~/.local/bin/acmecode --version
~/.local/bin/acmecode login
~/.local/bin/acmecode --smoke
~/.local/bin/acmecode --smoke-model
~/.local/bin/acmecode models
~/.local/bin/acmecode --model acme/review --smoke   # MODEL_UNAVAILABLE: not entitled
~/.local/bin/acmecode doctor
~/.local/bin/acmecode config explain
~/.local/bin/acmecode logout
node dist/acmecode/piship.mjs uninstall acmecode
```

`login` prints the sign-in URL and opens a browser; the fixture approves it at once and redirects to `http://127.0.0.1:8765/callback`, so that port must be free. Set `PISHIP_NO_BROWSER=1` to only print the URL. Before `login`, `--smoke` fails with `IDENTITY_REQUIRED`. `--smoke` checks Pi startup, declared resources, the read tool, session resume, and the access summary without a model call; `--smoke-model` sends one prompt through the fixture gateway. The declared `enterprise-context` extension adds a `demo_context` tool that reads the token-free enterprise context. `config set theme light` is refused because the theme is enforced; `config set model acme/general` is permitted.

Every branded command resolves the `ACMECODE_*` variables at launch, so keep them set in that shell. The fixture keeps its sessions in memory: after restarting it, run `login` again. `logout` revokes the credential and tokens at the fixture, clears local secrets, and keeps sessions; `node dist/acmecode/piship.mjs purge acmecode --yes` removes the state after uninstall.

## Authorized live path

To try AcmeCode against real services you are authorized to use, set the same variables before `login`:

| Variable | Value |
| --- | --- |
| `ACMECODE_OIDC_ISSUER` | Issuer URL of an OIDC provider |
| `ACMECODE_OIDC_CLIENT_ID` | A public native client (no secret) with Authorization Code + PKCE S256 and the registered redirect `http://127.0.0.1:8765/callback` |
| `ACMECODE_CREDENTIAL_BROKER_URL` | A service implementing the [http-broker protocol](../../docs/credentials.md#http-broker-protocol) |
| `ACMECODE_CREDENTIAL_REVOKE_URL` | Its revoke endpoint |
| `ACMECODE_LLM_GATEWAY_URL` | An OpenAI-compatible gateway base URL that serves `GET /models` and the allowed model IDs |

All URLs must use HTTPS. Because `network.privateOnly` is on, OIDC endpoints that discovery returns on other hosts must be added to `network.allowHosts`, and an enterprise CA goes in `network.tls.additionalCA`; make these changes, and any model ID changes, in a copy, then lock and build it. The project has not yet recorded such a live run.
