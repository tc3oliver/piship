# Production validation

This page is the protocol for validating a managed PiShip distribution in production: against the organization's own identity provider, credential broker, LLM gateway, proxy and CA, endpoint controls, and update path. It lists the steps to run, the command for each, what a pass proves, and the only facts a report may carry back to the project. The [status page](status.md#distribution-qualification) records what has been shown so far; the first production consumer's managed path is still **open** there.

The evidence stays with the organization. The project never sees the company's services, a report is voluntary and needs the distribution owner's approval, and a result reaches the status page only without identifiers.

## Before you start

- Pin one exact qualified artifact; do not track `main`. The status page names the [baseline](status.md#v0110-production-validation-baseline), v0.11.0, and the Release qualification run behind it. Install that release's archive, and compare its SHA-256 and its pinned update keys with the values the distribution owner published ([distribution bootstrap](release/trust-root.md#distribution-bootstrap)).
- Use a supported platform: `linux-x64`, `darwin-arm64`, or `win32-x64` with Node.js 22.19.0 or later ([compatibility](compatibility.md)). Native Windows has no sandbox adapter, so a distribution that requires the sandbox fails closed there with `SANDBOX_UNAVAILABLE` ([troubleshooting](troubleshooting.md#prerequisites)).
- Start from a machine that has nothing of the distribution: no install, no state directory, no secret-store entry.
- If the organization prohibits public session export, close the [`/share` gap](#share-and-public-session-export) before the first step.
- Use a throwaway project directory. The authenticated model request sends a real prompt to the real model, and the sandbox step runs commands.

## The sequence

Run the steps in order, on one installed distribution with one install home, state directory, secret store, and Pi session: each step starts from what the one before it left. Stop at the first failure and report it; the later steps depend on what it should have produced.

In the commands, `<command>` is the distribution's branded command, `<id>` its distribution ID, and `piship` the PiShip CLI. A machine without the CLI runs the copy inside the extracted release instead, `node <release-dir>/payload/piship.mjs`.

| # | Step | Run | A pass proves | A failure usually names |
| --- | --- | --- | --- | --- |
| 1 | install | `piship install <archive> --sha256 <hex> --expect-key sha256:<fingerprint>` | The archive is the one the owner published and carries the update keys the owner published. It verifies against its inventory and lock and installs with no collision. | `INTEGRITY_FAILED`, `CONFIG_INVALID` |
| 2 | launch | `<command> version`, `<command> --help`, then, signed out, `<command> --smoke` | The installed command starts and the runtime variables it needs resolve. Signed out, it refuses with `IDENTITY_REQUIRED` before it contacts any service; that refusal is the pass. The interactive session needs a terminal, so the headless `--smoke` is the launch check. | `CONFIG_UNAVAILABLE`, `CONFIG_INVALID`, `SANDBOX_UNAVAILABLE`, `AUDIT_UNAVAILABLE` |
| 3 | OIDC login | `<command> login` | The company identity provider accepts PiShip's Authorization Code with PKCE sign-in: discovery, client registration, the redirect, and the path through the proxy and CA. In a remote shell, forward the redirect port first ([remote shells](identity.md#remote-shells)), or use `flow: device_code`, which needs none ([device code](identity.md#device-code)). | `IDENTITY_REQUIRED`, `IDENTITY_INVALID`, `CONFIG_UNAVAILABLE`, `GATEWAY_UNREACHABLE`, `NETWORK_DENIED`, `TLS_POLICY_VIOLATION` |
| 4 | credential acquire | `<command> --smoke`, then `<command> doctor` | The broker turned the identity into a runtime credential, which is kept in the platform secret store and is valid. The first launch after `login` runs with it; the Credential and Secret Store groups of `doctor` report it. | `CREDENTIAL_ACQUIRE_FAILED`, `CREDENTIAL_DENIED`, `CREDENTIAL_EXPIRED`, `SECRET_STORE_UNAVAILABLE` |
| 5 | model discovery | `<command> models` | The gateway's model list is readable with the brokered credential, and the owner's allowlist and the user's entitlement decide which models are available. | `GATEWAY_UNREACHABLE`, `GATEWAY_PROTOCOL_ERROR`, `CREDENTIAL_REVOKED`, `MODEL_UNAVAILABLE` |
| 6 | authenticated model request | `<command> --smoke-model` | One Pi request, authenticated with the brokered credential, goes through the gateway to the model behind it and comes back with a reply. It sends one acceptance prompt to the selected model. | `GATEWAY_UNREACHABLE`, `GATEWAY_RATE_LIMITED`, `GATEWAY_PROTOCOL_ERROR`, `CREDENTIAL_REVOKED`, `MODEL_DENIED`, `MODEL_INCOMPATIBLE` |
| 7 | session resume | Start `<command>` in the project, send a message, exit, and start `<command>` again there. Headless: run `<command> --smoke` again and read `resumed` in its JSON | The next launch continues the project's most recent session, which still holds the earlier turn, for the same signed-in user. `--new-session` starts another. | `CONFIG_UNAVAILABLE` (a damaged or over-64 MiB session) |
| 8 | doctor | `<command> doctor` (`--json` for a machine-readable report) | Every group reports the state the flow has produced: identity, credential, gateway, secret store, outbound network policy, sandbox, release, and audit. The Policy group reports each rule PiShip cannot enforce and the status of session export, and the Governance group how many actions are `enforced` and the tool exposure, Codemode, and deferred tools in effect; an `unsupported` action is a known gap, not a failed step. The gateway check lists models and contacts no model provider. | The failing group; `AUDIT_UNAVAILABLE`, `MCP_UNHEALTHY` |
| 9 | sandbox command | In Build mode (Plan mode runs no command), ask the agent to run a harmless command in the project, then one that reads a canary file you placed outside the project, and one that writes outside it. Then `<command> doctor` | The agent's commands run inside the required sandbox: the harmless one works, each escape is refused, and the Sandbox group of `doctor` reports containment `enforced`. Without a usable sandbox no command runs. Never use a real key as the canary. | `SANDBOX_UNAVAILABLE`, `POLICY_DENIED` |
| 10 | update | `<command> update --check`, then `<command> update` | The update source answers through the proxy and CA, its signed channel verifies against the installation's pinned trust, and the new release downloads, verifies, and activates. The session, the identity, and the credential come through. | `UPDATE_FAILED`, `INTEGRITY_FAILED`, `NETWORK_DENIED`, `TLS_POLICY_VIOLATION` |
| 11 | rollback | `<command> rollback` | The retained previous release is active again, and the session and the sign-in survive. | `ROLLBACK_FAILED` |
| 12 | logout | `<command> logout` | The broker revoked the runtime credential, the identity provider revoked the tokens, and the secret store holds nothing of the distribution; sessions are kept. The next `<command> --smoke` fails with `IDENTITY_REQUIRED`. A revocation warning is not a pass: the credential may still be valid remotely ([logout and revocation](security.md#logout-and-revocation)). | `SECRET_STORE_UNAVAILABLE` |
| 13 | uninstall | `piship uninstall <id>` | The install and the command are gone; the user's sessions and settings are kept. | The code the command prints |
| 14 | purge | `piship purge <id> --yes` | The state and the secret-store entries it references are removed, so the machine is clean again. It refuses while an identity session or credential is still present, so run `logout` first. | `SECRET_STORE_UNAVAILABLE` |

Steps 10 and 11 apply only when the distribution declares an update source ([update lifecycle](release/update-lifecycle.md)); without one, an installation cannot update and there is nothing to report for them. The codes in the last column are the usual ones, not the only ones; every code PiShip reports, and what to do about it, is in [troubleshooting](troubleshooting.md#error-codes).

The same sequence runs against deterministic fixtures on all three platforms in [`managed-clean-machine`](../tests/e2e/managed-clean-machine.test.ts), and against a live Keycloak, the reference broker, and LiteLLM in the [reference distribution's flow](../examples/enterprise-reference/tests/distribution-flow.test.ts). Neither is evidence for a company's services: that is what this protocol collects ([status](status.md#capability-matrix)).

## What to report

A report covers one step on one operating system and architecture. It carries these fields and nothing else:

| Field | Value |
| --- | --- |
| PiShip version | For example `0.9.1`. `piship verify-release <archive> --json` prints the release's `release.json`, which records it |
| Pi version | The Pi version the same `release.json` records |
| OS | Linux, macOS, or Windows |
| Architecture | `x64` or `arm64` |
| Step | One of the fourteen above |
| Result | `PASS` or `FAIL` |
| PiShip error code | The code of a failure, such as `GATEWAY_UNREACHABLE`. Leave it empty when there is none (a revocation warning has none) |
| Sanitized note | Only when the code does not say enough, in a sentence of generic wording: "the proxy refused the tunnel", "the gateway answered a client error" |

Report the code and never the message. A message can name the host, proxy, path, or user that the failure involved, and the code cannot.

Use the [production evidence issue form](https://github.com/tc3oliver/piship/issues/new?template=production-evidence.yml), which asks for exactly these fields. Report passes as well as failures: a pass is the evidence the status page can count, and a failure is what leads to a fix.

## What never to report

Leave all of the following out of a report, a note, a screenshot, and an attachment, however much it would help:

- raw credentials: API keys, passwords, client secrets, and private signing keys
- tokens: identity, access, refresh, and runtime credentials, authorization codes, and session cookies
- claims: anything read from an identity token or the user-info endpoint, such as group names or tenant IDs
- internal URLs and hosts: the identity provider's issuer, the broker, the gateway, the update source, the proxy, the audit collector, and a path that contains one
- usernames and email addresses, including the home directory path of a user
- model names and IDs, including the gateway's own aliases
- raw logs: terminal output, `doctor` output, `--smoke` JSON, audit logs, session files, and crash records
- company-identifying fields: the company, the distribution or product name where it identifies the company, project and repository names, certificate subjects, and ticket references

Output such as `doctor` and `--smoke` holds several of these. Read it yourself and report only the step, the result, and the code. When in doubt, leave it out.

Editing an issue does not remove what it said: GitHub keeps the edit history. A credential or token that reached an issue, a log, or a transcript is compromised; revoke it first, then tell the maintainers privately ([SECURITY.md](../SECURITY.md)).

## Known upstream limits

PiShip does not patch Pi. These behaviors belong to Pi, and no public Pi switch changes them. They are known and tracked, so they are not a failed step and need no report.

### `/share` and public session export

Pi's built-in `/share` command uploads the session file as a GitHub gist through the user's own `gh` CLI. A session file holds the user's prompts, the model's output, and tool results, so `/share` is a path by which a session can leave the machine, in managed mode too. `gh` is a child process outside PiShip's in-process network policy, so `network.privateOnly` does not apply to it, and PiShip cannot turn the command off ([security](security.md#limits)).

An organization that prohibits public session export therefore needs an endpoint or egress control for it, and this is a requirement of the validation, not an option. Decide it before step 1: for example, keep `gh` off the validation machines, or block `gh` and github.com at the endpoint or the egress proxy. PiShip's `doctor` reports the gap but cannot close it: its Policy group always shows session export `public` (`/share`) and `local` (`/export`) as `unsupported`, whatever the manifest declares ([session export](manifest.md#session-export)). It does not check the endpoint or egress control itself.

### Other upstream-owned limits

- Pi adds its own `/bug` hint to a PiShip identity or credential failure in the TUI ([#139](https://github.com/tc3oliver/piship/issues/139)). The command itself sends its report through PiShip's network policy, so a managed launch, which is private-only, refuses it unless the report service's host is allowed ([security](security.md#network-and-tls)).
- A user's `!` shell command still writes its full output through Pi's temp file, so a temp filesystem that fills while Pi writes it (`ENOSPC`) is not contained ([#64](https://github.com/tc3oliver/piship/issues/64), [security](security.md#tools-shell-and-plan-mode)).
- The terminal title is still "π", and the exit hint still names `pi --session-dir ... --session ...`, a command a distribution's user does not have. The branded command continues the project's most recent session by itself, and `--new-session` starts a new one ([security](security.md#secrets)).

The [status page](status.md#known-limits-and-non-claims) lists these with the rest of the known limits.
