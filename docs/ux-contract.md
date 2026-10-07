# UX contract

> Security controls protect explicit trust boundaries. They must not block normal workflows without a concrete threat model.

This is the rule PiShip applies to every restriction a person can meet. A restriction is user-visible when it refuses, prompts, warns, or removes something a person would otherwise expect to work: a refused command, a withheld resource, an unavailable model, a required flag, a blocked update. Each one must answer four questions, and a restriction that cannot answer them does not ship:

1. **Threat model.** Who is the attacker or what is the failure, and what can it do without the restriction?
2. **Protected boundary.** Which explicit trust boundary does the restriction defend? A boundary is one of identity, credential, policy, the sandbox a distribution requires, artifact integrity, or a line between a person's own data and code that someone else wrote.
3. **Attack or failure prevented.** What exactly stops happening?
4. **Why lower friction is not enough.** What weaker behavior (a warning, a prompt, an opt-in, a default) was considered, and why does it not hold the boundary?

A new restriction adds its row to the table below in the same change. A restriction that blocks a normal workflow and has no concrete answer is removed or turned into a default the person can change.

## What stays easy

These are the personal profile's requirements, and a change that makes one harder needs the four answers above for the added friction:

- **Easy install.** `install` takes a payload, a release directory, or an archive and needs no enterprise service; it verifies what it extracts and refuses only collisions it did not create.
- **Easy authoring.** `piship init` writes a complete personal distribution that validates, locks, builds, and runs; `piship build`, `release`, `dev`, and `test` do not need a checkout of the PiShip source repository: a bundled PiShip carries its authoring inputs as one compressed snapshot it expands into a cache on first use ([performance](performance.md#what-a-release-does-now)).
- **Easy auth and model configuration.** A personal distribution delegates credentials and models to Pi (`credential.provider: pi-native`, `inference.provider: pi-native`) with no identity provider, credential broker, or gateway, and the person keeps Pi's own sign-in.
- **No enterprise infrastructure.** Identity, broker, gateway, audit collector, sandbox, signed update channel, and plain-HTTP opt-ins are all optional in personal mode. A personal manifest is permissive by default (`policy.default: allow`), and the person owns the policy: user rules and `--yolo` relax what the distribution asks.

## What fails closed, and what degrades

A managed distribution fails closed only at an enforced boundary: **identity, credential, policy, a required sandbox, and artifact integrity**. A control that the manifest declares required (`audit.sinks[].required: true`, `mcp.servers.<id>.required: true`, `sandbox.required: true`) is part of the policy and fails the way it says. Everything else degrades: the agent stays available, the failure is reported, and the person can keep working.

| Dependency | When it is unavailable | Result |
| --- | --- | --- |
| Identity provider, credential broker (login, renewal) | Boundary: identity and credential | Fails closed: no sign-in, no credential, no model request (`IDENTITY_EXPIRED`, `CREDENTIAL_EXPIRED`, `CREDENTIAL_REQUIRED`); a refresh that fails while the credential is still valid continues with a notice |
| Policy adapter module, policy rule that cannot load | Boundary: policy | Fails closed (`CONFIG_UNAVAILABLE`) |
| Required sandbox | Boundary: required sandbox | Fails the launch with `SANDBOX_UNAVAILABLE`; there is no unsandboxed fallback |
| Release, payload, or lock that does not verify | Boundary: artifact integrity | Fails closed (`INTEGRITY_FAILED`) |
| Optional audit sink | Not a boundary | Sink is degraded; events dropped and counted; governed actions continue |
| Required audit sink | Declared policy | Buffers; governed actions fail closed only when the buffer is full; reported at shutdown |
| Optional MCP server | Not a boundary | Reported as failed; the session continues without it |
| Capability provider that policy refuses or whose files do not match | Not a boundary | The capability is not effective; PiShip's policy stays in force |
| Data retention sweep | Not a boundary | A warning; the next sweep retries |
| Local metrics file, compile cache, launcher refresh | Not a boundary | Ignored; the launch continues |
| Update channel | Not contacted at launch | `update` fails closed on its own; the installed release runs |
| Inference gateway | Needed to answer | A request fails with a gateway code and is retried by the person. With `inference.liveCatalog: true` the launch lists the gateway's models and fails with `GATEWAY_UNREACHABLE` when it cannot (see [open question](#open-question)) |

### Open question

`inference.liveCatalog: true` makes an unreachable gateway stop the launch, because the catalog fetch throws. The option is off by default and opt-in, and the gateway is the service every request needs, so this is recorded rather than changed here. Degrading to the static catalog and the credential's entitlement would only widen what is offered if the gateway's listing is what narrows it, so the choice belongs to the owner of a distribution with a live catalog and is not made by this release.

## Restrictions and their answers

Rows are grouped by the profile that meets them. "Both" means personal and managed.

### Both

| Restriction | Threat model and protected boundary | Prevented | Why lower friction is not enough |
| --- | --- | --- | --- |
| A manifest or lock with a secret-looking field, or a runtime variable named like one, is rejected | Someone commits `piship.yaml` or `piship.lock`, which are shared and public. Boundary: credential | A credential in a repository or a release | A warning is ignored in a commit; the file travels to every machine and cannot be revoked by deleting it |
| TLS verification is always on; `NODE_TLS_REJECT_UNAUTHORIZED=0` fails the launch; the manifest has no switch | A network attacker between the person and the gateway, broker, or identity provider. Boundary: identity and credential | A forged server and a stolen bearer or refresh token | An opt-out in the manifest would reach every user; a private CA is added to the trust roots instead (`network.tls.additionalCA`) |
| Plain HTTP is accepted only for loopback, or for one endpoint a manifest names with `httpTransport: http-allowed`, to a private or internal host | The same network attacker, on a company LAN without TLS. Boundary: credential and identity | Cleartext tokens, prompts, and tool results to a public host | The opt-in is the lower friction: it exists per endpoint, `validate` warns, and `piship diff` reports it high risk; a global switch would also open public hosts |
| Endpoint URLs may not hold credentials, a query, or a fragment; redirects are not followed | A server or a manifest that sends the credential somewhere unintended. Boundary: credential | A bearer leaking through a URL, log, or redirect to another origin | A redirect carries the request to a host the owner never named; following it is the attack |
| A secret store that is unavailable fails with `SECRET_STORE_UNAVAILABLE`; `system` never falls back to a file; the file store is an explicit opt-in (managed adds `acknowledgePlaintext`) | A machine whose keychain is locked or missing, and any process reading the user's files. Boundary: credential | A credential silently written in plaintext | A silent fallback hides the downgrade; the opt-in is one line and `doctor` reports it |
| Tools never read or write the distribution state directory, and never write the project's git control files (`.git/config`, hooks, and their include targets) | Prompt injection or a malicious repository steering the agent. Boundary: policy and a person's own data | Rewriting trust state, stored credentials, or a git hook that later runs outside any sandbox | A prompt would ask the person to approve an edit they cannot judge; these files decide a project's trust class and what git runs |
| Project items (instructions, skills, agents, hooks, extensions, MCP, providers) from an external or unknown workspace are not loaded by the managed `init` template; the personal one loads instructions and skills, asks before extensions and MCP, and denies hooks, agents, and providers | A repository the person cloned carries code or instructions that run with the person's privileges. Boundary: code from someone else | A repository executing a hook, extension, or MCP server on `cd` | Loading and warning runs the code before the person reads the warning. Relaxing is one line per dimension (`policy.projectTrust`), and a company origin match trusts a person's own repositories |
| An `allow` or `ask` shell rule such as `git *` does not match a command with a shell metacharacter | A rule written for one command being stretched by `;`, `&&`, `$()`. Boundary: policy | `git status; rm -rf ~` passing as `git *` | Matching on a prefix alone is the bug; a rule that spells out the character still matches |
| `read` and `edit` refuse a file over 16 MiB; a command's output is capped at 64 MiB | A huge file or runaway output exhausting the process's memory. Boundary: the person's session | The agent process running out of memory and losing the session | A warning arrives after the process is gone; `bash` (`head`, `sed -n`) reads the part the agent needs |
| A session file that is damaged, over 64 MiB, or owned by another live process is not resumed (`--new-session` starts fresh) | Two processes appending to one session, or a corrupt file. Boundary: the person's own data | A corrupted conversation and lost work | A silent resume could append over another process's file; a new session leaves the old file alone |
| `install` refuses a collision with an install, command, or state it did not create; `uninstall` keeps state; `purge` needs `--yes` and refuses while signed in | Overwriting another program's command or a person's data. Boundary: the person's own data | Data loss and a command hijacked by name | A prompt is not available to a script; `--use-existing-state` and `--yes` are the explicit choices |
| Updates are off until `updates.source` and `updates.trust.bootstrap` are set; an update needs signed channel metadata, refuses a downgrade or replay, and verifies each file as it extracts | A hostile update host or network path. Boundary: artifact integrity | A forged, altered, or replayed release becoming the running code | An unsigned update over HTTPS only trusts the host; the signature is what survives a compromised host |
| Pi packages are resolved with `--ignore-scripts` and a refusing `git`; `piship lock` needs npm 11 or newer when a distribution declares packages | A package whose install step runs code on the owner's machine. Boundary: artifact integrity | Install-time code execution while locking | An older npm runs a git dependency's `prepare` despite the flag; no setting makes npm 10 safe |
| `piship release` stops on an install script PiShip has not reviewed, a package from a source outside `release.sources`, or a vulnerability at `failOn` | A dependency that arrives after the owner reviewed the lock. Boundary: artifact integrity | A release shipping unreviewed code or a known-vulnerable package | A warning in a CI log is not read; the owner can allow an advisory or a source by name |
| Node.js 22.19.0 or newer | Pi and PiShip use APIs older Node versions lack. Boundary: none (a platform requirement) | A launch that fails partway | There is no lower version to support; the shim says so before anything runs |

### Personal

| Restriction | Threat model and protected boundary | Prevented | Why lower friction is not enough |
| --- | --- | --- | --- |
| `--yolo` and auto mode never change a `deny`, project trust prompts, the built-in denials, Plan mode, the sandbox, or audit | An agent following injected instructions. Boundary: policy | Auto-approval widening past what the person declared | The person typed the flag to skip confirmations, not to remove the protections that no confirmation covers |
| A user rule can relax a default but never an enforced rule | A user rule file written by a script or a repository. Boundary: policy | A default the owner meant to hold being undone by a file | The owner has `policy.enforced` for what must hold; everything else is the person's to relax |

### Managed

| Restriction | Threat model and protected boundary | Prevented | Why lower friction is not enough |
| --- | --- | --- | --- |
| Ambient credential variables (`*_API_KEY`, `*_TOKEN`, `AWS_*`, `PI_*`, and the rest) are removed before Pi starts; declared runtime variables stay | A credential in the shell reaching Pi, its tools, and child processes. Boundary: credential | A user's personal key silently used against the company gateway, or leaked into a tool | Passing them through is the default of every tool; the declared-variable list is the opt-in |
| Pi runs with an in-memory credential store, no `models.json` or `auth.json`, and only allowed models | A person's own Pi sign-in or provider being used outside the company gateway. Boundary: credential and policy | Inference to an unapproved provider; a model the policy denies | A warning cannot stop a request that carries company prompts to a provider the company did not approve |
| `network.publicFallback: deny` (private-only) is required, and only declared hosts are reachable | A compromised extension or prompt injection exfiltrating to an arbitrary host. Boundary: policy | Requests to undeclared hosts from Pi's process | It is a hostname allowlist, not a firewall, and says so; it removes the easy exfiltration paths and nothing else is claimed |
| `user` resources and providers are denied by default; a managed user can only narrow policy | A user-supplied extension or rule widening what the administrator set. Boundary: policy | Local code or rules overriding the company's | The administrator can allow a class, or `policy.userAuto: allowed`, per distribution |
| A deny or ask rule on an action without a runtime seam fails `validate` (`POLICY_UNENFORCEABLE`) unless acknowledged | A rule that looks like a control and prevents nothing. Boundary: policy | A false sense of enforcement | A warning reads as acceptance; `policy.acknowledgeUnenforced` is one explicit line, audited as a gap |
| `sandbox.required: true` fails the launch when the sandbox cannot be enforced | A command escaping containment the owner depends on. Boundary: the required sandbox | Running uncontained while the report says contained | A fallback to no sandbox defeats the declaration; the owner sets `required: false` if containment is optional |
| A required audit sink that cannot be opened fails the launch; with a full buffer governed actions stop | An administrator who must have the audit record. Boundary: policy | Governed actions with no record | The owner chose `required`; `required: false` degrades instead |
| A managed release needs an offline root key separate from the channel key | A stolen release key rotating the trust root. Boundary: artifact integrity | One key compromise taking over updates for every install | A shared key makes the threshold meaningless; `validate` and `piship release` say how to split |
| Claude project configuration (`.claude`, `.mcp.json`, hooks) is untrusted unless the company admits it, and a managed session whose origin does not admit hooks keeps the project `.claude` directories read-only | A cloned repository planting executable settings for an extension that reads them itself. Boundary: code from someone else | A hook or MCP server started by a file in a repository | An extension that asks the person is answered from policy; the person's click would open what the company closed |
| A model outside the allowlist is `MODEL_DENIED`; an unentitled one is `MODEL_UNAVAILABLE`; PiShip never substitutes another | A request going to a model the organization did not approve or the credential is not entitled to. Boundary: policy and credential | Silent substitution and a gateway-side surprise | A substitution would send the person's prompt to a different model than they chose |
| A credential and its entitlement are used only by the principal that was issued them; another user's sign-in clears them | A shared machine where one user's credential is used by the next. Boundary: identity and credential | Cross-user credential reuse | Reusing it is the attack; signing in again is the cost |
| `--yolo` is refused unless `policy.userAuto: allowed` | A user opting out of confirmations the administrator wants. Boundary: policy | Auto-approval where the administrator did not allow it | The administrator's opt-in is the only way to get it, and it is one manifest line |
| An MCP server sends the runtime credential only to the gateway's own origin, runs with an allowlisted environment, and starts only after `mcp.server.start` is allowed | A server that is not the gateway receiving a company credential. Boundary: credential and policy | A credential sent to an arbitrary MCP host | A server on another origin has no claim on a gateway credential |

## Maintaining this page

- The rows are derived from [security](security.md), the policy code, and the `init` templates. A restriction found in the code with no row is a defect in this page; a row whose restriction no longer exists is removed with it.
- A restriction that changes its default, or adds a new refusal to a normal workflow, adds or edits its row in the same change, with the four answers.
- A row that cannot answer "why lower friction is not enough" is a candidate for removal.
