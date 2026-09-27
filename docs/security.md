# Security architecture

## Trust boundaries

Upstream Pi executes the agent runtime. PiShip validates distribution inputs and controls the initial resource set. A distribution repository supplies executable extensions and instructions. Local project content remains less trusted than a curated distribution. The current slice is not a sandbox.

## Current isolation

The launcher passes Pi an explicit state directory under `~/.piship/<id>` (or `PISHIP_STATE_HOME/<id>`), a separate session directory, in-memory settings, and a `DefaultResourceLoader` that discovers from built distribution resources rather than the user's project or personal `~/.pi`. Declared instructions, skills, extensions, and prompts are copied into the build. Resource file hashes are checked when the launcher starts. CI checks that its smoke path does not create `~/.pi`.

This is configuration and state isolation, not process containment. A declared extension executes with the user's process privileges and can read files available to that user. The user project remains the agent's working directory. Project content and tool execution may still affect the agent. Distributions must review extensions before declaring them.

## Secrets

The manifest and `piship.lock` contain no secret values or environment substitutions. They may be committed to Git. Do not include API keys, OIDC tokens, gateway credentials, proprietary source, or sensitive logs in issues or build resources. The alpha launcher has no credential broker; any provider setup is local to the isolated Pi state.

## Governance and containment

An allowlist or policy label does not contain malicious code. Future governance must distinguish approval from OS enforcement. PiShip does not yet sandbox extensions, enforce policy, or manage identity and credentials.

## Pi public API and supply chain

Only `packages/pi` imports upstream Pi, through the public entrypoint and an exact pin. This boundary localizes upgrades; it is not a security sandbox. `npm ci` fixes transitive resolution from `package-lock.json`. The current build is checkout-local and not signed or packaged. SBOM, provenance, signing, and release verification are future work.

Security reports follow [SECURITY.md](../SECURITY.md).
