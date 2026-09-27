# Security architecture

## Trust boundaries

Upstream Pi executes the agent runtime. PiShip will govern distribution configuration and selected capabilities. A distribution repository may contain company-specific adapters and resources. Local project content and user extensions are less trusted than a managed distribution. These boundaries do not imply enforcement in the current foundation.

## Pi extension execution risk

Pi extensions can execute code with the process's privileges. Future capability governance must distinguish what is allowed from what is actually contained. Installing or loading an extension is a trust decision, and a policy label alone is not a sandbox.

## Secret handling

Manifests and `piship.lock` must never contain API keys, OIDC tokens, gateway credentials, or other secret values. Future manifests may reference secret names. Credentials should enter only through a dedicated future runtime boundary and should not be logged or embedded in artifacts.

## Governance versus containment

Governance expresses allowed behavior; containment requires OS or platform enforcement. PiShip must not claim that an allowlist, policy check, or extension registry prevents malicious code from escaping process privileges. Sandbox support is future work and must state its actual guarantees.

## Pi public API boundary

Only `packages/pi` imports upstream Pi packages, using public exports and an exact production version. This is an upgrade and review boundary, not a security sandbox. The source scanner and compatibility test make accidental deep imports visible.

## Supply chain assumptions

The npm lockfile fixes transitive dependency resolution for `npm ci`. CI runs on GitHub-hosted runners and uses maintained actions. Future builds should add integrity verification, SBOM, provenance, signing, and reviewed release processes. These controls are not implemented today.

## Future identity and credential boundary

Managed access may later use OIDC, a SecretStore, CredentialProvider, and an HTTP credential broker. PiShip should not become an identity provider or LLM gateway. The exact trust and failure behavior must be specified before implementation.

## Current limitations

This repository does not yet parse full manifests, validate a lockfile, launch Pi, isolate runtime state, sandbox extensions, enforce policy, manage credentials, or produce signed artifacts. Security reports should follow [SECURITY.md](../SECURITY.md).
