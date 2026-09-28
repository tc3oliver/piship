# Architecture decisions

These decisions constrain every change to PiShip. Each names where it is enforced; a change that would break one needs an explicit, reviewed update to this file first.

| # | Decision | Enforced by |
| --- | --- | --- |
| 1 | Pi stays upstream. No fork, vendored copy, source patch, or private import. | `scripts/check-boundaries.mjs` (only `packages/pi` imports Pi, public entrypoint only); [compatibility](compatibility.md) |
| 2 | PiShip is open source and company-first. A first production consumer proves the managed model but does not own the generic API; personal mode reuses the same contracts. | Public examples are neutral (`examples/demo-company`, `examples/personal`); consumer-specific code lives in its own distribution repository |
| 3 | The manifest declares static intent, the lock records resolved static facts, and runtime diagnostics report dynamic state. | `@piship/schema`, the `piship.lock` builder in `@piship/core`, `doctor` |
| 4 | Identity, runtime credential, and inference are separate contracts, and identity may be absent. | `IdentityProvider`, `CredentialProvider`, `SecretStore`, `InferenceProvider` in `@piship/contracts`; `identity`, `credentials`, and `inference` may import only `contracts` |
| 5 | Runtime credentials never live in ordinary configuration. PiShip-managed secrets use a secret store and process- or provider-scoped injection; Pi-native auth is an explicit personal delegation. | Schema secret checks; `SecretValue` redaction; [credentials](credentials.md) |
| 6 | In managed gateway profiles, upstream provider and gateway administration credentials stay server-side; the device holds only a scoped runtime credential. | `http-broker` protocol; [security](security.md#guarantees-and-their-limits) |
| 7 | Pi resources and PiShip capability providers are separate; ordinary extensions are not wrapped in a capability contract. | `resources` and `capabilities` manifest sections; [manifest](manifest.md) |
| 8 | Managed mode disables ambient inheritance: undeclared global or project resources and personal credentials do not load. | Resource loader with discovery disabled; managed environment sanitizing; in-memory model credentials |
| 9 | When distribution policy governs resources and instructions, PiShip owns discovery. | Governance session resource admission and project trust in `@piship/policy` |
| 10 | Governance is not containment. Permission hooks never replace an OS or process sandbox. | Separate `@piship/sandbox`; [security](security.md#limits) |
| 11 | Every decision names its enforcement plane: `control-plane`, `sandbox`, or `audit-only`, and an audit-only decision is never reported as prevented. | `PolicyDecision.enforcement`; `policy explain` |
| 12 | Capability state has six independent axes: supported, resolved, enabled, compatible, healthy, effective. | `@piship/policy` capability state; `capabilities` |
| 13 | Reproducibility covers the static envelope; entitlements and remote health are never lock facts. | Lock builder; `piship reproducibility`; release-candidate workflow |
| 14 | Standard protocols first: OIDC and OAuth, and OpenAI-compatible inference, before organization-specific adapters. | `@piship/identity`, `@piship/inference` |
| 15 | PiShip does not implement OIDC or JWT cryptography; it uses a maintained library. | `openid-client` in `@piship/identity` |
| 16 | Runtime credentials are never rollback state. Rollback may require signing in again; it never restores a secret. | Update and rollback credential handling in `@piship/core`; lifecycle E2E |
| 17 | A private-only profile never silently contacts an undeclared public endpoint. | Managed fetch and `network.privateOnly` in `@piship/contracts` |
| 18 | PiShip owns contracts, not every implementation; upstream Pi and certified or distribution providers are used where appropriate. | Capability provider trust classes |
| 19 | Product parity requirements of one consumer belong to that consumer's profile, not to the universal contract. | Review rule; see [contributing](../CONTRIBUTING.md) |
| 20 | Personal mode is a profile, not a separate architecture: identity, broker, gateway, sandbox, and audit may be omitted, while manifest, lock, isolation, resources, compatibility, and lifecycle stay shared. | One schema family and lifecycle for both `deployment.mode` values |

## Scope test

Before adding a feature, ask whether it helps describe, build, govern, distribute, secure, diagnose, reproduce, or maintain a Pi-based coding-agent distribution. Generic agent-loop or runtime behavior belongs upstream in Pi. Behavior that exists for one organization's product belongs in that distribution, unless the contract is broadly reusable.
