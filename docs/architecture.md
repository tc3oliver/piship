# Architecture

PiShip sits between upstream Pi and a distribution repository:

```text
Upstream Pi → PiShip → distribution repository → branded coding agent
```

Pi owns the agent runtime, TUI, sessions, tools, model interaction, and extension execution. PiShip owns the description, reproduction, compatibility, and lifecycle of a distribution. The distribution repository owns its branding, chosen resources, and organization-specific integrations. PiShip does not fork or vendor Pi.

## Where a change belongs

| Change | Home |
| --- | --- |
| Generic agent or runtime behavior | Upstream Pi |
| Distribution manifest, isolation, resolution, build, compatibility, or governance | PiShip |
| Brand, private endpoint, organization policy, or custom resource | Distribution repository |

A Pi extension adds behavior inside an existing Pi environment. PiShip aims to make the surrounding distribution reproducible. The first milestone is a manifest that leads to an exact Pi version, isolated state, controlled resources, and a branded launcher. That flow is not implemented yet.

## Package dependencies

Arrows point from the importing package to its allowed dependency:

```text
@piship/cli ───────→ @piship/pi ───────→ Pi public API
     │                   │
     ├────→ @piship/core ┴────→ @piship/schema
     └────────────────────────→ @piship/schema
```

`schema` defines the experimental marker and minimal diagnostics. `core` owns distribution types and state path abstractions. `pi` is the sole adapter for upstream Pi. `cli` presents commands and keeps domain logic in other packages. These are allowed boundaries; packages declare only dependencies they currently use.

Only `packages/pi` may depend directly on or import `@earendil-works/pi-*`. It uses an exact Pi version pin and public package exports. No package may import Pi source files or private implementation paths. The boundary checker enforces these rules in CI. This keeps Pi upgrades localized and testable.

## Intended data flow

```text
manifest → validation → resolved distribution → lock and build → Pi runtime
```

Today, only the alpha schema marker, a small resolved distribution type, Pi compatibility metadata, and CLI help/version exist. Parsing YAML, producing a lockfile, building a distribution, and launching Pi are future work. Manifests and lockfiles must never contain secret values.

For the current contract, see [manifest status](manifest.md). For Pi upgrades, see [compatibility](compatibility.md). For trust boundaries, see [security architecture](security.md).
