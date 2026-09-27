# Architecture

PiShip sits between upstream Pi and a distribution repository:

```text
Upstream Pi → PiShip → distribution repository → branded coding agent
```

Pi owns the agent loop, TUI, sessions, tools, model interaction, and extension execution. PiShip owns the distribution manifest, exact runtime pin, lock, controlled resources, build, and compatibility boundary. A distribution repository owns branding and chosen resources. PiShip does not fork or vendor Pi.

| Change | Home |
| --- | --- |
| Generic agent or runtime behavior | Upstream Pi |
| Manifest, resource isolation, lock, build, compatibility | PiShip |
| Brand, private endpoint, organization-specific resources | Distribution repository |

## Package dependencies

Arrows point from importer to dependency:

```text
@piship/cli ───────→ @piship/pi ───────→ Pi public API
     │                   │
     ├────→ @piship/core ┴────→ @piship/schema
     └────────────────────────→ @piship/schema
```

`schema` parses and validates the alpha manifest. `core` resolves resources, locks their content, and builds the checkout-local output. `pi` alone imports `@earendil-works/pi-*`, using the public SDK entrypoint. `cli` presents commands. The boundary checker enforces these dependencies in CI.

## First runnable flow

```text
piship.yaml → validate → piship.lock → build → branded command → Pi SDK/TUI
```

The build output stores metadata, copied resources, and a thin launcher. The launcher resolves `@piship/pi` from the same repository; it requires the workspace's installed dependencies. It creates state under `~/.piship/<id>` by default (or `PISHIP_STATE_HOME/<id>`). Pi receives explicit `agentDir`, session directory, in-memory settings, and a resource loader with ambient discovery disabled and declared paths added explicitly. The user project remains the agent working directory, while its `.pi` files are not loaded as distribution resources. No source distribution directory receives runtime state.

For the current schema and lock contract see [manifest](manifest.md). For version upgrades see [compatibility](compatibility.md). For trust limits see [security](security.md).
