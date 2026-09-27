# PiShip

**Ship your own coding agent on Pi — without forking Pi.**

PiShip is an open-source framework for building branded, reproducible Pi-based coding-agent distributions.

```text
Pi → PiShip → Your Agent
```

**Early preview.** The first personal distribution can now validate, lock, build, and launch the pinned upstream Pi runtime from this checkout. It is a development slice, not a packaged release.

## Why PiShip?

[Pi](https://github.com/earendil-works/pi) gives you the agent runtime. Shipping your own coding agent is a different problem. You still need to:

- pin and upgrade Pi without carrying a fork
- control which skills, extensions, prompts, and instructions load
- isolate state from a developer's personal Pi installation
- brand, build, test, release, and eventually govern the distribution

**Pi owns the agent. PiShip owns the distribution.**

## Project status

The `piship/v1alpha1` personal example now completes this checkout-local flow:

```text
piship.yaml → validate → piship.lock → build → branded command → Pi
```

The branded command starts a real Pi 0.87.1 SDK session and interactive TUI. CI uses `--smoke` to initialize the session and check controlled resources without a model call. The output requires this repository and `npm ci`; it is not an installer, a standalone executable, or a production release. Managed identity, credentials, policy, sandboxing, and release lifecycle are planned.

## How it works

```text
Upstream Pi → PiShip → Your distribution → Your coding agent
```

The [personal example](examples/personal/README.md) demonstrates exact Pi pinning, a content-hashed lockfile, an isolated state directory, explicit distribution resources, and a branded command. PiShip keeps upstream Pi untouched. See the [architecture guide](docs/architecture.md) for boundaries and the build flow.

## How PiShip differs

| Approach | Focus | Relationship to upstream Pi |
| --- | --- | --- |
| Pi configuration, including [pi-distro](https://github.com/msdavid/pi-distro) | Reusable, composable configuration with version-aware updates | Configures an existing Pi environment |
| PiShip | Distribution manifest, exact pin, lock, isolated state, controlled resources, and branded launcher; governance and portable releases are planned | Uses public Pi interfaces without a fork |
| Pi fork | Direct control of runtime code | Requires maintaining changes across upstream releases |

## Pi compatibility

The current integration is pinned to `@earendil-works/pi-coding-agent@0.87.1`. It is **supported for this distribution slice** after Ubuntu, macOS, and Windows launch gates passed. This does not cover live model calls or future managed features. Only `packages/pi` imports upstream Pi packages, through public exports. See the [compatibility policy](docs/compatibility.md).

## Roadmap

[v0.1](docs/roadmap.md) continues from this runnable personal slice toward a portable distribution core. Later milestones cover managed access, governance, and production lifecycle. These are plans without dates.

## Documentation

- [Architecture](docs/architecture.md): product and package boundaries
- [Manifest](docs/manifest.md): current alpha contract and lock
- [Pi compatibility](docs/compatibility.md): pin and upgrade policy
- [Security model](docs/security.md): trust boundaries and current limits
- [Roadmap](docs/roadmap.md): milestones without dates

## Contributing

Use Node.js 22.19.0 or newer:

```bash
npm ci
npm run check
```

The [personal example](examples/personal/README.md) has the runnable commands. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PiShip is licensed under [MIT](LICENSE).
