# PiShip

**Ship Pi as your coding agent distribution.**

PiShip is an open-source framework for turning upstream [Pi](https://github.com/earendil-works/pi) into a branded, reproducible coding agent without maintaining a Pi fork. It is designed for personal agents and team distributions.

```text
Upstream Pi → PiShip → Your distribution → Your coding agent
```

**Status: early development.** The distribution builder and launcher do not exist yet. The first goal is a manifest that pins Pi, isolates state and resources, and launches a branded command.

## Why PiShip

Pi gives you the agent runtime. Shipping your own agent also means choosing a Pi version, controlling which resources load, separating its state, applying a brand, and repeating that setup across machines. A team may later need identity, credentials, policy, and a release process. Those are distribution concerns.

Forking Pi gives direct control, but each upstream release then becomes a merge task. PiShip keeps Pi upstream and puts distribution behavior around its public interfaces. Pi remains responsible for the agent runtime, TUI, and tools.

| Layer | Responsibility |
| --- | --- |
| Pi | Agent runtime and user experience |
| Pi extensions or configuration | Customize an existing Pi installation |
| PiShip | Define, reproduce, and maintain a Pi-based distribution |
| Your distribution repository | Branding, resources, and integrations specific to your agent |

[pi-distro](https://github.com/msdavid/pi-distro), for example, provides reusable, composable Pi configurations with version-aware updates. PiShip is designed around a branded distribution with a pinned runtime, isolated state, controlled resources, compatibility testing, and a release lifecycle. These capabilities are **planned**, not shipped. If you only need shared Pi configuration, pi-distro may be enough.

## What works today

The repository has four small TypeScript packages, an experimental `piship/v1alpha1` schema marker, an exact Pi `0.87.1` dependency in the integration package, compatibility tests against Pi's public package entrypoint, and a CLI with help and version output. `init`, `validate`, `lock`, `dev`, `build`, and `inspect` are registered as planned commands and return an error when invoked.

For contributors, use Node.js 22.19.0 or newer:

```bash
npm ci
npm run check
npm exec -- piship --help
npm exec -- piship --version
```

The [personal](examples/personal/README.md) and [demo company](examples/demo-company/README.md) manifests illustrate the intended alpha shape. The CLI cannot read them yet.

## First working milestone

The first useful distribution should make this path real:

```text
piship.yaml → pinned Pi → isolated state → controlled resources → branded command
```

The branded command should launch upstream Pi. Managed access and governance come after this distribution core; see the [roadmap](docs/roadmap.md).

## Pi compatibility

Only `packages/pi` may import upstream Pi packages. The production dependency is pinned to `@earendil-works/pi-coding-agent@0.87.1`, and integration uses public exports. The [compatibility policy](docs/compatibility.md) explains upgrades and regression tests.

## Documentation

- [Architecture](docs/architecture.md): ownership and package boundaries
- [Manifest](docs/manifest.md): current alpha contract
- [Pi compatibility](docs/compatibility.md): pin and upgrade policy
- [Security model](docs/security.md): trust boundaries and current limits
- [Roadmap](docs/roadmap.md): milestones without dates
- [Contributing](CONTRIBUTING.md): setup, tests, and pull requests

## Community

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PiShip is licensed under [MIT](LICENSE).
