# PiShip

**Ship your own coding agent on Pi — without forking Pi.**

PiShip is an open-source framework for building branded, reproducible Pi-based coding-agent distributions.

```text
Pi → PiShip → Your Agent
```

**Early preview.** PiShip is building toward its first runnable distribution release: a pinned Pi runtime, isolated state, controlled resources, and a branded launcher.

## Why PiShip?

[Pi](https://github.com/earendil-works/pi) gives you the agent runtime. Shipping your own coding agent is a different problem. You still need to:

- pin and upgrade Pi without carrying a fork
- control exactly which skills, extensions, prompts, and settings load
- isolate state from a developer's personal Pi installation
- brand, build, test, release, and eventually govern the distribution

**Pi owns the agent. PiShip owns the distribution.**

## Project status

PiShip is currently an early development preview. The foundation is in place:

- a public Pi integration boundary and an exact version pin
- cross-platform compatibility CI
- an experimental `piship/v1alpha1` manifest marker
- CLI help and version output, plus illustrative distribution examples

The first runnable milestone is v0.1:

```text
piship.yaml
    ↓
pinned Pi
    ↓
isolated state + controlled resources
    ↓
branded agent command
```

The distribution builder and launcher are not implemented yet. The example manifests are fixtures; the CLI cannot build or launch them.

## How it works

```text
Upstream Pi → PiShip → Your distribution → Your coding agent
```

Pi provides the agent runtime. PiShip is designed to define and maintain the distribution around it. Your distribution repository will hold the branding and resources specific to your agent. See the [architecture guide](docs/architecture.md) for package boundaries and the intended flow.

## How PiShip differs

| Approach | Focus | Relationship to upstream Pi |
| --- | --- | --- |
| Pi configuration, including [pi-distro](https://github.com/msdavid/pi-distro) | Reusable, composable configuration with version-aware updates | Configures an existing Pi environment |
| PiShip | **Planned:** branded distribution, exact runtime pin, isolated state, controlled resources, and compatibility lifecycle | Keeps Pi upstream and uses public interfaces |
| Pi fork | Direct control of runtime code | Requires maintaining changes across upstream releases |

PiShip's distribution capabilities are planned, not shipped. If shared configuration is all you need, a configuration tool may be enough.

## Pi compatibility

The current Pi integration is pinned to `@earendil-works/pi-coding-agent@0.87.1`, currently classified as a compatibility **candidate**. Only `packages/pi` may import upstream Pi packages, through public exports. See the [compatibility policy](docs/compatibility.md).

## Roadmap

[v0.1](docs/roadmap.md) targets the first runnable personal distribution. Later milestones cover managed access, governance, and release lifecycle; they are plans, not available features.

## Documentation

- [Architecture](docs/architecture.md): product and package boundaries
- [Manifest](docs/manifest.md): current alpha contract
- [Pi compatibility](docs/compatibility.md): pin and upgrade policy
- [Security model](docs/security.md): trust boundaries and current limits
- [Roadmap](docs/roadmap.md): milestones without dates

## Contributing

Use Node.js 22.19.0 or newer. To work on the repository:

```bash
npm ci
npm run check
npm exec -- piship --help
npm exec -- piship --version
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PiShip is licensed under [MIT](LICENSE).
