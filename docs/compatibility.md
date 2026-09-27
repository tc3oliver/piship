# Pi compatibility

## Exact pin

`packages/pi/package.json` pins `@earendil-works/pi-coding-agent` to exactly `0.87.1`. Its public entrypoint reports Node `>=22.19.0`. No other PiShip package may declare or import `@earendil-works/pi-*`. The lockfile records the complete transitive graph.

## Status contract

`compatibility/pi.json` maps a Pi version to one of:

- `supported`: exact version tested in the pinned compatibility suite.
- `candidate`: under evaluation; not a production pin.
- `unsupported`: known incompatible or not accepted.

The initial supported version is `0.87.1`. A version is not supported just because it installs.

## Public API only

Use exported package entrypoints. Never import `node_modules/.../src/*`, private or internal subpaths, GitHub source URLs, or Pi implementation files. Current integration uses the root public entrypoint. The boundary scanner enforces this for PiShip source and checks manifests; compatibility tests import the public entrypoint.

## Upgrade workflow

1. Open a Pi compatibility change and record the upstream release and relevant API changes.
2. Test the candidate through public exports without changing the production pin.
3. Update the exact pin, compatibility matrix, and lockfile together.
4. Add or update regression tests for affected behavior.
5. Run `npm run check` and `npm run test:compatibility` across CI platforms before changing status to supported.

The scheduled canary is intentionally deferred until it can report latest-version failures reliably without touching the production dependency. It must only signal; it must not commit, merge, or publish.

## Temporary shims

Prefer upstream fixes. Every temporary compatibility shim requires an owner, reason, expiration or removal condition, upstream issue or PR when appropriate, and a regression test. Remove the shim once the pinned Pi release supports the required public behavior.
