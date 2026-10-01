# Release owner workflow

How a distribution owner builds, reviews, signs, and approves a release. This page is part of the [release guide](../release.md); the artifact format and its verification are in the [artifact contract](artifact-contract.md), and what users' installations do with a release is in the [update lifecycle](update-lifecycle.md).

The production lifecycle for `piship/v1alpha4` distributions (added in v0.4) consists of a verifiable release artifact per target, signed update channels, verified update with atomic activation, rollback to a retained known-good release, and an explicit migration check for local data. Its current status and evidence are on the [status page](../status.md); nothing is published to npm or through a signed channel. It wraps the v0.1 [portable payload](../portable-artifact.md) unchanged; nothing here assembles a second runtime, resource, launcher, or state layout.

The flow for a distribution owner:

1. Migrate the manifest to `piship/v1alpha4`, add a release key, and lock ([manifest](../manifest.md#lifecycle-fields-v1alpha4)).
2. Build a release on each target with `piship release`.
3. Verify it with `piship verify-release` and, in CI, check reproducibility and build provenance.
4. Add the archives to a channel with `piship sign-channel` and serve the channel directory.
5. Users install the release, then run `<command> update` and `<command> rollback`.

```bash
node packages/cli/dist/bin.js migrate ./acmecode/piship.yaml --write
node packages/cli/dist/bin.js keygen ~/keys/acme-release.pem --id acme-release-2026
node packages/cli/dist/bin.js lock ./acmecode/piship.yaml
node packages/cli/dist/bin.js release ./acmecode/piship.yaml [--out <dir>] [--channel <name>] [--reclaim-staging]
node packages/cli/dist/bin.js verify-release dist/releases/acmecode-1.1.0-linux-x64.tar.gz [--sha256 <hex>] [--json]
node packages/cli/dist/bin.js reproducibility <release-a> <release-b> [--out report.json]
node packages/cli/dist/bin.js diff <before> <after> [--json]
node packages/cli/dist/bin.js sign-channel ./channel dist/releases/acmecode-1.1.0-linux-x64.tar.gz \
  --channel stable --key ~/keys/acme-release.pem --key-id acme-release-2026 [--sequence <n>] [--expires-days <n>]
```

## Building a release

`piship release <manifest>` runs on the target it builds for; cross-target builds are refused. It needs a `piship/v1alpha4` manifest, a current `piship.lock`, and package-registry access for the dependency scan. Static gates run first, before anything is assembled; each failure names its gate:

| Gate | Stops the build when |
| --- | --- |
| `lock` | `piship.lock` is missing, stale, or does not match the manifest and resources (`LOCK_INVALID`) |
| `schema` | The manifest is not `piship/v1alpha4` |
| `target` | This machine's `<platform>-<arch>` is not in `release.targets`, has no installed lifecycle evidence in this PiShip version (only `linux-x64`, `darwin-arm64`, and `win32-x64` do), or differs from the requested target |
| `pi` | The pinned Pi version is not in this PiShip build's compatibility matrix |
| `source` | A locked package has no recorded source, comes from an origin outside `release.sources`, or has no `sha512` integrity in the npm lock |
| `install-script` | A locked package runs npm lifecycle scripts and is not on PiShip's reviewed list for the pinned Pi closure |
| `policy` | A rule ID appears in both `policy.enforced` and `policy.defaults`; two enforced rules for the same action and resource disagree; a declared resource's class is denied by `policy.resourceTrust`; or an enabled capability's provider class is denied by `policy.providerTrust` |
| `certification` | A certified resource or capability provider has no certification evidence |
| `sandbox` | `sandbox.required: true` and the target is not Linux or macOS (there is no Windows sandbox adapter) |

`piship build` also runs the `source` and `install-script` gates on `piship/v1alpha4` locks, reported as `Build gate source` or `Build gate install-script`; `dev` and `test` do not.

PiShip then assembles the canonical payload with the same code as `piship build`, and runs the required tests on it with a throwaway state directory:

- `launch-version`: the branded `version` command, which verifies payload integrity, target, Node, and the pinned Pi version.
- `offline-smoke`: the branded `--smoke`, only when the distribution needs no sign-in (personal Pi-native or `none` credentials).
- `governance-inspection`: the branded `capabilities --json`, when the distribution is governed.

A managed distribution that requires sign-in is therefore not smoke-tested by `piship release`; the lifecycle E2E covers login, model use, and session resume against local fixtures. After the tests come the vulnerability gate, the registry signature gate (`npm audit signatures`: an invalid signature or attestation fails the build, missing signatures are recorded, a check that cannot run, for example without access to the Sigstore TUF repository, is recorded as `unavailable`, and unreadable output fails closed), SBOM, notices, metadata, checksums, and a deterministic archive. Any failure removes the partial output. On success the release lands in `<out>/releases/` (default `dist/releases/`). The build stages in `<out>/releases/.piship-release-<id>-*` with an owner marker. A build killed with SIGKILL, or a machine that loses power, leaves that directory; the next `piship release` (and `piship build`, `dev`, and `test` for their own staging in `dist/`) says how many abandoned ones it found and removes nothing, because the output directory usually lies inside a project that sandboxed commands can write. Pass `--reclaim-staging` to `piship build` or `piship release` to remove the abandoned staging of dead processes there ([temporary directories](../architecture.md#temporary-directories)). On Windows keep the release output path short (about 100 characters or less), because npm cannot run install scripts in a directory longer than 260 characters. The build is unsigned: its output says so, and it is a development artifact until it is published through a signed channel or carries verified build provenance.

Set `SOURCE_DATE_EPOCH` to record a creation time. Without it the recorded time is the Unix epoch, so two builds of the same inputs still produce identical metadata.

## Supported platforms

Releases are built only for `linux-x64` (Ubuntu), `darwin-arm64`, and `win32-x64`, the targets that the lifecycle E2E and the Release candidate workflow cover (current results are on the [status page](../status.md#recorded-evidence)), and only when listed in `release.targets` (the default). `linux-arm64` and `darwin-x64` are accepted in the manifest but refused by the `target` gate. Node.js 22.19.0 or newer remains a separate prerequisite. A Windows release of a distribution that requires the OS sandbox is refused.

## Reviewing a change

`piship diff <before> <after> [--json]` compares two distribution locks, taken from manifests (which must have a current lock), lock files, payloads, releases, archives, or installed IDs; older lock schemas compare too. It reports each change by area (distribution, schema, Pi, PiShip, packages, resources, extensions, providers, capabilities, policy, MCP, sandbox, audit, access, models, network, updates, and release) as added, removed, or changed, with a `low`, `medium`, or `high` risk and a reason; for example, a policy effect that loosens or a new pinned key. It ends with the highest risk and the tests a reviewer should require, such as the Pi compatibility suite or the release update and rollback E2E. Values are versions, IDs, effects, templates, and shortened digests; environment values, settings text, and key material are not shown. The report is `piship-diff/v1` with `--json`.

## Signing a channel

Channel names, the channel directory layout, and how clients accept signed metadata are described in the [update lifecycle](update-lifecycle.md#channels-and-signed-metadata). The owner's commands:

- `piship keygen <file> --id <key-id> [--force-in-worktree]` writes a new Ed25519 private key (PKCS#8 PEM, mode 0600, refusing to overwrite, and refusing a path inside a git work tree that is not git-ignored unless `--force-in-worktree` is given) and prints the `updates.trust.keys` entry and the key's `sha256:` fingerprint. Keep the private key out of the repository, CI logs, and the manifest; only the public key is pinned.
- `piship sign-channel <channel-dir> <archive>... --channel <name> --key <file> --key-id <id>` verifies each archive with `verify-release`, copies it into the channel directory, adds or replaces its version and target entry while keeping the others, and writes and signs the metadata. The sequence defaults to the previous one plus one and must increase; `expires` defaults to 30 days. A channel belongs to one distribution. `sign-channel` does not check that the key is pinned by the distribution; an update with an unpinned key fails.
- Rotation: pin the new key next to the old one, ship a release with both, then sign with the new key and remove the old key in a later release. Key IDs are unique within `updates.trust.keys`.

Key custody, a backup key, the first trust root a client installs, rotation timing, compromised and lost keys, channel hosting and atomic publish, and why a GitHub Release is not a signed channel are covered in [release trust root](trust-root.md).

## Release checklist

Nothing is published automatically: there is no npm publication or publish automation, and CI keeps artifacts only as workflow artifacts. A GitHub Release, such as the v0.7.0 pre-release, is created by hand from a qualified run's artifacts. The maintainer, Oliver, is the sole release approver. Before any publish step:

1. Dispatch `Release qualification` on the exact commit on `main` and confirm the run is green. It runs `CI`, CodeQL, Portable E2E, and Reference E2E on that commit, then `Release candidate`. Its `release-candidate` jobs must have passed on `linux-x64`, `darwin-arm64`, and `win32-x64`. It must show two builds on separate runners with equal payloads for both `acmecode` and `mypi` (the `reproducibility-<distribution>-<target>` reports), `verify-release` on a fresh job, and rejection of the tampered archive, the wrong digest, and the modified payload, `release.json`, SBOM, and `checksums.txt`, and an install with the shipped script on a fresh job, followed for `mypi` by the installed release's offline `--smoke` and `doctor`. Attestations must verify with `gh attestation verify --repo tc3oliver/piship --signer-workflow tc3oliver/piship/.github/workflows/release-candidate.yml --source-ref refs/heads/main`. Its Portable E2E jobs must have passed on all three targets, including the lifecycle scenarios (`tests/e2e/lifecycle-*.test.ts` and `tests/e2e/personal-lifecycle.test.ts`), its Reference E2E job, the AcmeCode reference distribution against the enterprise reference stack on Ubuntu, must have passed, and its CodeQL job must be green.
2. Confirm `examples/demo-company/piship.lock` was reviewed in the change that committed it, and that the Windows candidate is treated as the patched variant whose lock was generated in CI.
3. Confirm `npm run check` and `npm run test:compatibility` passed, and review `piship diff` between the previous and new release for its risk and required tests.
4. Review `vulnerabilities.json` and every `release.vulnerabilities.allow` exception and its expiry.
5. Confirm the pinned release keys, and that the private key is held outside the repository and CI.
6. Record the archive SHA-256 values and attestation results.
7. Obtain the maintainer's explicit written approval for this specific commit and these artifacts. Without it, nothing is signed into a channel or published anywhere.
8. Only then sign the channel with a higher sequence and publish its directory. Rolling back a bad release means signing a channel that offers a newer, fixed version; clients refuse downgrades, and users can run `rollback` locally.
