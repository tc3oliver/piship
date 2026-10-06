# Release owner workflow

How a distribution owner builds, reviews, signs, and approves a release. This page is part of the [release guide](../release.md); the artifact format and its verification are in the [artifact contract](artifact-contract.md), and what users' installations do with a release is in the [update lifecycle](update-lifecycle.md).

The production lifecycle for `piship/v1alpha4` and later distributions (added in v0.4) consists of a verifiable release artifact per target, signed update channels, verified update with atomic activation, rollback to a retained known-good release, and an explicit migration check for local data. Its current status and evidence are on the [status page](../status.md); nothing is published to npm or through a signed channel. It wraps the v0.1 [portable payload](../portable-artifact.md) unchanged; nothing here assembles a second runtime, resource, launcher, or state layout.

The flow for a distribution owner:

1. Migrate the manifest to `piship/v1alpha6` (`piship release` also takes `piship/v1alpha5`), add the update trust bootstrap (root and channel keys), and lock ([manifest](../manifest.md#update-trust-bootstrap-v1alpha5)).
2. Build a release on each target with `piship release`.
3. Verify it with `piship verify-release` and, in CI, check reproducibility and build provenance.
4. Add the archives to a channel with `piship sign-channel` and serve the channel directory over HTTPS, or over plain HTTP from an internal host when the manifest sets `updates.transport: http-allowed` ([channel hosting](trust-root.md#channel-hosting)).
5. Users install the release, then run `<command> update` and `<command> rollback`.
6. Change trust later only by publishing the next root with `piship trust-root next`, never by editing a release's bootstrap.

```bash
node packages/cli/dist/bin.js migrate ./acmecode/piship.yaml --write
node packages/cli/dist/bin.js keygen /media/offline/acme-root.pem --id acme-root-2026 --encrypt
node packages/cli/dist/bin.js keygen ~/keys/acme-release.pem --id acme-release-2026 --encrypt
node packages/cli/dist/bin.js trust-root init --key acme-root-2026=<public-key> --key acme-release-2026=<public-key> \
  --root-keys acme-root-2026 --channel-keys acme-release-2026 --expires-days 365
node packages/cli/dist/bin.js lock ./acmecode/piship.yaml
node packages/cli/dist/bin.js release ./acmecode/piship.yaml [--out <dir>] [--channel <name>] [--rebuild] [--reclaim-staging]
node packages/cli/dist/bin.js verify-release dist/releases/acmecode-1.1.0-linux-x64.tar.gz [--sha256 <hex>] [--json]
node packages/cli/dist/bin.js reproducibility <release-a> <release-b> [--out report.json]
node packages/cli/dist/bin.js diff <before> <after> [--json]
node packages/cli/dist/bin.js sign-channel ./channel dist/releases/acmecode-1.1.0-linux-x64.tar.gz \
  --channel stable --key ~/keys/acme-release.pem --key-id acme-release-2026 [--previous-key <id>=<public-key>] [--sequence <n>] [--expires-days <n>]
node packages/cli/dist/bin.js trust-root next ./channel --manifest ./acmecode/piship.yaml \
  [--add-key <id>=<public-key>]... [--remove-key <id>]... [--channel-keys <ids>] [--root-keys <ids>] \
  --expires-days 365 --sign acme-root-2026=/media/offline/acme-root.pem
```

## Building a release

`piship release <manifest>` runs on the target it builds for; cross-target builds are refused. It needs a `piship/v1alpha5` or `piship/v1alpha6` manifest, a current `piship.lock` (and `piship.lock.d/` when it declares Pi packages), and package-registry access for the dependency scan and for vendoring Pi packages. Static gates run first, before anything is assembled; each failure names its gate:

| Gate | Stops the build when |
| --- | --- |
| `lock` | `piship.lock` is missing, stale, or does not match the manifest and resources (`LOCK_INVALID`) |
| `schema` | The manifest is not `piship/v1alpha5` or `piship/v1alpha6` |
| `trust` | `updates.source` is set without `updates.trust.bootstrap`, or a managed distribution's root and channel roles share a key (as a migrated v1alpha4 key set does) |
| `target` | This machine's `<platform>-<arch>` is not in `release.targets`, has no installed lifecycle evidence in this PiShip version (only `linux-x64`, `darwin-arm64`, and `win32-x64` do), or differs from the requested target |
| `pi` | The pinned Pi version is not in this PiShip build's compatibility matrix |
| `source` | A locked package, in the payload's npm lock or in a Pi package's closure under `pi-packages/<id>`, has no recorded source, comes from an origin outside `release.sources`, or has no `sha512` integrity |
| `install-script` | A locked package or Pi package closure entry runs npm lifecycle scripts or has a `binding.gyp`, and is neither on PiShip's reviewed list for the pinned Pi closure nor in `release.installScripts` (v1alpha6; a git or local package's own root script is reviewed as `pi-packages/<id>/package@<commit or tree digest>`) |
| `package` | A Pi package's stored lockfile is missing from `piship.lock.d/packages/<id>/` (`LOCK_INVALID`). A lockfile that no longer matches its sha256 in the lock, or a closure entry that is not an exact registry tarball with integrity (an alias, link, file, workspace, git, or URL dependency), is reported as `Package <id>: …` |
| `policy` | A rule ID appears in both `policy.enforced` and `policy.defaults`; two enforced rules for the same action and resource disagree; a declared resource's class is denied by `policy.resourceTrust`; or an enabled capability's provider class is denied by `policy.providerTrust`; or a managed `deny` or `ask` rule names an action no runtime seam enforces and is not listed in `policy.acknowledgeUnenforced` (`POLICY_UNENFORCEABLE`) |
| `models` | A virtual model's route is not an allowed physical chat model of the catalog (managed), or its router is not a declared extension (a `package:<id>` router is not resolved yet) |
| `certification` | A certified resource or capability provider has no certification evidence |
| `sandbox` | `sandbox.required: true` and the target is not Linux or macOS (there is no Windows sandbox adapter) |

`piship build` also runs the `source` and `install-script` gates on locks of `piship/v1alpha4` and later, and on each locked Pi package's closure (reported as `Build gate source` or `Build gate install-script`); `dev` and `test` do not. Vendoring fails with `INTEGRITY_FAILED` when a package's version or commit, integrity, tree digest, file count, or resource inventory differs from the lock.

PiShip then assembles the canonical payload with the same code as `piship build`, and runs the required tests on it, all at once, each with its own throwaway state directory:

- `launch-version`: the branded `version` command, which verifies payload integrity, target, Node, and the pinned Pi version.
- `offline-smoke`: the branded `--smoke`, only when the distribution needs no sign-in (personal Pi-native or `none` credentials).
- `governance-inspection`: the branded `capabilities --json`, when the distribution is governed.

A managed distribution that requires sign-in is therefore not smoke-tested by `piship release`; the lifecycle E2E covers login, model use, and session resume against local fixtures. The vulnerability gate and the registry signature gate run beside the tests and the SBOM and notices, not after them: the registry scans start together, and their verdicts are applied in a fixed order whichever finishes first (a bundled payload waits for the signature check before bundling, because it reads the packages bundling replaces, and is then tested). The vulnerability gate is `npm audit` of the payload's npm lock and of each vendored Pi package lockfile under `release.vulnerabilities`, asking `release.vulnerabilities.registry` when set; a managed release fails when no audit endpoint answers for a package, a personal one records a warning in `vulnerabilities.json`. The registry signature gate is `npm audit signatures`: an invalid signature or attestation fails the build, missing signatures are recorded, a check that cannot run, for example without access to the Sigstore TUF repository, is recorded as `unavailable`, and unreadable output fails closed. Then come the metadata, checksums, and a deterministic archive. Any failure removes the partial output. On success the release lands in `<out>/releases/` (default `dist/releases/`). The build stages in `<out>/releases/.piship-release-<id>-*` with an owner marker. A build killed with SIGKILL, or a machine that loses power, leaves that directory; the next `piship release` (and `piship build`, `dev`, and `test` for their own staging in `dist/`) says how many abandoned ones it found and removes nothing, because the output directory usually lies inside a project that sandboxed commands can write. Pass `--reclaim-staging` to `piship build` or `piship release` to remove the abandoned staging of dead processes there ([temporary directories](../architecture.md#temporary-directories)). On Windows keep the release output path short (about 100 characters or less), because npm cannot run install scripts in a directory longer than 260 characters. The build is unsigned: its output says so, and it is a development artifact until it is published through a signed channel or carries verified build provenance.

The release is the qualified artifact: its `release.json` records `qualification: qualified`, meaning the dependency audit, registry signature check, SBOM, notices, and tests above all passed, and the output of `piship release` says so. `piship build`, `dev`, and `test` produce an unqualified local build instead. `piship build` prints a notice saying it is not audited, has no SBOM or notices, and is not signed, and each of the three writes `<out>/<id>.piship-qualification.json` (`qualification: unqualified-local`) beside the payload, never inside it, so a release still wraps the payload byte for byte. `piship verify-release` refuses a local build directory and names it as one, `piship install` of one prints a warning (installing a local build for your own testing stays supported), and a `release.json` that records any qualification other than `qualified` fails verification. Releases built before the field existed omit it and verify as before.

A release reuses the runtime bytes (the installed dependency tree and, with `release.bundle`, the bundled runtime) of an earlier release built from the same PiShip build, Pi and npm lock, platform, Node, and strip setting, from `<cache>/piship/runtime`; it redoes every audit, the SBOM, notices, tests, and the archive. The cache has the trust of the owner's home directory, so build a release you will publish cold: on a clean runner, or with `--rebuild` or `PISHIP_RELEASE_NO_CACHE=1`, which ignore it. `release.json` records `runtimeCache` (`hit`, `miss`, or `disabled`, with the entry id) ([performance](../performance.md#what-a-release-does-now)).

Set `PISHIP_DEBUG_TIMING=1` to see where a release spends its time: each stage is printed as `release <stage>: N ms`, longest first, followed by one `piship-timing/v1` JSON line on stderr with each stage's start offset and duration. Stages that run side by side overlap, so they can add up to more than the total. `node scripts/benchmark-build.mjs --release` records these for a bundled and an unbundled example.

Set `SOURCE_DATE_EPOCH` to record a creation time. Without it the recorded time is the Unix epoch, so two builds of the same inputs still produce identical metadata.

## Supported platforms

Releases are built only for `linux-x64` (Ubuntu), `darwin-arm64`, and `win32-x64`, the targets that the lifecycle E2E and the Release candidate workflow cover (current results are on the [status page](../status.md#recorded-evidence)), and only when listed in `release.targets` (the default). `linux-arm64` and `darwin-x64` are accepted in the manifest but refused by the `target` gate. Node.js 22.19.0 or newer remains a separate prerequisite. A Windows release of a distribution that requires the OS sandbox is refused.

## Reviewing a change

`piship diff <before> <after> [--json]` compares two distribution locks, taken from manifests (which must have a current lock), lock files, payloads, releases, archives, or installed IDs; older lock schemas compare too. It reports each change by area (distribution, schema, Pi, PiShip, packages, resources, extensions, providers, capabilities, policy, enforcement, tools, MCP, sandbox, audit, data, access, models, network, updates, and release) as added, removed, or changed, with a `low`, `medium`, or `high` risk and a reason; for example, a policy effect that loosens or a new pinned key. It ends with the highest risk and the tests a reviewer should require, such as the Pi compatibility suite or the release update and rollback E2E. Values are versions, IDs, effects, templates, and shortened digests; environment values, settings text, and key material are not shown. The report is `piship-diff/v1` with `--json`.

## Signing a channel

Channel names, the channel directory layout, and how clients accept signed metadata are described in the [update lifecycle](update-lifecycle.md#channels-and-signed-metadata). The owner's commands:

- `piship keygen <file> --id <key-id> [--encrypt [--passphrase-env <NAME> | --passphrase-stdin]] [--force-in-worktree]` writes a new Ed25519 private key (PKCS#8 PEM, mode 0600, encrypted with `--encrypt`, refusing to overwrite, and refusing a path inside a git work tree that is not git-ignored unless `--force-in-worktree` is given) and prints the public key and its `sha256:` fingerprint. Keep the private key out of the repository, CI logs, and the manifest; only the public key is pinned.
- `piship trust-root init --key <id>=<public-key>... --root-keys <ids> --channel-keys <ids> [--root-threshold <n>] [--channel-threshold <n>] (--expires <timestamp> | --expires-days <n>)` validates a bootstrap root and prints the `updates.trust.bootstrap` block for `piship.yaml` with each key's fingerprint. It warns when the roles share a key, which a managed release refuses.
- `piship trust-root next <update-source-dir> --manifest <piship.yaml> --sign <id>=<private-key-file>... [--add-key <id>=<public-key>]... [--remove-key <id>]... [--root-keys <ids>] [--channel-keys <ids>] [--root-threshold <n>] [--channel-threshold <n>] (--expires <timestamp> | --expires-days <n>)` verifies the chain from the manifest's bootstrap through `root/` in the directory, builds exactly the next version (a removed key leaves every role; a role keeps its keys and threshold unless given), signs it with every `--sign` key, requires the current and the new root-role thresholds, and only then writes `root/<N+1>.json.sig` and `root/<N+1>.json`. A wrong passphrase, failing signer, or unmet threshold writes nothing. Every required signature is collected in one run; partially signed roots are not supported.
- `piship sign-channel <channel-dir> <archive>... --channel <name> --key <file> --key-id <id> [--key <file> --key-id <id>]...` verifies each archive with `verify-release`, copies it into the channel directory, adds or replaces its version and target entry while keeping the others, and writes and signs the metadata. With several keys, the first one's signature is the top-level signature (what v0.7 clients check) and all of them are in `signatures[]`. Before writing, it checks the signatures against the trust the releases declare: the channel role of the newest root in `<channel-dir>/root/` reached from their bootstrap, or for v1alpha4 releases the top-level signature against `updates.trust.keys`; it refuses signatures clients would refuse. It extends existing metadata only when its signature verifies with a signing key, a key of that declared trust, a key a release being added pins, or `--previous-key <id>=<public-key>`, and it replaces the metadata and signature each through a temporary file and a rename ([trust root](trust-root.md#channel-hosting)). The sequence defaults to the previous one plus one and must increase; `expires` defaults to 30 days. A channel belongs to one distribution.
- Encrypted keys take their passphrase at a hidden prompt per key, from `--passphrase-env <NAME>` (one passphrase for all encrypted keys of the run), or from `--passphrase-stdin` (one encrypted key).
- Rotation and revocation publish the next root ([key runbook](key-runbook.md)); a release lock never changes what installed clients trust.

Key custody, a backup key, the first trust root a client installs, rotation timing, compromised and lost keys, channel hosting and atomic publish, and why a GitHub Release is not a signed channel are covered in [release trust root](trust-root.md).

## Release checklist

This is the checklist for a distribution owner shipping a release of their own distribution to their users. The PiShip project's own release qualification, which builds the example distributions in its CI, is a different process: see the [PiShip maintainer release checklist](../maintainers/release-checklist.md).

Before anything is signed into a channel employees read:

1. **Inputs.** `piship validate` passes and every `Warning:` is understood ([what validate checks](../enterprise-integration.md#running-the-cli-from-your-own-repository)); `piship.lock` is current and was reviewed in the change that committed it.
2. **Review the change.** Run `piship diff` between the previous release and this one. Every `high` risk change (a bootstrap key or role changed, a policy that loosens, a new endpoint, host, or provider, a new Pi package or a changed package source, version, commit, or content, widened tool exposure, an enforcement downgrade, an allowed session export) has a second reviewer, and the tests the report asks for were run.
3. **Build on each target** with `piship release`, on a clean machine or CI runner per target in `release.targets`. Run `piship verify-release` on another machine, and, if you build twice, `piship reproducibility` on the two builds ([artifact contract](artifact-contract.md)).
4. **Vulnerabilities.** Review `vulnerabilities.json` (including each Pi package's entry under `packages`), and every `release.vulnerabilities.allow` exception and `release.installScripts` entry: its reason still holds and its expiry is in the future.
5. **Against your services.** Install the release on a test machine and run it against staging: `login`, `doctor`, `--smoke`, `logout`, with your broker and audit collector checked as in [testing your own broker and audit collector](../enterprise-integration.md#testing-your-own-broker-and-audit-collector). A managed release that requires sign-in is not smoke-tested by `piship release` itself.
6. **Trust keys.** The bootstrap pins exactly the root and channel keys you intend (distinct for a managed distribution) and their fingerprints match your key record; the newest published root has not expired and expires well after this release. A key change follows the [release key runbook](key-runbook.md).
7. **Record** the commit, version, archive SHA-256 values, the bootstrap root version, and the approver.
8. **Approval** by the named release owner for this commit and these archives.
9. **Stage it.** Sign the release into `candidate` first and let a pilot group update; then sign the same archives into `stable` (`sign-channel --channel stable`; the archive is not rebuilt), with a higher sequence. Publish the channel files in the order the [trust root page](trust-root.md#channel-hosting) gives, and re-sign each channel before its metadata expires (30 days by default).
10. **Know the way back** before you need it: [company-wide rollback](key-runbook.md#company-wide-rollback).
