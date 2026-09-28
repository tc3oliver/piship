# Releases, updates, and rollback

v0.4 adds a production lifecycle for `piship/v1alpha4` distributions: a verifiable release artifact per target, signed update channels, verified update with atomic activation, rollback to a retained known-good release, and an explicit migration check for local data. Its current status and evidence are on the [status page](status.md); nothing is published. It wraps the v0.1 [portable payload](portable-artifact.md) unchanged; nothing here assembles a second runtime, resource, launcher, or state layout.

The flow for a distribution owner:

1. Migrate the manifest to `piship/v1alpha4`, add a release key, and lock ([manifest](manifest.md#lifecycle-fields-v1alpha4)).
2. Build a release on each target with `piship release`.
3. Verify it with `piship verify-release` and, in CI, check reproducibility and build provenance.
4. Add the archives to a channel with `piship sign-channel` and serve the channel directory.
5. Users install the release, then run `<command> update` and `<command> rollback`.

```bash
npm exec -- piship migrate ./acmecode/piship.yaml --write
npm exec -- piship keygen ~/keys/acme-release.pem --id acme-release-2026
npm exec -- piship lock ./acmecode/piship.yaml
npm exec -- piship release ./acmecode/piship.yaml [--out <dir>] [--channel <name>]
npm exec -- piship verify-release dist/releases/acmecode-1.1.0-linux-x64.tar.gz [--sha256 <hex>] [--json]
npm exec -- piship reproducibility <release-a> <release-b> [--out report.json]
npm exec -- piship diff <before> <after> [--json]
npm exec -- piship sign-channel ./channel dist/releases/acmecode-1.1.0-linux-x64.tar.gz \
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

PiShip then assembles the canonical payload with the same code as `piship build`, and runs the required tests on it with a throwaway state directory:

- `launch-version`: the branded `version` command, which verifies payload integrity, target, Node, and the pinned Pi version.
- `offline-smoke`: the branded `--smoke`, only when the distribution needs no sign-in (personal Pi-native or `none` credentials).
- `governance-inspection`: the branded `capabilities --json`, when the distribution is governed.

A managed distribution that requires sign-in is therefore not smoke-tested by `piship release`; the lifecycle E2E covers login, model use, and session resume against local fixtures. After the tests come the vulnerability gate, the registry signature gate (`npm audit signatures`: an invalid signature or attestation fails the build, missing signatures are recorded, a check that cannot run, for example without access to the Sigstore TUF repository, is recorded as `unavailable`, and unreadable output fails closed), SBOM, notices, metadata, checksums, and a deterministic archive. Any failure removes the partial output. On success the release lands in `<out>/releases/` (default `dist/releases/`). The build is unsigned: its output says so, and it is a development artifact until it is published through a signed channel or carries verified build provenance.

Set `SOURCE_DATE_EPOCH` to record a creation time. Without it the recorded time is the Unix epoch, so two builds of the same inputs still produce identical metadata.

## Artifact layout

Each target produces one deterministic `<id>-<version>-<target>.tar.gz` with a single root directory of the same name, and a `<archive>.sha256` sidecar in `sha256sum` format:

```text
acmecode-1.1.0-linux-x64/
  payload/                          the v0.1 payload, byte for byte as piship build produces it
  release.json                      piship-release/v1 metadata
  sbom.spdx.json                    SPDX 2.3 JSON
  licenses/THIRD_PARTY_NOTICES.txt  license and notice files of every installed package
  licenses/index.json               piship-notices/v1 machine-readable index
  vulnerabilities.json              piship-vulnerabilities/v1 scan result and verdict
  checksums.txt                     sha256sum lines for every file above except payload/, plus payload/metadata/inventory.json
  install.sh, install.ps1           verify this release, then install it for the current user
```

The payload's own `metadata/inventory.json` covers every payload file, so `checksums.txt` plus the inventory cover the whole release. `release.json` records the distribution ID, name, version, command, and deployment mode; the PiShip version; the Pi package, version, and its compatibility status, the weaker of the distribution's surface and the `lifecycle` surface, with each surface's status; the manifest and lock schemas and the lock SHA-256; the target; the channel it was built for; the creation time; the payload inventory digest and file count; the local state schemas this PiShip version reads; the passed tests; the SBOM digest and package count; the vulnerability verdict and counts; the registry signature verdict and any packages without signatures; and a Pi attribution line. Distribution, PiShip, and Pi versions are recorded separately.

The archive is plain ustar in gzip: entries are sorted by byte order, with a fixed modification time (`SOURCE_DATE_EPOCH` or 0), owner 0, and mode `0755` for directories, `install.sh`, and payload launchers or `0644` otherwise; the gzip header's time and OS bytes are normalized. Symbolic links and special files are refused when archiving. Extraction accepts only regular files and directories under the expected root, refuses absolute, `..`, drive-letter, control-character, and (on Windows) reserved or ill-formed names, and stops at 2 GiB or 200,000 entries.

## Verifying a release

`piship verify-release <archive|release-dir>` is the consumer check, and also runs inside `install.sh`, `install.ps1`, `piship install`, `sign-channel`, and every update. It fails with `INTEGRITY_FAILED` unless:

- For an archive: its SHA-256 matches `--sha256` when given and the `.sha256` sidecar when present, and it extracts cleanly under the rules above.
- `checksums.txt` lists every required release file, each file matches, and no listed path escapes the release root.
- Every payload file matches the payload inventory, with no missing or extra files, and the packaged manifest, lock, and npm lock agree with each other. The target need not be this machine unless the release is being installed.
- `release.json` agrees with the payload: distribution ID, version, command, Pi and PiShip versions, lock schema and digest, inventory digest, and target.
- The SBOM lists exactly the packages installed in the payload, by name, version, and payload path, each with a `DEPENDS_ON` relationship; the notices index covers every SBOM package.
- The recorded vulnerability verdict is `passed` and the required tests are recorded as passed.

These checks prove the release is complete and internally consistent. They do not prove who built it: anyone can produce a consistent release. Publisher identity comes from the channel signature for updates, and from build provenance for CI-built artifacts. `--json` prints `release.json`.

## Reproducibility

`piship reproducibility <release-a> <release-b> [--out report.json]` verifies both releases, refuses to compare different distributions, versions, or targets, and writes a `piship-reproducibility/v1` report. Payload equality is the claim: every declared payload path and SHA-256 must match, and the command exits 1 otherwise, listing the differing paths. Wrapper files (`release.json`, SBOM, notices, scan result, install scripts) and whole-archive equality are reported separately. A new vulnerability advisory published between two builds changes `vulnerabilities.json` without changing the payload. Equality is claimed only per target: `metadata/target.json` and native package files differ between targets by design.

In CI, the `release-candidate` workflow builds each target twice on separate runners, each from a fresh checkout and `npm ci`, with the same `SOURCE_DATE_EPOCH`, and fails unless `piship reproducibility` passes on the two archives ([Build provenance](#build-provenance)).

## Reviewing a change

`piship diff <before> <after> [--json]` compares two distribution locks, taken from manifests (which must have a current lock), lock files, payloads, releases, archives, or installed IDs; older lock schemas compare too. It reports each change by area (distribution, schema, Pi, PiShip, packages, resources, extensions, providers, capabilities, policy, MCP, sandbox, audit, access, models, network, updates, and release) as added, removed, or changed, with a `low`, `medium`, or `high` risk and a reason; for example, a policy effect that loosens or a new pinned key. It ends with the highest risk and the tests a reviewer should require, such as the Pi compatibility suite or the release update and rollback E2E. Values are versions, IDs, effects, templates, and shortened digests; environment values, settings text, and key material are not shown. The report is `piship-diff/v1` with `--json`.

## SBOM, notices, and vulnerabilities

The SBOM is SPDX 2.3 JSON built by walking every `package.json` under the payload's `node_modules`, including nested and scoped packages. Each package records its name, version, payload path (`sourceInfo: payload:<path>`), declared license when it is a simple SPDX expression (otherwise `NOASSERTION`), a `pkg:npm` purl, and, when the lock has them, its npm source URL and SHA-512 checksum. The distribution itself is the described root package.

`licenses/THIRD_PARTY_NOTICES.txt` reproduces each package's `LICENSE`, `LICENCE`, `COPYING`, and `NOTICE` files from its package root. A package that ships none gets an explicit "No license file is shipped" entry with its declared license.

The dependency scan runs `npm audit --omit=dev --json` over the payload's npm lock and applies `release.vulnerabilities`:

- A finding at or above `failOn` (`low`, `moderate`, `high`, or `critical`; default `high`) is blocking unless its advisory ID is listed in `allow` with an `expires` date that is today or later. Advisory IDs are the GHSA ID from the advisory URL, or `npm-<source>` otherwise.
- An expired exception no longer applies, so the build fails again until the dependency is fixed or the exception is reviewed and renewed.
- Findings below `failOn` are recorded as `below-threshold`.
- A scan that cannot run, for example without registry access, fails the build: there is no release without a scan.

`vulnerabilities.json` keeps every finding with its status, so the result travels with the artifact. The scan reflects the advisory database at build time only.

## Build provenance

Release candidates for the PiShip demo are built by the `release-candidate` GitHub Actions workflow on each evidenced target (`linux-x64`, `darwin-arm64`, `win32-x64`). Its jobs:

- `build` builds every target twice, as `first` and `second`, on separate runners. Each does a fresh checkout, `npm ci`, `npm run build`, and `piship release --channel candidate` with `SOURCE_DATE_EPOCH` set to the commit time, and uploads the archive and its `.sha256` as the workflow artifact `release-<target>-<build>`.
- `reproducibility` downloads both builds of a target and runs `piship reproducibility` on them. The job fails unless the payloads are equal, and it uploads the report as `reproducibility-<target>`.
- `attest` creates a GitHub artifact attestation with `actions/attest-build-provenance` for the `first` archive of each target. This is a Sigstore keyless signature bound to the workflow identity and to the ref the run was for. The workflow runs only when a maintainer starts it (`workflow_dispatch`) on the exact candidate commit; it does not run for pull requests or `main` pushes. The job still carries a condition that skips it for pull requests from forks, which cannot obtain the signing token; it is left over from the earlier pull request trigger.
- `verify` runs on a fresh runner per target that did not build the archive. It verifies the `first` archive with `piship verify-release --sha256`, and checks its attestation with `gh attestation verify --repo --signer-workflow --source-ref "$GITHUB_REF"` when one was made. It then requires rejection of tampered inputs: an archive with a flipped byte (by `verify-release` and by `gh attestation verify`), a wrong expected digest, and, each in a fresh extraction, a modified payload file, a modified `release.json`, and a modified `checksums.txt` line (`INTEGRITY_FAILED`). Finally it installs the archive with the shipped `install.sh` or `install.ps1` and runs `acmecode version`.

Only the `first` build is attested, verified, and installed. The `second` build exists only for the comparison. Artifacts are kept only as workflow artifacts.

On `linux-x64` and `darwin-arm64` the workflow builds from a copy of `examples/demo-company` with its committed, reviewed `piship.lock` and does not run `piship lock`, so the release `lock` gate proves that the committed lock is current. The demo requires the OS sandbox, which the `sandbox` gate refuses on `win32-x64`. The Windows candidate is therefore a variant built from a patched copy with `sandbox.required: false`, as the lifecycle E2E does, and its lock is generated in CI rather than reviewed and committed.

To check a downloaded candidate yourself:

```bash
gh attestation verify acmecode-1.1.0-linux-x64.tar.gz --repo tc3oliver/piship \
  --signer-workflow tc3oliver/piship/.github/workflows/release-candidate.yml \
  --source-ref refs/heads/main
npm exec -- piship verify-release acmecode-1.1.0-linux-x64.tar.gz
```

A run dispatched on another branch carries a valid attestation from the same workflow that records its own ref (`refs/heads/<branch>`), and runs from before v0.5, when the workflow also ran for pull requests, recorded `refs/pull/<n>/merge`. Accept an archive as a `main` build only when verification with `--source-ref refs/heads/main` passes. Without `--source-ref`, branch and pull request builds are accepted too. Without `--signer-workflow`, an attestation from any workflow in the repository is accepted.

The attestation proves which workflow run built the archive and for which ref. It is not a code review of the archive's content, and it depends on the integrity of GitHub Actions and the repository's workflow files.

## Channels and signed metadata

A distribution declares its channels in `updates` ([manifest](manifest.md#lifecycle-fields-v1alpha4)). The names are `stable`, `candidate`, and `dev`; `updates.channel` (default `stable`) is where users start, and `updates.channels` lists the channels users may pick. What each channel carries is the owner's decision. `piship release --channel` records the channel a build is meant for; `sign-channel` may add the same archive to another channel, so a candidate can be promoted without a rebuild, while its `release.json` keeps the original channel.

An update source is a directory, served as static files over HTTPS or read locally, containing:

```text
stable.json        piship-channel/v1 metadata
stable.json.sig    piship-signature/v1 Ed25519 envelope over the exact bytes of stable.json
acmecode-1.1.0-linux-x64.tar.gz
acmecode-1.1.0-darwin-arm64.tar.gz
...
```

The channel metadata names the distribution and channel, a monotonic `sequence`, an `expires` time, and for each release its version, target, archive name, archive SHA-256 and size, Pi and PiShip versions, and lock SHA-256.

- `piship keygen <file> --id <key-id>` writes a new Ed25519 private key (PKCS#8 PEM, mode 0600, refusing to overwrite) and prints the `updates.trust.keys` entry and the key's `sha256:` fingerprint. Keep the private key out of the repository, CI logs, and the manifest; only the public key is pinned.
- `piship sign-channel <channel-dir> <archive>... --channel <name> --key <file> --key-id <id>` verifies each archive with `verify-release`, copies it into the channel directory, adds or replaces its version and target entry while keeping the others, and writes and signs the metadata. The sequence defaults to the previous one plus one and must increase; `expires` defaults to 30 days. A channel belongs to one distribution. `sign-channel` does not check that the key is pinned by the distribution; an update with an unpinned key fails.
- Rotation: pin the new key next to the old one, ship a release with both, then sign with the new key and remove the old key in a later release. Key IDs are unique within `updates.trust.keys`.

Clients accept channel metadata only when the envelope names a pinned key and verifies with it, the metadata names this distribution and channel, it has not expired, and its sequence is not lower than the highest one this installation has already accepted for that channel. The highest accepted sequence is stored in the install receipt, so replaying older signed metadata is refused. Re-sign each channel before it expires; expired metadata stops updates until it is re-signed.

## Updating and rolling back

Users run the branded commands; `piship update <id>` and `piship rollback <id>` run the same commands through the active release:

```bash
acmecode update --check                 # verify what is available; change nothing
acmecode update                         # verify and activate the newest release on the channel
acmecode update --channel candidate     # switch to an allowed channel
acmecode update --from ./channel        # use another directory or URL than updates.source
acmecode update --accept-review         # proceed when the migration check requires review
acmecode rollback                       # return to the retained release
npm exec -- piship migrate-check acmecode <archive|release-dir|payload>
```

`update` needs a release-tracking install of a `piship/v1alpha4` release with at least one pinned key. It locks the installation against a concurrent update, rollback, or uninstall, repairs a state marker left behind by an interrupted operation, then:

1. Selects the channel: `--channel` must be in `updates.channels` (`POLICY_DENIED` otherwise) and is remembered after an update, not after `--check`; a remembered channel that is no longer allowed falls back to `updates.channel` with a notice.
2. Resolves `updates.source` from the environment, or uses `--from`. Only `https` sources, `http` on a loopback host, and local directories are accepted. Requests use the managed fetch with the distribution's proxy and CA settings, and never follow redirects. Only the host of the declared `updates.source` is added to a `privateOnly` allow list; a `--from` URL gets no such exception.
3. Reads and verifies the signed channel metadata as above.
4. Picks the newest release for this machine's target. If it equals the active version, reports up to date; if the channel lists no release for this target, reports up to date with a notice; if it is older, refuses the downgrade.
5. Downloads the archive into a staging directory and checks its size and SHA-256 against the signed entry, then runs `verify-release` for this target and checks that the release matches the signed entry (distribution, command, version, Pi version, lock digest). A release that records its Pi version as unsupported is refused.
6. Runs the candidate's `version` command as a launch check.
7. Runs the migration check against the local state (below). `unsupported` stops the update; `requires-review` stops it unless `--accept-review` is given (a `--check` reports it with a notice instead).
8. With `--check`, stops here and reports the available version, signing key, and migration report. The archive has been downloaded and verified, but nothing is activated.
9. Snapshots non-secret state, moves the verified payload into place, verifies it again, clears credential data the target cannot read, and switches the active release in one atomic step.

After an update, the previous active release is retained for rollback when `updates.rollback` is true in both the old and the new release. At most two releases are kept: the active one and one retained release; older ones are removed.

`rollback` switches back to the retained release. It re-verifies that payload against its inventory and runs its launch check, requires the same command name, and refuses a retained release newer than the active one (use `update` to move forward again). It runs the same migration check: `unsupported` stops it, and review notices are printed. Sessions, preferences, and user policy stay in place. The release rolled back from is kept as the retained release, but a second rollback is refused because it is newer; `update` downloads it again.

Updates and rollbacks record `runtime.update` and `runtime.rollback` audit events (allowed or denied, with versions and the error code, never content) for governed distributions, best effort, and count outcomes in `<state>/logs/metrics.json` as `update:ok`, `check:<code>`, `rollback:<code>`, and so on. `doctor` adds Supply Chain and Update sections: whether the active release was installed from a verified release, the active version, channel and allowed channels, source, number of trusted keys, the retained release, the last check, leftovers of an interrupted operation, and the lifecycle counters. `doctor` never contacts the update source.

## Migration check and local data

The migration check compares each local data class with the state schemas the target release reads (recorded in its lock and `release.json`; releases built before lock v1alpha4 are assumed to read the v1 schemas). It only reads the state directory, and `piship migrate-check` runs it standalone; it exits 1 on `unsupported`.

| Class | Path under the state directory | Update and rollback |
| --- | --- | --- |
| State marker | `state.json` (`piship-state/v1`) | Rewritten at each update and rollback activation with the distribution, version, Pi, and PiShip versions |
| Identity session | `identity/session.json` | Credential class: kept when the target reads its schema, otherwise cleared with its secret-store entry and reacquired by `login` |
| Runtime credential metadata | `credentials-metadata/inference.json` | Credential class: kept when readable, otherwise cleared with its secret-store entry and reacquired |
| File secret fallback | `secrets/` | Never copied, snapshotted, or restored; removed when any credential class is cleared |
| Preferences | `config/preferences.json` | Kept in place; `unsupported` when the target cannot read its schema; included in the snapshot |
| User policy rules | `config/policy.json` | Kept in place; included in the snapshot |
| Pi agent configuration | `agent/` | Owned by Pi and kept in place; Pi-native `auth.json` is a credential and never snapshotted |
| Sessions | `sessions/` | Kept in place; Pi migrates its session files forward. A target with an older Pi than the one that wrote existing sessions `requires-review` |
| Audit and metrics logs | `logs/` | Kept in place and append-only; `unsupported` when the target cannot read the newest audit event schema |
| Cache | `cache/` | Not migrated; safe to delete |
| Runtime data | `data/` | Kept in place |
| Migration snapshots | `migration/snapshots/` | The last three pre-update snapshots |

Verdicts are `safe`, `requires-review`, or `unsupported`; the report shows each class with its action (`keep`, `clear-and-reacquire`, `review`, or `refuse`) and reason. An unreadable file of a schema-versioned non-credential class is `unsupported`: PiShip never reinterprets data under another schema.

Before activating an update, PiShip copies `config/preferences.json` and `config/policy.json` into `<state>/migration/snapshots/<time>-<from>-to-<to>/` with a `piship-snapshot/v1` record that lists the credential paths it excluded. No command restores a snapshot; it is a manual recovery copy.

Credentials are never snapshotted, copied into a release, or restored. Rollback switches only the immutable payload, so it cannot bring back a credential that was revoked or cleared: after `logout`, a rolled-back release requires `login` again. When a credential class is cleared because the target cannot read it, the switching release first revokes the runtime credential at the broker's revoke endpoint, best effort, when the distribution declares one (a failure is a notice, and local clearing still happens). It then deletes the local secret-store entries each cleared class references and the metadata file. Identity tokens are cleared only locally: the identity provider's revocation endpoint is not called. Run `logout` first when identity tokens must also be revoked remotely.

## Install layout and atomic activation

```text
<install-home>/                           ~/.local/share/piship or PISHIP_INSTALL_HOME
  receipts/<id>.json                      piship-install/v1 receipt: the only record of the active release
  apps/<id>/launch.mjs                    reads the receipt and starts the active release
  apps/<id>/<version>/                    immutable payloads: the active one and at most one retained
  apps/<id>/.staging-*                    in-progress downloads; removed by the next operation
  apps/<id>/.lifecycle.lock               one update, rollback, or uninstall at a time (holder's process ID)
<bin-home>/<command>                      shim that runs launch.mjs; <command>.cmd on Windows
```

`piship install <payload|release-dir|archive>` accepts a payload directory as before, or a release, which it verifies for this target first. `install.sh` and `install.ps1` inside an extracted release run `verify-release` and then `install` on it. The receipt records each retained release (version, payload path, install time, and for releases the target, channel, Pi and PiShip versions, lock digest, and archive digest), the active and retained versions, the selected channel (an install starts on `updates.channel`, whatever channel the archive was built for), the highest accepted channel sequences, and the last check. Receipt paths must be the owned ones or the receipt is rejected.

Before activation, every file and directory of the new payload is flushed to disk, so a power loss after the switch cannot leave the receipt naming a missing or truncated release. Windows cannot flush directories and needs write access to flush a file, so there this step is best effort. On macOS Node's file flush (libuv 1.51 in Node 22.19) issues `F_FULLFSYNC`, falling back to `F_BARRIERFSYNC` and then `fsync` where a filesystem does not support it, so data reaches stable storage past the drive's write cache. Activation is then one receipt write: a temporary file is written, flushed to disk, and renamed over the receipt, and the directory is flushed where the filesystem allows it. The launcher reads the receipt on every start. An interruption before the rename leaves the old release active; after it, the new one. Staging directories and payloads the receipt does not name are removed by the next update or rollback, and `doctor` reports them in the meantime. Credential data the target cannot read is cleared just before the switch, so an interruption between those two steps leaves the old release active with the user signed out.

A receipt written by an earlier PiShip (without `schema`) is still read, launched, and uninstalled, but `update` and `rollback` need a reinstall: `uninstall`, then `install --use-existing-state`. `uninstall` removes the shim, launcher, every retained release, leftovers, and the receipt, and keeps state.

## Failure policy

Every failure happens before activation and leaves the active release and state unchanged, apart from the highest accepted channel sequence and the last check result, and, where noted, cleared credentials.

| Condition | Result |
| --- | --- |
| A release gate or required test fails, or the scan cannot run | `piship release` fails and removes its partial output |
| Archive, checksums, payload, SBOM, notices, or metadata do not verify | `INTEGRITY_FAILED` |
| No pinned keys, or no update source and no `--from` | `UPDATE_FAILED` |
| Signature by an unpinned key, altered metadata, wrong distribution or channel, expired metadata, or a replayed lower sequence | `INTEGRITY_FAILED` |
| Channel not in `updates.channels` | `POLICY_DENIED` |
| `updates.source` variable unset | `CONFIG_UNAVAILABLE` |
| Plain `http` to a non-loopback source | `NETWORK_DENIED` |
| Downloaded archive differs from its signed entry | `INTEGRITY_FAILED` |
| Older release offered, target Pi recorded unsupported, launch check fails, migration `unsupported`, or `requires-review` without `--accept-review` | `UPDATE_FAILED` |
| Another update or rollback is running | `UPDATE_FAILED` (retryable) |
| No retained release, retained release damaged or newer, different command, launch check fails, or migration `unsupported` | `ROLLBACK_FAILED` |

## Supported platforms

Releases are built only for `linux-x64` (Ubuntu), `darwin-arm64`, and `win32-x64`, the targets that the lifecycle E2E and the Release candidate workflow cover (current results are on the [status page](status.md#recorded-evidence)), and only when listed in `release.targets` (the default). `linux-arm64` and `darwin-x64` are accepted in the manifest but refused by the `target` gate. Node.js 22.19.0 or newer remains a separate prerequisite. A Windows release of a distribution that requires the OS sandbox is refused.

## Known limitations

- There is no macOS notarization or code signing, and no Windows Authenticode signing. Release archives and their scripts may be flagged or quarantined by the operating system.
- The local PiShip workspace packages are linked, not downloaded, so they are left out of the lock's package list; the payload inventory and the archive digest cover them. Any other package without an integrity value fails the `source` gate. Pi 0.87.1's own shrinkwrap omits integrity for five nested `@earendil-works` packages; the root npm lock records their registry integrity so `npm ci` verifies them, and a Pi upgrade must re-check this.
- Packages that ship no license or notice file are listed with their declared license only.
- The vulnerability verdict reflects `npm audit` and its advisory database at build time; it is not rechecked at install or update.
- Clearing an unreadable credential during update or rollback revokes the runtime credential only where the distribution declares a broker revoke endpoint, and only best effort; identity tokens are cleared locally without remote revocation.
- `update --check` downloads and verifies the full archive and runs its launch check, so it costs as much network and time as an update.
- A migration snapshot has no restore command.
- The channel host is trusted for availability: it can withhold updates until the metadata expires, but it cannot forge, alter, or roll back signed metadata that a client has already seen.
- Verification detects tampering while the verifying PiShip and the pinned keys are trusted; it is not a boundary against a local administrator.

## Release checklist

Nothing is published automatically: there is no GitHub Release, npm publication, or publish automation, and CI keeps artifacts only as workflow artifacts. The maintainer, Oliver, is the sole release approver. Before any publish step:

1. Confirm the `release-candidate` run for the exact commit on `main` passed on `linux-x64`, `darwin-arm64`, and `win32-x64`. It must show two builds on separate runners with equal payloads (the `reproducibility-<target>` reports), `verify-release` on a fresh job, and rejection of the tampered archive, the wrong digest, and the modified payload, `release.json`, SBOM, and `checksums.txt`, and an install with the shipped script on a fresh job. Attestations must verify with `gh attestation verify --repo tc3oliver/piship --signer-workflow tc3oliver/piship/.github/workflows/release-candidate.yml --source-ref refs/heads/main`. Also confirm a Portable E2E run on the same commit passed on all three targets, including the lifecycle scenarios (`tests/e2e/lifecycle-*.test.ts` and `tests/e2e/personal-lifecycle.test.ts`), and that CodeQL is green on it.
2. Confirm `examples/demo-company/piship.lock` was reviewed in the change that committed it, and that the Windows candidate is treated as the patched variant whose lock was generated in CI.
3. Confirm `npm run check` and `npm run test:compatibility` passed, and review `piship diff` between the previous and new release for its risk and required tests.
4. Review `vulnerabilities.json` and every `release.vulnerabilities.allow` exception and its expiry.
5. Confirm the pinned release keys, and that the private key is held outside the repository and CI.
6. Record the archive SHA-256 values and attestation results.
7. Obtain the maintainer's explicit written approval for this specific commit and these artifacts. Without it, nothing is signed into a channel or published anywhere.
8. Only then sign the channel with a higher sequence and publish its directory. Rolling back a bad release means signing a channel that offers a newer, fixed version; clients refuse downgrades, and users can run `rollback` locally.
