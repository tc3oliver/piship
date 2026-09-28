# Release artifact contract

What a release archive contains, how it is verified, and what CI proves about how it was built. This page is part of the [release guide](../release.md); building and signing are in the [owner workflow](owner-workflow.md).

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

The payload's own `metadata/inventory.json` covers every payload file, so `checksums.txt` plus the inventory cover the whole release. `release.json` records the distribution ID, name, version, command, and deployment mode; the PiShip version; the Pi package, version, and its compatibility status, the weakest of the distribution's deployment surface, the `governance` surface when the distribution declares governance (every `piship/v1alpha3` or later manifest does), and the `lifecycle` surface, with each surface's status; the manifest and lock schemas and the lock SHA-256; the target; the channel it was built for; the creation time; the payload inventory digest and file count; the local state schemas this PiShip version reads; the passed tests; the SBOM digest and package count; the vulnerability verdict and counts; the registry signature verdict and any packages without signatures; and a Pi attribution line. Distribution, PiShip, and Pi versions are recorded separately.

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

Release candidates are built by the `release-candidate` GitHub Actions workflow on each evidenced target (`linux-x64`, `darwin-arm64`, `win32-x64`) for two distributions: the managed demo (`acmecode`, from `examples/demo-company`) and the personal example (`mypi`, from `examples/personal`). Its jobs:

- `build` builds every target twice, as `first` and `second`, on separate runners. Each does a fresh checkout, `npm ci`, `npm run build`, and `piship release --channel candidate` for both distributions with `SOURCE_DATE_EPOCH` set to the commit time, and uploads both archives and their `.sha256` files as the workflow artifact `release-<target>-<build>`.
- `reproducibility` downloads both builds of a target and runs `piship reproducibility` on each distribution's two archives. The job fails unless the payloads are equal, and it uploads the report as `reproducibility-<distribution>-<target>`.
- `attest` creates a GitHub artifact attestation with `actions/attest-build-provenance` for the `first` archive of each target. This is a Sigstore keyless signature bound to the workflow identity and to the ref the run was for. The workflow runs only when a maintainer starts it (`workflow_dispatch`) on the exact candidate commit; it does not run for pull requests or `main` pushes.
- `verify` runs on a fresh runner per distribution and target that did not build the archive. It verifies the `first` archive with `piship verify-release --sha256`, and checks its attestation with `gh attestation verify --repo --signer-workflow --source-ref "$GITHUB_REF"` when one was made. It then requires rejection of tampered inputs: an archive with a flipped byte (by `verify-release` and by `gh attestation verify`), a wrong expected digest, and, each in a fresh extraction, a modified payload file, a modified `release.json`, and a modified `checksums.txt` line (`INTEGRITY_FAILED`). 
- `install` runs on a fresh runner per distribution and target. It installs the `first` archive with the shipped `install.sh` or `install.ps1` and runs the branded `version` (`acmecode version` or `mypi version`). For `mypi` it then runs the installed release's offline `--smoke` and `doctor`; the managed demo's `--smoke` and `doctor` need a sign-in and are covered by Portable E2E.

Only the `first` build is attested, verified, and installed. The `second` build exists only for the comparison. Artifacts are kept only as workflow artifacts.

The personal example needs no sandbox, so every target builds it from a copy of `examples/personal` with its committed, reviewed `piship.lock`. On `linux-x64` and `darwin-arm64` the workflow builds the demo from a copy of `examples/demo-company` with its committed, reviewed `piship.lock` and does not run `piship lock`, so the release `lock` gate proves that the committed lock is current. The demo requires the OS sandbox, which the `sandbox` gate refuses on `win32-x64`. The Windows candidate is therefore a variant built from a patched copy with `sandbox.required: false`, as the lifecycle E2E does, and its lock is generated in CI rather than reviewed and committed.

To check a downloaded candidate yourself:

```bash
gh attestation verify acmecode-1.1.0-linux-x64.tar.gz --repo tc3oliver/piship \
  --signer-workflow tc3oliver/piship/.github/workflows/release-candidate.yml \
  --source-ref refs/heads/main
npm exec -- piship verify-release acmecode-1.1.0-linux-x64.tar.gz
```

A run dispatched on another branch carries a valid attestation from the same workflow that records its own ref (`refs/heads/<branch>`), and runs from before v0.5, when the workflow also ran for pull requests, recorded `refs/pull/<n>/merge`. Accept an archive as a `main` build only when verification with `--source-ref refs/heads/main` passes. Without `--source-ref`, branch and pull request builds are accepted too. Without `--signer-workflow`, an attestation from any workflow in the repository is accepted.

The attestation proves which workflow run built the archive and for which ref. It is not a code review of the archive's content, and it depends on the integrity of GitHub Actions and the repository's workflow files.

## Known limitations

- There is no macOS notarization or code signing, and no Windows Authenticode signing. Release archives and their scripts may be flagged or quarantined by the operating system.
- The local PiShip workspace packages are linked, not downloaded, so they are left out of the lock's package list; the payload inventory and the archive digest cover them. Any other package without an integrity value fails the `source` gate. Pi 0.87.1's own shrinkwrap omits integrity for five nested `@earendil-works` packages; the root npm lock records their registry integrity so `npm ci` verifies them, and a Pi upgrade must re-check this.
- Packages that ship no license or notice file are listed with their declared license only.
- The vulnerability verdict reflects `npm audit` and its advisory database at build time; it is not rechecked at install or update.
