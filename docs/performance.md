# Install, startup, and build performance

On Windows the cost of an install, an update, and every start is mostly the number of files: each one is created, written, closed, and scanned by Defender, and a payload of thousands of small files makes that the whole bill. The changes below cut that work three ways: fewer files (`release.bundle` and `release.strip`), fewer operations per file on the consumer path, and less repeated work in a release or a local build. Every number in this page is a macOS measurement unless it says otherwise. No Windows speed is claimed: Windows needs the measurement in [Reproduce on Windows](#reproduce-on-windows).

## What the consumer path does now

- **Install and update check what they can check cheaply.** An archive is hashed once: while it downloads (`update`), while its release metadata is read (`install`), or in the one pass that checks `--sha256` before anything is parsed. They then check the signed or expected bindings and six small metadata files (`release.json`, `piship.lock`, `piship.yaml`, `package-lock.json`, `metadata/target.json`, `metadata/inventory.json`), and extract. They no longer run `verify-release` (checksums, every payload file's hash, SBOM, notices, scan results), flush every extracted file, or boot the candidate as a launch check. `install.sh` and `install.ps1` run `install` only. Release qualification already ran those checks on the release, and an explicit `verify-release`, and `doctor` for an installed release, still run the full verification.
- **Extraction writes in parallel, straight into place.** Files up to 1 MiB are buffered and written by 8 writers at once, so the wait for each create, write, and close overlaps; larger files stream in order. The payload goes directly into `apps/<id>/<version>`, which nothing references until the receipt is written, so there is no staged payload to rename into place. Renaming a tree of thousands of files is what a scanner's open handle makes fail on Windows, and a staged payload would have to be written and then moved a second time. An interrupted install or update leaves only an unreferenced directory, which the next attempt moves aside with one rename instead of deleting thousands of files first. A retained release is never overwritten: updating to a version that is already retained reuses it only when the signed archive digest equals the one recorded for it.
- **Renames that Windows refuses are retried.** A scanner or indexer can hold a handle inside a directory, which makes its rename fail with `EPERM`, `EBUSY`, or `EACCES`. On Windows the install and update renames wait and retry for about 1.6 s; the final rename of a `piship build` output and the runtime cache's renames wait for about 4.5 s. Elsewhere those codes fail at once.
- **A start reads less.** The payload launcher reads only `metadata/target.json` and `piship.lock`; it does not walk the payload or read its inventory. A start no longer sweeps abandoned temporary directories, which `doctor` does, and the data retention sweep and the replacement of an outdated installed launcher run after a session ends instead of before it starts.
- **The launcher registers a launch, then lets go.** The installed `launch.mjs` takes the launch gate, writes the runtime lease itself, and releases the gate before the runtime loads. The gate is held for the few milliseconds registration takes, not for a cold load, so a second launch or an `update` waits for far less. The lease is written with the record `holdRuntimeLease` writes and is not flushed (a lease only means something while its process runs).
- **Nothing asks the system who a process is, unless it must.** Reading a process's start identity is a PowerShell start on Windows and a `ps` on macOS. Records now name a process by ID, host, start time, and a random instance, and carry a start identity only on Linux, where `/proc` gives it for free. A process that finds a record whose ID is in use and is not its own asks the system then; an uncontested start asks nothing. The tolerance between a recorded start time and the system's is 30 s (it was 5 s), because on Windows a first launch can spend seconds loading and scanning `node.exe` before Node's clock starts. The Windows command shim no longer runs `where node`: it runs `node` and turns the "not found" exit code (9009) into the same message.
- **fd and rg are checked by receipt.** The bundled search tools are copied to `<state>/agent/bin` and checked against the lock. A receipt beside them (`.piship-search-tools.json`) records each executable's digest, size, times, and file index. A start that finds the same fingerprint reads nothing; any change to the file, including one that restores its modification time, changes its change time and brings the full digest check back.
- **`runtime.verifyAtLaunch` decides what a start hashes and whether it keeps a code cache.** Unset or `false`: a start checks that each resource the distribution lists is still a regular file, and may use a V8 compile cache. `true`: it hashes each of those resources against the lock, and keeps no compile cache. It never walks the payload inventory either way (that is `doctor` and `verify-release`), and it does not change the digest checks that admit a Pi package's entry files or a certified resource, which always run. See [the manifest](manifest.md#v1alpha6-fields).
- **A bundled payload keeps a compile cache.** Node's `enableCompileCache` stores what V8 compiled of the bundled JavaScript in `<state>/<id>/cache/compile`, so the next start does not parse it again. It is used only for a bundled payload, only once the state directory exists (from the second launch), and not when the lock asks for `verifyAtLaunch: true` or cannot be read, because Node checks an entry against its source file, not against the lock.
- **The installed launcher is replaced after an update or rollback.** An update activates a release; it does not rewrite `launch.mjs`, so a user who installed long ago would keep an old registration and verification path. The launcher carries a build stamp, `// launcher-build: <12 hex>`: the start of the SHA-256 of its text, which `PISHIP_DEBUG_TIMING` prints. After `update` or `rollback` commits, `doctor`, and the end of a session, PiShip replaces an installed launcher whose text differs from what it would write, by writing a file beside it and renaming it over. Only the active installed release does this, and a file that is not a PiShip launcher for that distribution is left alone.

## What a release does now

`piship release` assembles the canonical payload, runs the gates, and archives it. What changed is how much of that runs at once and how much it repeats.

- **Stages overlap.** The registry scans (`npm audit` of the payload's npm lock, the audit of each vendored Pi package lockfile, and `npm audit signatures`) start together and run beside the SBOM and notices. Without bundling the smoke tests start beside the signature check. With bundling the signature check reads the packages bundling replaces, so it finishes first, then the bundle is made, then the tests run on what it leaves. The tests run side by side, each with its own throwaway state directory. Verdicts are still applied in a fixed order, and a failure still stops the release after every started stage has finished and cleaned up.
- **The archive is hashed while it is compressed.** The gzip header is normalized in the stream, so the file is neither reopened to patch it nor read again for its digest. Small files are read ahead of the compressor.
- **A release runtime cache holds the runtime bytes.** A release spends most of its time installing the same locked dependencies and bundling them. The cache stores those bytes and nothing else:
  - *Where*: `<piship cache>/runtime`, where the piship cache is `PISHIP_CACHE_HOME`, or `piship` under `XDG_CACHE_HOME`, `%LOCALAPPDATA%` on Windows, or `~/.cache` (the directory that also holds the `search-tools` downloads).
  - *Keys*: the installed dependency tree (`i-<20 hex>`) is keyed by the PiShip build input digest, the lock's `runtime` section (Pi version and npm lock), the platform and CPU, and Node's major.minor. The bundled runtime (`b-<20 hex>`) is keyed by that key, `release.strip`, and the esbuild version. A different Pi pin, npm lock, PiShip build, Node, or strip setting is a different entry.
  - *Reuse*: an entry is written whole by one directory rename and never changed. A hit places the files from it (hardlinks on Windows, where each created file is scanned; copy-on-write clones or copies elsewhere), leaves maps and declarations out when stripping, and takes the entry's recorded digests instead of hashing the tree again. A hit of the bundled runtime checks every file's size and SHA-256 first. The cache keeps the three newest dependency trees and six newest bundles, and removing old entries has a time budget, so a build never waits for it.
  - *Not reused*: the vendored Pi packages and the distribution's own resources, and every check on the result: `npm audit`, the signature check, SBOM, notices, the smoke tests, the metadata, checksums, and the archive. Those run on every release.
  - *Trust*: the cache is as trusted as the build machine's user account. An installed tree is checked by its file names and sizes when it is used, not by content, so a release meant for distribution should come from a clean machine (CI's runners start empty) or from `piship release --rebuild`, which bypasses the cache and runs `npm ci` and the bundler again. On `piship build`, `--rebuild` bypasses the local build stamp (below) instead.
- **Stage timings.** `PISHIP_DEBUG_TIMING=1` prints each stage as `release <stage>: N ms`, longest first, then one `piship-timing/v1` JSON line with each stage's start offset and duration. The stages are `release inputs`, `search tools`, `runtime assembly` (with `runtime cache hit`, `miss`, or `unusable`), `npm audit`, `pi package audits`, `signature audit`, `sbom`, `notices`, `smoke tests`, `bundle` (with `bundle cache hit` or `miss`), `metadata`, `checksums`, `archive`, `publish`, and `staging cleanup`. Stages that overlap are each counted in full, so they can add up to more than the total.

### Local and qualified artifacts

A release is the qualified artifact: its `release.json` records `qualification: qualified`, and its output says so. `piship build`, `dev`, and `test` produce an unqualified local build: no audit, no SBOM or notices, no recorded tests, not signed. Each writes `<out>/<id>.piship-qualification.json` beside the payload (never inside it, so a release still wraps the payload byte for byte). `piship build` says so when it finishes, `piship install` of such a directory warns, and `verify-release` refuses it. Install it for local testing; ship only what `piship release` produced.

## Bundling and stripping

`release.strip: true` removes source maps and TypeScript declarations, which a running Node process never reads (Markdown stays: Pi embeds prompt templates). `release.bundle: true` combines the framework and the pinned Pi runtime into a few large JavaScript files through upstream's public exports, keeps native and WASM assets and extension loading as ordinary files, and leaves public module shims so imports resolve. Both change the release bytes and need a relock (`piship lock <manifest>`). Neither is on by default in the schema; the personal and developer examples, which are what people install, turn both on. Vendored Pi packages and distribution resources stay separate files, so a distribution with more packages has more files than the personal example: the developer example, where its six vendored Pi packages are most of the files, goes from 29,318 files (408 MB) to 12,194 files (235 MB) with both options (`piship build` on macOS), which is fewer to scan but not a few hundred. A single executable is not implemented: native modules, runtime assets, extension loading, and platform executables still need ordinary files.

A bundled payload keeps the runtime commands (`install`, `update`, `rollback`, `doctor`, and the launch) but not the build-input snapshot, so it cannot run `build`, `release`, `dev`, or `test`: those fail with a message to build from the PiShip source checkout. Use an unbundled payload where portable build tooling is needed.

## Reproduce on Windows

Run the following in PowerShell on the affected Windows machine, keeping its normal Defender settings. Node 24.21 or newer, npm 11, and Git are needed. Start inside your existing PiShip checkout, at the revision to measure (this pull request's branch, `feat/payload-strip`, or `main` once it is merged):

```powershell
git fetch origin
git switch feat/payload-strip
git pull --ff-only origin feat/payload-strip
npm ci
npm run build
node --version
npm --version
git rev-parse HEAD
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureVersion
```

The benchmark prepares two personal releases, creates fresh Ed25519 trust keys, signs a local update channel, and measures archive installation, the first installed `--smoke` launch that actually creates a Pi session, signed-channel upgrade, and the first Pi session after upgrade. Build, lock, npm audit, signature audit, release smoke checks, and channel signing happen outside consumer timings. It sets `release.strip: true` in its copied manifest and adds `release.bundle: true` with `--bundle`, whatever the example declares, so without `--bundle` it builds a stripped, unbundled payload. With `--baseline` it adds neither key, so it can build a revision from before `release.strip` existed. It leaves your example manifests and existing installation unchanged.

The baseline is `0752f02`, the `main` commit this work started from, with none of the changes above. It is the oldest revision `--baseline` was run against (on macOS: the script completes and reports the install, upgrade, and start timings); earlier revisions are untested and may lack a CLI option or receipt field the script uses. Create a separate checkout for it, then run the same benchmark script against both revisions:

```powershell
$checkoutPath = (Get-Location).Path
$baselinePath = Join-Path (Split-Path $checkoutPath -Parent) 'piship-perf-baseline'
git worktree add --detach $baselinePath 0752f02
Push-Location $baselinePath
npm ci
npm run build
Pop-Location
$measurementPath = Join-Path $env:LOCALAPPDATA ('PiShipPerformance-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-install.mjs --root $baselinePath --out (Join-Path $measurementPath 'baseline') --baseline
node scripts/benchmark-install.mjs --root $checkoutPath --out (Join-Path $measurementPath 'candidate') --bundle
Get-Content (Join-Path $measurementPath 'baseline/report.json')
Get-Content (Join-Path $measurementPath 'candidate/report.json')
```

Use a new baseline checkout path and empty measurement directories. `%LOCALAPPDATA%` normally places installation files on C:, matching a user installation; record any relocated drive. Output is retained for inspection; remove it separately after measurement. Reports contain elapsed milliseconds, installed payload and retained-version file counts, archive sizes, Node/OS/CPU details, Pi session evidence, the modules a start loaded and its process spawns, and, where the revision reports them, its startup phases. Record the commit IDs and Defender output alongside the reports. No model API key or external model call is needed. The script isolates install, state, bin, and the launched child processes' home inside the output directory; it does not change your shell's HOME or USERPROFILE.

These are process-cold first installed launches with filesystem caches warmed by extraction and build, not storage-cold launches after a reboot or flushed Windows cache. Release construction warms OS and Defender caches, so this setup can underestimate a fresh machine's cold boot. The baseline runs first, so results are not randomized. The local signed HTTP channel excludes internet latency, and the script starts `launch.mjs` with Node directly, so the command shim's own cost (`cmd.exe` starting) is not measured. Repeat with fresh directories in reversed order to assess run-to-run variation. To measure storage-cold behavior, retain the installed candidate, reboot, and separately time its installed command's first actual session startup.

For a quick functional test without the baseline comparison:

```powershell
$measurementPath = Join-Path $env:LOCALAPPDATA ('PiShipPerformance-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-install.mjs --root . --out $measurementPath --bundle
Get-Content (Join-Path $measurementPath 'report.json')
```

### Where a start spends its time

`PISHIP_DEBUG_TIMING=1 <command> --smoke` (or an interactive start) prints each phase as `launch <phase>: N ms` and ends with one `piship-timing/v1` JSON line, `command: "launch"`, that also carries the marks, counters (`identity_spawns`), and notes (the installed and payload launcher builds, the distribution, PiShip, and Pi versions). Each phase is the time since the previous mark. In order: `launcher_start`, `gate_acquired`, `receipt_resolved`, `lease_held`, `gate_released`, `launcher_handoff` (the installed launcher), `node_entry`, `payload_checked`, `pi_environment_ready`, `pi_loaded` (the payload launcher), `launch_pi_distribution`, `search_tools_start`, `search_tools_done`, `access_prepared`, the `governance_*` marks, `governance_open`, `resources_verified`, `resources_loaded`, `agent_session_start`, `pi_initialized`, `ui_ready` (interactive starts only, once the terminal UI is up), and `process_exit`. `launcher_start` is the time Node took to start and read the installed launcher; `node_entry` is the same for the payload launcher.

## Operation estimates and remaining costs

File counts are measured after timings using directory enumeration. Create, open, and delete counts below are structural estimates read from the code, not ETW or Process Monitor measurements; include directory operations, Node loader probes, Defender's own opens, and archive bytes when collecting OS-level counters. `scripts/benchmark-install.mjs` prints the same estimates in its report.

| Operation | Before: N payload files | After: B payload files |
| --- | --- | --- |
| Install creates | N extracted into a staging directory, then renamed; plus metadata and temporary files | B extracted straight into the version directory; plus 6 small metadata files read from the archive and a few receipt files |
| Install content opens | At least 3N payload opens: two full verification passes and a flush of each file; the archive hashed twice | The archive read for its digest and metadata and once more to extract; no per-file hash and no flush |
| Update creates | N extracted, then renamed into place | B extracted straight into the version directory |
| Update content opens | At least 4N: the new payload verified twice and flushed, plus the active payload verified; and a launch check that starts the candidate | The archive's digest from the download, 6 small metadata files, and the active payload's metadata; no inventory pass, no flush, no candidate start |
| Start, file reads | N payload hashes at every start | None for the payload; a lock read, the receipt, and the resources the distribution loads |
| Start, process spawns | A start-identity lookup (`powershell.exe` or `ps`) at every start, and `where node` in the Windows shim | None unless a contested record has to be judged |
| Delete on a successful install or update | Temporary metadata trees; the payload is renamed | None: retained versions stay for rollback, and an abandoned directory is renamed aside, not deleted |

Pi itself still opens runtime assets, extensions, resources, and native libraries. Defender still scans extracted and bundled files, Node's cold boot and Pi initialization remain, and archive download and decompression still take time. `doctor` and `verify-release` deliberately run full diagnostics and can be slow on Windows. Explicit `uninstall`, `purge`, `repair`, and `doctor`'s sweeps delete trees outside the successful critical path.

## Results

All of this is macOS 27, Apple M4 Max, Node 24.21.0, warm OS and npm caches, with other processes using the machine, so treat differences of a few percent as noise. None of it is a Windows result.

The reported production baseline on Windows was approximately 7,451 files and 125 MB, 75 to 90 seconds of extra startup verification, and up to 12 minutes installing. Those are user observations, not measurements made by this benchmark, and no elapsed target is claimed as achieved without a managed-machine run.

### Install, update, and start

`scripts/benchmark-install.mjs` on the personal example, run for the baseline (`0752f02`, `--baseline`) and the candidate (this branch, once without and once with `--bundle`):

| | Baseline | Candidate, stripped | Candidate, bundled and stripped |
| --- | --- | --- | --- |
| Payload files | 17,170 | 7,451 | 117 |
| Archive size | 37.4 MB | 35.7 MB | 4.9 MB |
| Archive install | 3.45 s | 0.74 s | 0.20 s |
| First installed `--smoke` start | 1.28 s | 0.80 s | 0.66 s |
| Signed-channel upgrade | 5.71 s | 0.94 s | 0.43 s |
| First start after upgrade | 1.32 s | 0.77 s | 0.71 s |
| Files on disk after the upgrade (two versions retained) | 34,343 | 14,905 | 237 |
| JavaScript modules a start loads | 1,919 | 1,927 | 10 |
| Process spawns in a start | 2 (`ps`, `node`) | 1 | 1 |

The bundled start spends its time in loading the bundle (`pi_environment_ready`, about 160 ms), activating the sandbox (`governance_sandbox_active`, about 230 ms), and starting MCP servers (about 25 ms); the launcher's own registration steps add up to under 2 ms apart from Node's start. Bundling mostly removes the install and upgrade cost and the module loading; the start itself is dominated by work this change does not touch.

Measured one change at a time while this was built, also on macOS:

- Install: 1.48 s to 0.72 s from an archive and 1.02 s to 0.54 s from a directory; update 1.97 s to 1.19 s.
- Release (`scripts/benchmark-build.mjs --release`), warm: unbundled 6.2 s to 4.7 s, bundled 5.6 s to 3.1 s, and a bundled release with a warm runtime cache about 2.1 s. Hash reads per release fell from about 8,300 to 854 for a warm bundled release.
- Start: process spawns 2 to 1, and `--smoke` of a bundled payload 663 ms to 610 ms.

### Iterative local builds

`npm run build` compiles PiShip and prepares its build-input snapshot. `piship build <manifest>` separately assembles a distribution payload, and on an unchanged manifest and lock it reuses the earlier output. A stamp beside the output (`dist/<id>.piship-build.json`, never in the payload) records the key of what decided its bytes: the build input digest, the npm lock, the locked packages and search tools, the release policy, the platform and Node version, and the bundle and strip settings. An unchanged key reuses the payload as it is; a changed manifest, lock, or resource with the same runtime key refreshes only the distribution files. `piship build --rebuild` ignores the stamp. `release` does not use the stamp; it uses the runtime cache above. Profile both without Bash or PowerShell timing wrappers:

```powershell
$profilePath = Join-Path $env:LOCALAPPDATA ('PiShipBuildProfile-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-build.mjs --root . --out $profilePath --label before --compile
```

The script copies the personal example twice, sets `release.strip: true` on both copies and `release.bundle: true` on one, locks them outside the measured path, and performs two consecutive builds against each unchanged manifest and lock in the same output directory. `--compile` first records TypeScript, build-input preparation, and CLI permission stages corresponding to `npm run build`. `--release` times `piship release` instead (it needs registry access for its audits) and records its stages from the `piship-timing/v1` summary. JSON and raw logs are retained. Uninstrumented time includes process startup, cleanup, and any phase without its own timing marker; it must not be labeled as pure bundling time.

After changing PiShip, recompile and reuse those same manifests and locks to measure the changed implementation:

```powershell
npm run build
node scripts/benchmark-build.mjs --root . --out $profilePath --label after --compile --reuse-manifests
Get-Content (Join-Path $profilePath 'before.json')
Get-Content (Join-Path $profilePath 'after.json')
```

If a runtime dependency, manifest, or resource changed, its lock becomes stale; create a fresh profile directory instead of using `--reuse-manifests`. These profiles use warm npm and filesystem caches, matching repeated local development. They are not release reproducibility evidence or Windows performance results.

Before the local build stamp and runtime cache, on the same machine:

| Phase | Unbundled build 1 / 2 | Bundled build 1 / 2 |
| --- | --- | --- |
| Total | 2.432 / 2.835 s | 3.484 / 3.370 s |
| Runtime npm ci | 1.255 / 1.221 s | 1.236 / 1.217 s |
| Strip maps/declarations | 0.476 / 0.508 s | 0.487 / 0.500 s |
| Payload inventory hashing | 0.234 / 0.233 s | 0.232 / 0.235 s |
| PiShip/build-input copy | 0.205 / 0.208 s | 0.208 / 0.229 s |
| Uninstrumented remainder | 0.117 / 0.517 s | 1.174 / 1.039 s |
| Payload files | 7,436 / 7,436 | 117 / 117 |

The largest costs were npm installation, stripping, and inventory generation; a bundled build added about a second of uninstrumented work that includes bundling. The original build-input preparation replaced 829 files even when unchanged (829 copies and 829 deletes); it now keeps unchanged files, and the standalone preparation fell from 140, 118, and 118 ms to 41, 39, and 39 ms over three runs, with zero copies, deletes, and source-content hash reads for those 829 files (metadata checks still happen). A generation marker in the snapshot lets the caches tell an unchanged build input from a changed one.

With the stamp, the same unchanged manifests and locks produced:

| Measurement | Before, build 1 / 2 | After, first build / unchanged rebuild |
| --- | --- | --- |
| Unbundled total | 2.432 / 2.835 s | 3.150 / 0.140 s |
| Bundled total | 3.484 / 3.370 s | 3.578 / 0.126 s |
| Unbundled files | 7,436 | 7,439 |
| Bundled files | 117 | 117 |

An unchanged rebuild is about 95% faster unbundled and 96% faster bundled: it skips the runtime npm install, strip, inventory hashing, bundling, and output replacement. The first build still seeds the stamp and assembles the payload, and was not faster in that run; its largest stages when the runtime inputs change are npm installation (1.288 s), bundling (0.952 s), and stripping (0.535 s). A release gets the same effect from the runtime cache even on a fresh output directory, which is what the release timings above show.

## Not measured

Windows behavior still needs the affected machine: Defender and EDR scanning cost, C: write and rename timing, file locks held by a running executable or native module, simultaneous session and update registration, process-cold versus reboot-cold boot, and network transfer latency. The code retains version directories used by runtime leases and never overwrites a receipt-retained version with different archive bytes.
