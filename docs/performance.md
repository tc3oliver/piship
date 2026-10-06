# Consumer performance measurements

Windows performance is primarily sensitive to file count and Defender's interception of each file operation. The consumer path verifies the archive digest and signed release bindings, extracts once into its version directory, and activates the receipt. Full payload verification and package audits belong to explicit diagnostics and release qualification. Old versions remain available for rollback; install and upgrade do not delete them.

`release.bundle: true` opts into a bundled JavaScript runtime. `release.strip: true` removes maps and declarations. Both change release bytes and require relocking. Bundling keeps upstream Pi packages unchanged and uses their public exports. The bundled payload retains runtime management commands (including install/update/rollback/doctor), but authoring another distribution with build/release requires the PiShip source checkout; use an unbundled payload when portable build tooling is needed. Bundling combines the framework and pinned Pi runtime; vendored Pi packages and distribution resources remain separate, so distributions with additional packages can contain more files than the sample. A single executable is not implemented: native modules, runtime assets, extension loading, and platform executables still require ordinary files.

## Reproduce on Windows

Run the following in PowerShell on the affected Windows machine, keeping its normal Defender settings. Node 24.21 or newer, npm 11, and Git are needed. Start inside your existing PiShip checkout:

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

The benchmark prepares two personal releases, creates fresh Ed25519 trust keys, signs a local update channel, and measures archive installation, the first installed `--smoke` launch that actually creates a Pi session, signed-channel upgrade, and the first Pi session after upgrade. Build, lock, npm audit, signature audit, release smoke checks, and channel signing happen outside consumer timings. It enables `release.strip: true` in its copied manifest and adds `release.bundle: true` for the candidate. It leaves your example manifests and existing installation unchanged.

Create a separate checkout for the baseline, then run the same candidate benchmark script against both revisions:

```powershell
$checkoutPath = (Get-Location).Path
$baselinePath = Join-Path (Split-Path $checkoutPath -Parent) 'piship-perf-baseline'
git worktree add --detach $baselinePath edc9125
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

Use a new baseline checkout path and empty measurement directories. `%LOCALAPPDATA%` normally places installation files on C:, matching a user installation; record any relocated drive. Output is retained for inspection; remove it separately after measurement. Reports contain elapsed milliseconds, installed payload and retained-version file counts, archive sizes, Node/OS/CPU details, and Pi session evidence. Record the commit IDs and Defender output alongside the reports. No model API key or external model call is needed. The script isolates install, state, bin, and the launched child processes' home inside the output directory; it does not change your shell's HOME or USERPROFILE.

These are process-cold first installed launches with filesystem caches warmed by extraction/build, not storage-cold launches after a reboot or flushed Windows cache. Release construction warms OS and Defender caches, so this setup can underestimate a fresh machine's cold boot. Baseline runs first, so results are not randomized. The local signed HTTP channel excludes internet latency. Repeat with fresh directories in reversed order to assess run-to-run variation. To measure storage-cold behavior, retain the installed candidate, reboot, and separately time its installed command's first actual session startup.

For a quick functional test without the baseline comparison:

```powershell
$measurementPath = Join-Path $env:LOCALAPPDATA ('PiShipPerformance-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-install.mjs --root . --out $measurementPath --bundle
Get-Content (Join-Path $measurementPath 'report.json')
```

## Operation estimates and remaining costs

File counts are measured after timings using directory enumeration. Create/open/delete counts below are structural estimates, not ETW or Process Monitor measurements; include directory operations, Node loader probes, Defender's own opens, and archive bytes when collecting OS-level counters.

| Operation | Previous consumer path, N payload files | Candidate consumer path, B bundled payload files |
| --- | --- | --- |
| Install creates | N extracted, then renamed; plus metadata/temp files | B extracted, plus a few metadata/temp files |
| Install content opens | At least 3N payload opens: two full verification passes and per-file flush; plus archive/metadata reads | Archive reads and a few metadata bindings; no per-file content hash |
| Upgrade creates | N archive entries extracted, then renamed | B extracted directly into the version directory |
| Upgrade verification/flush opens | At least 3N new-payload opens plus N active-payload verification opens; candidate version check and recovery can add more | A few metadata bindings; no full inventory pass or payload-tree flush |
| Startup verification opens | N per launch when verifyAtLaunch is enabled | Zero payload inventory/hash verification opens |
| Delete on successful activation | Temporary metadata trees; payload is renamed. Existing destination and obsolete versions can be deleted when recovered | No successful payload-tree deletion; retained rollback versions increase disk use |

Pi itself still opens runtime assets, extensions, resources, and native libraries. Defender scans extracted assets and bundled JavaScript, Node cold boot and Pi initialization remain, and archive download/decompression still consume time. `doctor` and `verify-release` deliberately provide full diagnostics and may be slow on Windows. Explicit uninstall/purge and failed-install recovery can delete trees outside the successful critical path.

## Results

The reported production baseline was approximately 7,451 files / 125 MB, 75–90 seconds of extra startup verification, and up to 12 minutes installing. Those numbers are user observations, not measurements made by this benchmark. Candidate Windows results must come from the managed-machine run; elapsed targets are not claimed as achieved without those measurements.

Script validation on the implementation checkout, **unbundled**, on macOS 27 / Apple M4 Max / Node 24.21.0: archive install 1.370 s, first Pi-session launch 0.986 s, signed-channel upgrade 1.654 s, first post-upgrade launch 0.722 s; 7,434 first-release payload files and 14,873 retained installation files after upgrade. This verifies the measurement flow and is not a Windows result or a bundled candidate result.

The baseline archive install already renamed its extracted payload (`install/install.ts`) and update renamed the verified payload (`update/update.ts`), so archive consumer creates are N rather than 2N. Copy avoidance primarily helps unpacked-directory installation; bundled archive installation reduces creates by reducing N itself. The baseline lower-bound open estimates come from `verifyRelease` → `verifyPayloadContents`, post-rename `verifyPayload`, and `syncTree`; update also calls `activeLock`. They exclude package/SBOM metadata reads, launch-check probes, recovery passes, and OS scanner work.


Final packaging/functionality validation on macOS (not a Windows performance conclusion): the personal sample has **117 total payload files, 50 runtime JavaScript files**, and a 4.89 MB archive. Its directly installed bundled release booted a real Pi session, upgraded through a signed channel, rolled back, booted again, and passed explicit full `verify-release`. The measured macOS times were 0.250 s install, 0.838 s first process startup, 0.524 s signed upgrade and 0.666 s first startup after upgrade; these confirm the flow works, and do not predict managed Windows timings.

Windows behavior still needs the affected machine: Defender/EDR scanning cost, C: write/rename timing, a running executable or native module's file locks, simultaneous session/update registration, process-cold versus reboot-cold boot, and network transfer latency. No Windows speed target is claimed from the macOS validation. The code retains version directories used by runtime leases and never overwrites a receipt-retained version with different archive bytes.

## Iterative local builds

`npm run build` compiles PiShip and prepares its build-input snapshot. `piship build <manifest>` separately assembles a distribution payload. Profile both without Bash or PowerShell timing wrappers:

```powershell
$profilePath = Join-Path $env:LOCALAPPDATA ('PiShipBuildProfile-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-build.mjs --root . --out $profilePath --label before --compile
```

The script copies the personal example twice, sets `release.strip: true` on both copies and `release.bundle: true` on one, locks them outside the measured path, and performs two consecutive builds against each unchanged manifest and lock in the same output directory. `--compile` first records TypeScript, build-input preparation, and CLI permission stages corresponding to `npm run build`. JSON and raw logs are retained. `PISHIP_DEBUG_TIMING=1` provides the payload stages. Uninstrumented time includes process startup, cleanup, and any phase without its own timing marker; it must not be labeled as pure bundling time.

After changing PiShip, recompile and reuse those same manifests and locks to measure the changed implementation:

```powershell
npm run build
node scripts/benchmark-build.mjs --root . --out $profilePath --label after --compile --reuse-manifests
Get-Content (Join-Path $profilePath 'before.json')
Get-Content (Join-Path $profilePath 'after.json')
```

If a runtime dependency, manifest, or resource changed, its lock becomes stale; create a fresh profile directory instead of using `--reuse-manifests`. These profiles use warm npm and filesystem caches, matching repeated local development. They are not release reproducibility evidence or Windows performance results.

Baseline on macOS 27 / Apple M4 Max / Node 24.21.0 before the local build cache change:

| Phase | Unbundled build 1 / 2 | Bundled build 1 / 2 |
| --- | --- | --- |
| Total | 2.432 / 2.835 s | 3.484 / 3.370 s |
| Runtime npm ci | 1.255 / 1.221 s | 1.236 / 1.217 s |
| Strip maps/declarations | 0.476 / 0.508 s | 0.487 / 0.500 s |
| Payload inventory hashing | 0.234 / 0.233 s | 0.232 / 0.235 s |
| PiShip/build-input copy | 0.205 / 0.208 s | 0.208 / 0.229 s |
| Uninstrumented remainder | 0.117 / 0.517 s | 1.174 / 1.039 s |
| Payload files | 7,436 / 7,436 | 117 / 117 |

The largest measured payload costs were npm installation, stripping, and inventory generation; bundled builds also had approximately one second of uninstrumented work including bundling. Incremental workspace build phases were TypeScript 56 ms, build-input preparation 121 ms, and CLI permission marking 21 ms. The original build-input preparation replaced 829 files even when unchanged (829 copies and 829 deletes). These are local measurements, not predictions for Defender-managed Windows.

Incremental build-input synchronization retains unchanged files. On the same macOS machine, the standalone preparation process fell from 140/118/118 ms to 41/39/39 ms across three runs. For 829 unchanged files, the operation counts changed from 829 copies and 829 deletes per run to zero copies, zero deletes, and zero source-content hash reads (metadata checks still occur). Files that change are refreshed, and removed or unexpected snapshot files are removed. The resulting generation marker lets the local runtime assembly cache identify an unchanged build-input snapshot.

After enabling the local assembly cache, the same unchanged manifests and locks produced:

| Measurement | Before, build 1 / 2 | After, first cache seed / unchanged rebuild |
| --- | --- | --- |
| Unbundled total | 2.432 / 2.835 s | 3.150 / 0.140 s |
| Bundled total | 3.484 / 3.370 s | 3.578 / 0.126 s |
| Unbundled files | 7,436 | 7,439 |
| Bundled files | 117 | 117 |
| Incremental TypeScript | 56 ms | 66 ms |
| Build-input preparation | 121 ms | 45 ms |
| CLI permission marking | 21 ms | 25 ms |

The unchanged second rebuild improved approximately 95% unbundled and 96% bundled. The first build still seeds the cache and assembles the payload; it did not become faster in this run. Small file-count changes reflect the added cache implementation and snapshot marker. Unchanged rebuilds skipped runtime npm installation, strip, inventory hashing, bundling, and output-tree replacement. Cache lookup/reuse took 9.4 ms unbundled and 0.7 ms bundled; the remaining approximately 126–130 ms was process startup and uninstrumented lock/CLI work.

On the first bundled cache-seeding build, explicit stage timing measured npm installation 1.288 s, bundling 0.952 s, and stripping 0.535 s: these are the three largest remaining build stages when runtime inputs change. First unbundled replacement also took 0.443 s deleting the previous output; the cache avoids that tree deletion on unchanged rebuilds. Release assembly bypasses this local cache and retains its independent full qualification path.
