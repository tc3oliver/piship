# Install, startup, and build performance

On Windows the cost of an install, an update, and every start is mostly the number of files: each one is created, written, closed, and scanned by Defender, and a payload of thousands of small files makes that the whole bill. The changes below cut that work three ways: fewer files (`release.bundle` and `release.strip`), fewer operations per file on the consumer path, and less repeated work in a release or a local build. Every number in this page is a macOS measurement unless it says otherwise. No Windows speed is claimed: Windows needs the measurement in [Reproduce on Windows](#reproduce-on-windows).

## What the consumer path does now

- **Install and update verify while they extract, once.** The archive is read once and extracted once. In that same pass its SHA-256 and the SHA-256 of every file written are computed, and before the receipt is written they are compared with what the release binds: the archive digest with the signed channel entry (or `--sha256`), and the file digests with the payload inventory that the signed or expected release metadata covers. A mismatch fails the install or update with the version directory still unreferenced. A directory install hashes each file as it copies it. So an install is verified without a second read or open of any payload file. They no longer run `verify-release` (the checksums file, SBOM, notices, scan results), flush every extracted file, or boot the candidate as a launch check. `install.sh` and `install.ps1` run `install` only. Release qualification already ran those other checks on the release, and an explicit `verify-release`, and `doctor` for an installed release, still run the full verification.
- **Extraction writes in parallel, straight into place.** Files up to 1 MiB are buffered and written by 8 writers at once, so the wait for each create, write, and close overlaps; larger files stream in order. The payload goes directly into `apps/<id>/<version>`, which nothing references until the receipt is written, so there is no staged payload to rename into place. Renaming a tree of thousands of files is what a scanner's open handle makes fail on Windows, and a staged payload would have to be written and then moved a second time. An interrupted install or update leaves only an unreferenced directory, which the next attempt moves aside with one rename instead of deleting thousands of files first. A retained release is never overwritten: updating to a version that is already retained reuses it only when the signed archive digest equals the one recorded for it.
- **Renames that Windows refuses are retried.** A scanner or indexer can hold a handle inside a directory, which makes its rename fail with `EPERM`, `EBUSY`, or `EACCES`. On Windows the install and update renames wait and retry for about 1.6 s; the final rename of a `piship build` output and the runtime cache's renames wait for about 4.5 s. Elsewhere those codes fail at once.
- **A start reads little, and checks what carries trust.** Every launch reads `metadata/target.json` and then hashes `piship.lock`, the small file that carries `policy.enforced` and decides what runs, against the digest the receipt recorded when the release was installed; a mismatch stops the launch with `INTEGRITY_FAILED`. The check is skipped, not failed, where there is nothing to compare with: a build directory, another install home, an unreadable receipt, and an installation recorded before the receipt carried the digest. It does not walk the rest of the payload or hash its inventory, unless the lock asks for `runtime.verifyAtLaunch: true` (below). A start no longer sweeps abandoned temporary directories, which `doctor` does, and the data retention sweep and the replacement of an outdated installed launcher run after a session ends instead of before it starts.
- **Old versions are reclaimed by `doctor`, never on the critical path.** Install, update, and launch never delete a version directory. `doctor` removes obsolete version directories and the `.retained-*` directories that a replaced or interrupted update set aside, within a time budget, and keeps the active version and the rollback target; whatever the budget leaves waits for the next `doctor`.
- **The launcher registers a launch, then lets go.** The installed `launch.mjs` takes the launch gate, writes the runtime lease itself, and releases the gate before the runtime loads. The gate is held for the few milliseconds registration takes, not for a cold load, so a second launch or an `update` waits for far less. The lease is written with the record `holdRuntimeLease` writes and is not flushed (a lease only means something while its process runs).
- **Nothing asks the system who a process is, unless it must.** Reading a process's start identity is a PowerShell start on Windows and a `ps` on macOS. Records now name a process by ID, host, start time, and a random instance, and carry a start identity only on Linux, where `/proc` gives it for free. A process that finds a record whose ID is in use and is not its own asks the system then; an uncontested start asks nothing. The tolerance between a recorded start time and the system's is 30 s (it was 5 s), because on Windows a first launch can spend seconds loading and scanning `node.exe` before Node's clock starts. The Windows command shim no longer runs `where node`: it runs `node` and turns the "not found" exit code (9009) into the same message.
- **fd and rg are checked by receipt.** The bundled search tools are copied to `<state>/agent/bin` and checked against the lock. A receipt beside them (`.piship-search-tools.json`) records each executable's digest, size, times, and file index. A start that finds the same fingerprint reads nothing; any change to the file, including one that restores its modification time, changes its change time and brings the full digest check back.
- **`runtime.verifyAtLaunch` decides how much a start verifies and whether it keeps a code cache.** Unset or `false`: a start checks the trust-bearing files against the receipt and that each resource the distribution lists is still a regular file, and may use a V8 compile cache. `true`: it runs the full payload verification, the same inventory check as `doctor`, and keeps no compile cache. It does not change the digest checks that admit a Pi package's entry files or a certified resource, which always run. See [the manifest](manifest.md#v1alpha6-fields).
- **A bundled payload keeps a compile cache.** Node's `enableCompileCache` stores what V8 compiled of the bundled JavaScript in `<state>/<id>/cache/compile`, so the next start does not parse it again. It is used only for a bundled payload, only once the state directory exists (from the second launch), and not when the lock asks for `verifyAtLaunch: true` or cannot be read, because Node checks an entry against its source file, not against the lock.
- **The installed launcher is replaced after an update or rollback.** An update activates a release; it does not rewrite `launch.mjs`, so a user who installed long ago would keep an old registration and verification path. The launcher carries a build stamp, `// launcher-build: <12 hex>`: the start of the SHA-256 of its text, which `PISHIP_DEBUG_TIMING` prints. After `update` or `rollback` commits, `doctor`, and the end of a session, PiShip replaces an installed launcher whose text differs from what it would write, by writing a file beside it and renaming it over. Only the active installed release does this, and a file that is not a PiShip launcher for that distribution is left alone.

## What a release does now

`piship release` assembles the canonical payload, runs the gates, and archives it. What changed is how much of that runs at once and how much it repeats.

- **Stages overlap.** The registry scans (`npm audit` of the payload's npm lock, the audit of each vendored Pi package lockfile, and `npm audit signatures`) start together and run beside the SBOM and notices. Without bundling the smoke tests start beside the signature check. With bundling the signature check reads the packages bundling replaces, so it finishes first, then the bundle is made, then the tests run on what it leaves. The tests run side by side, each with its own throwaway state directory. Verdicts are still applied in a fixed order, and a failure still stops the release after every started stage has finished and cleaned up.
- **The archive is hashed while it is compressed.** The gzip header is normalized in the stream, so the file is neither reopened to patch it nor read again for its digest. Small files are read ahead of the compressor.
- **A release runtime cache holds the runtime bytes.** A release spends most of its time installing the same locked dependencies and bundling them. The cache stores those bytes and nothing else:
  - *Where*: `<piship cache>/runtime`, where the piship cache is `PISHIP_CACHE_HOME`, or `piship` under `XDG_CACHE_HOME`, `%LOCALAPPDATA%` on Windows, or `~/.cache` (the directory that also holds the `search-tools` downloads).
  - *Keys*: the installed dependency tree (`i-<20 hex>`) is keyed by the PiShip build input digest, the lock's `runtime` section (Pi version and npm lock), the platform and CPU (and, on Linux, the libc family), and the major.minor of Node and npm. The bundled runtime (`b-<20 hex>`) is keyed by that key, `release.strip`, and the esbuild version. A different Pi pin, npm lock, PiShip build, Node, or strip setting is a different entry.
  - *Reuse*: an entry is written whole and never changed. A hit places the files from it (hardlinks on Windows, where each created file is scanned; copy-on-write clones or copies elsewhere), leaves maps and declarations out when stripping, and takes the entry's recorded digests instead of hashing the tree again. A cache on another volume than the build cannot be filled by one rename, so the tree is copied into it instead. The cache keeps the three newest dependency trees and six newest bundles, and removing old entries has a time budget, so a build never waits for it.
  - *Not reused*: the vendored Pi packages and the distribution's own resources, and every check on the result: `npm audit`, the signature check, SBOM, notices, the smoke tests, the metadata, checksums, and the archive. Those run on every release.
  - *Trust and checks*: the cache has the trust of the owner's home directory: whoever can write it can change what a release contains. A bundled-runtime entry is content-hashed (size and SHA-256 of every file) at each lookup; an installed dependency tree is checked by its file set, the size of each file, and an entry digest. A cache hit, a miss, and a cold build give a byte-identical archive, `release.json`, and `checksums.txt`, so nothing a release covers records where its runtime came from. That is reported outside those files: one stderr line from `piship release` (`runtime cache: hit (entry <digest>, linked N, copied M, bundle hit)`), the `PISHIP_DEBUG_TIMING` output, and an unsigned `<out>/releases/<name>.build-info.json` beside the archive, which a rebuild replaces. **`piship release` uses this cache by default**, and it trusts the dependency tree by file names, sizes, and an entry digest, not by hashing its contents (bundle entries are content-hashed). A release meant to be published must therefore be built cold: with `piship release --rebuild` or `PISHIP_RELEASE_NO_CACHE=1`, which ignore the cache and run `npm ci` and the bundler again, or in CI release qualification, which starts with no cache. On `piship build`, `--rebuild` bypasses the local build stamp (below) instead.
- **Stage timings.** `PISHIP_DEBUG_TIMING=1` prints each stage as `release <stage>: N ms`, longest first, then one `piship-timing/v1` JSON line with each stage's start offset and duration. The stages are `release inputs`, `search tools`, `runtime assembly` (with `runtime cache hit`, `miss`, or `unusable`), `npm audit`, `pi package audits`, `signature audit`, `sbom`, `notices`, `smoke tests`, `bundle` (with `bundle cache hit` or `miss`), `metadata`, `checksums`, `archive`, `publish`, and `staging cleanup`. Stages that overlap are each counted in full, so they can add up to more than the total.

### Local and qualified artifacts

A release is the qualified artifact: its `release.json` records `qualification: qualified`, and its output says so. `piship build`, `dev`, and `test` produce an unqualified local build: no audit, no SBOM or notices, no recorded tests, not signed. Each writes `<out>/<id>.piship-qualification.json` beside the payload (never inside it, so a release still wraps the payload byte for byte). `piship build` says so when it finishes, `piship install` of such a directory warns, and `verify-release` refuses it. Install it for local testing; ship only what `piship release` produced.

## Bundling and stripping

`release.strip: true` removes source maps and TypeScript declarations, which a running Node process never reads (Markdown stays: Pi embeds prompt templates). `release.bundle: true` combines the framework and the pinned Pi runtime into a few large JavaScript files through upstream's public exports, keeps native and WASM assets and extension loading as ordinary files, and leaves public module shims so imports resolve. Both change the release bytes. Both are on by default from `piship/v1alpha6`: a manifest that omits them builds bundled and stripped, and `false` opts out (the earlier schemas cannot set them and never bundle). The personal and developer examples write them out as `true`; every other example takes the default. The lock records the keys only when the manifest writes them, so adding `false` to a manifest needs a relock and omitting them does not. Vendored Pi packages and distribution resources stay separate files, so a distribution with more packages has more files than the personal example: the developer example, where its six vendored Pi packages are most of the files, goes from 29,318 files (408 MB) to 8,999 files (210 MB) with both options (`piship build` on macOS; the strip also covers the vendored packages), which is fewer to scan but not a few hundred. Of those, 2,865 are repeated identical copies of the same dependency version in several vendored packages. [Pi package dependencies and closures](#pi-package-dependencies-and-closures) says how many of them PiShip now shares, and why it keeps the rest. The personal and developer examples also bundle `fd` and `rg` (`runtime.searchTools`): without them Pi downloads them from GitHub at the first prompt and its interactive start waits for it, 24 to 30 seconds measured, which no file-count reduction fixes. For the personal example they add 7 files and 3.1 MB to the archive (124 files and 8.0 MB, from 117 and 4.9 MB). A personal distribution that bundles neither, with neither tool on `PATH`, no longer lets Pi download them: the launch runs Pi offline for that start, records `tool_downloads_deferred` in the timing notes, and `doctor` warns; `PISHIP_ALLOW_TOOL_DOWNLOAD=1` restores Pi's download ([the manifest](manifest.md#bundled-search-tools-v1alpha6)). A single executable is not implemented: native modules, runtime assets, extension loading, and platform executables still need ordinary files.

A bundled payload keeps the runtime commands (`install`, `update`, `rollback`, `doctor`, and the launch) as bundled files, and carries the authoring inputs (the compiled workspace packages and the lock metadata) as one deterministic gzip file, `authoring.json.gz`, listed in the payload inventory. `build`, `release`, `dev`, and `test` expand it once into `<cache>/piship/authoring/<version>-<digest>/input` (private staging, an atomic rename, a file inventory checked at each reuse) and reuse that copy; a launch, `install`, `update`, `rollback`, and `doctor` never read, verify, or expand it, so the runtime hot path has no added file operations.

## Pi package dependencies and closures

`release.bundle` (on by default from `piship/v1alpha6`) also decides what a build does with the vendored Pi packages. Two things happen, in this order, and each is decided from the vendored files and recorded, never assumed.

**A bundle-safe closure is bundled; any other keeps its vendored files.** A Pi package loads through its extension files, which the lock pins by SHA-256 and every launch checks. Those files stay exactly as they are. What they import is replaced: each file an extension imports directly becomes a small module of the same name and exports that forwards to shared chunks, and the modules those pull in are bundled into the chunks and removed. A closure is bundle-safe only when nothing in it needs its files to exist: pure JavaScript, static imports, every import resolvable in the vendored tree, no native addon, no WebAssembly, no install script, no dynamic `import()` or `require()`, nothing that locates its own files (`__dirname`, `import.meta.url`) or discovers modules at run time (`require.resolve`, `createRequire`), no CommonJS or JSON or TypeScript module an extension imports directly, and no file left behind that imports a module that was bundled. The six packages of the developer example all fail a test (child processes of their own files, native code and WebAssembly, TypeScript closures, an extension that imports another), so all six keep their vendored files and the build output says which test each failed. A package that passes is bundled; one that does not is never bundled to save files.

**Identical dependencies are shared.** A dependency several vendored packages hold a copy of is shared only when every copy is the same package: the same name, the same version, the same registry integrity from the package's own npm lockfile, byte-identical content (and execute bits), and nothing that depends on the platform or on where it sits. That means a package with no dependencies of its own (they would resolve from where the package sits, which a shared directory does not reproduce), an `exports` map (without one any file can be imported by path, so the reachable set is unknown), no native code or WebAssembly, no install script or `os`/`cpu` field, no `bin`, no file that fails to parse, and no code that finds modules or files at run time. The real files then live once in `pi-packages/.shared/<name>@<version>-<digest>`. Each place that had a copy keeps its `package.json`, its license files (so the SBOM and the notices list the same packages at the same paths), the files `exports` names that are data (`.json`, declarations), and a one-line module for every code file `exports` can reach: `export * from "<shared file>"` (plus `export { default }` when the file has one) or `module.exports = require("<shared file>")`. Node resolves the dependency exactly where it did, through the same `exports` map, and lands in the shared file; a path the map does not list is still refused with the same error. A package that fails a test, or whose copies differ in any way, keeps a package-local copy at every place, and the report says which reason applied.

Why plain files. A symlink, a junction, or a hardlink would share the files without stand-ins, but a payload and its archive hold regular files only (`inventory` and the archive reader refuse a link, so an archive cannot make an installer create one), a symlink needs a privilege on Windows, a junction is an absolute path that a moved or renamed directory breaks, and a zip or tar made on one machine has to extract on another. Package-local forwarding modules need none of that, and the installed tree is the same kind of files as before. Whether linking at install time pays is a separate question, for the runtime store to answer by measurement.

What sharing changes and what it does not. The lock, the SBOM, the notices, and the locked resource digests are unchanged (a release of the developer example before and after has the same `piship.lock`, `sbom.spdx.json`, and notices, and differs only in its payload inventory). The entry files Pi loads are the locked bytes. The shared modules are loaded once, so two packages that used separate copies of a dependency now share one instance of it and its module state (zod's global registry, for example); a package that must not share a dependency's state keeps a copy by having a copy that differs. A dependent that reads a shared package's files from disk instead of importing them sees the forwarding modules there, not the package's other files; the scan refuses a package that locates its own files, not a dependent that does.

Where it is recorded. `metadata/pi-package-footprint.json` (inventoried like every payload file) holds each closure's decision with its findings, each shared dependency with its places and files saved, and the count of copies kept by reason. `piship build` prints two lines from it, and `doctor` shows the same in the installed payload:

```text
Pi package closures: 0 of 6 bundled; vendored: pi-code (entry-imports-entry, typescript-closure); pi-lens (install-script, native-addon, wasm-asset); ...
Pi package dependencies: 3 shared (716 fewer files); copies kept: no-exports 38, has-dependencies 37, single-copy 22, ...
```

On the developer example (macOS, `piship build`) the payload goes from 9,007 to 8,292 files and its archive from 43.8 MB to 42.0 MB (the archive of a qualified `piship release` of the same example: 43,783,864 to 41,958,539 bytes). Three dependencies are shared: zod (three copies, 592 files each, 157 kept per place), content-type 2.1.0 (six copies), and eventsource-parser. What remains is mostly dependencies that have dependencies of their own (the MCP SDK and the express stack under it, 37 packages), or no `exports` map (38 packages), where sharing would need the closure-level store of the next milestone. The step reads every vendored closure and candidate dependency (a few esbuild runs, started together) and costs about 1.0 s of a developer build on this machine; a distribution without Pi packages pays nothing. [The measurement below](#measuring-the-footprint) has the build, install, and start timings before and after.

## Measuring the footprint

`scripts/benchmark-footprint.mjs` runs one workload over the personal example, the managed reference (`examples/demo-company`), and the developer example, so a revision before a change and one after compare on identical inputs. Per distribution it records the payload file count and bytes, the archive bytes of the payload (as `createArchive` writes it), the installed file count (a `piship install` into an isolated home), a cold build (empty PiShip cache, `--rebuild`), a warm build (populated cache, new output) and an unchanged rebuild, the install time, and with `--startup` a first and a warm `--smoke` start; with `--release` it adds a cold and a warm `piship release` and the release archive bytes. `--runs N` repeats the whole workload and reports min, median, and max, and `--reverse` runs the distributions in the opposite order, so an order or cache bias shows when a baseline and a candidate are each measured both ways. It writes one JSON report and prints a table:

```sh
npm run build
node scripts/benchmark-footprint.mjs --out "$(mktemp -d)" --label candidate --runs 3 --startup
```

On Windows run it with `--windows` (it implies `--startup` and three runs and records the Defender status) from PowerShell, at the revision to measure and again at the baseline checkout, and again in the reverse order:

```powershell
$out = Join-Path $env:LOCALAPPDATA ('PiShipFootprint-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-footprint.mjs --root $baselinePath --out $out --label baseline --windows
node scripts/benchmark-footprint.mjs --root $checkoutPath --out $out --label candidate --windows
node scripts/benchmark-footprint.mjs --root $checkoutPath --out $out --label candidate-reversed --windows --reverse
```

The timings it prints are macOS or whatever machine ran it; none is a Windows result unless it ran there, and a single run on a hosted runner supports no claim of improvement. The managed distribution cannot start headlessly without a sign-in, so its start is recorded as an error, not a time. Build timings include `npm ci` of the vendored packages and so depend on the npm cache.

The deterministic figures are also budgeted. `scripts/performance-budgets.json` records, per platform and distribution, the payload files, installed files, and payload archive bytes; `npm run check:budgets` builds the personal and managed examples (about a minute, mostly the search-tool archives it fetches from GitHub once) and fails when a figure is more than 10% over its budget; one more than 10% under is reported so the budget can be tightened. It runs in the CI check job on every pull request. The developer example needs the registry, so `npm run check:budgets -- --developer` runs in the nightly Portable E2E workflow and Release qualification instead. `-- --record` rewrites the budget of the current platform from a fresh measurement, which is how a reviewer accepts a deliberate increase. A platform with no recorded budget says so and passes. Timings are never gated by a pull request: a median start that regresses more than 5%, or a build, install, or release that regresses more than 10%, is judged from the manual benchmark and needs an explanation in the pull request.

### Footprint results, v0.10.0 baseline against this change

`scripts/benchmark-footprint.mjs --runs 2 --startup`, forward order, and once more in the reverse order, on macOS 27 (Apple M4 Max), Node 24.21.0, warm npm and OS caches, with other work running on the machine, so a difference of a few percent is noise. The baseline is `8b3c278`, the commit this change started from. None of it is a Windows result.

| Developer example | Baseline | After | Change |
| --- | --- | --- | --- |
| Payload files | 9,007 | 8,292 | -715 (-7.9%) |
| Installed files | 9,009 | 8,294 | -715 |
| Payload bytes | 201.2 MB | 190.3 MB | -5.4% |
| Payload archive | 43.69 MB | 41.86 MB | -4.2% |
| Cold build (`--rebuild`) | 5.0 s | 6.0 s | +1.0 s |
| Warm build (runtime cache hit) | 4.0 s | 5.0 s | +1.0 s |
| Unchanged rebuild (build stamp) | 0.16 s | 0.16 s | |
| `piship install` of the payload | 0.88 s | 0.83 s | -5% |
| First `--smoke` start | 3.64 s | 3.61 to 3.71 s | |
| Warm `--smoke` start | 2.45 s | 2.39 s | |

The reverse-order runs agree with the forward ones to within about 2% on every row. The build gains a second because the step reads the vendored closures; nothing in a launch changes, and the installed payload has 715 fewer files to create and scan. The personal example's payload file count, install time, and start are unchanged (125 files, 0.37 s, 0.54 s warm); its archive is 0.5% larger (10.28 to 10.33 MB) and the managed reference's 0.7% (7.20 to 7.25 MB) because the compiled sharing and bundling code travels in the authoring snapshot. A qualified `piship release` of the developer example before and after has the same `piship.lock`, SBOM (358 packages), and notices, and the same payload with the files above removed; a cold release and a release from a warm runtime cache have identical payloads.

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

The benchmark prepares two personal releases, creates fresh Ed25519 trust keys, signs a local update channel, and measures archive installation, the first installed `--smoke` launch that actually creates a Pi session, signed-channel upgrade, and the first Pi session after upgrade. Build, lock, npm audit, signature audit, release smoke checks, and channel signing happen outside consumer timings. It sets `release.strip: true` in its copied manifest and `release.bundle: true` with `--bundle` or `release.bundle: false` without it, whatever the example declares, so without `--bundle` it builds a stripped, unbundled payload. With `--baseline` it adds neither key, so it can build a revision from before `release.strip` existed. It leaves your example manifests and existing installation unchanged.

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
| Install creates | N extracted into a staging directory, then renamed; plus metadata and temporary files | B extracted straight into the version directory; plus a few receipt files |
| Install content opens | At least 3N payload opens: two full verification passes and a flush of each file; the archive hashed twice | The archive read once. Each file is hashed from the bytes being written, so there is no second open and no flush |
| Update creates | N extracted, then renamed into place | B extracted straight into the version directory |
| Update content opens | At least 4N: the new payload verified twice and flushed, plus the active payload verified; and a launch check that starts the candidate | The archive's digest from the download, then one extraction that hashes each file as it writes it; the active payload's metadata; no inventory pass, no flush, no candidate start |
| Start, file reads | N payload hashes at every start | The lock, hashed once against the receipt, the receipt, and the resources the distribution loads; the whole payload only with `runtime.verifyAtLaunch: true` |
| Start, process spawns | A start-identity lookup (`powershell.exe` or `ps`) at every start, and `where node` in the Windows shim | None unless a contested record has to be judged |
| Delete on a successful install or update | Temporary metadata trees; the payload is renamed | None: retained versions stay for rollback, an abandoned directory is renamed aside, and `doctor` reclaims obsolete versions within a time budget |

Pi itself still opens runtime assets, extensions, resources, and native libraries. Defender still scans extracted and bundled files, Node's cold boot and Pi initialization remain, and archive download and decompression still take time. Installing from an extracted release directory copies each file and checks it against the inventory as it is copied. `PISHIP_INSTALL_LINK=1` is an opt-in alternative that hard-links the files instead (a link costs a directory entry, not a scanner's pass over a new file): the installed payload then shares inodes with the source directory, so any later write through that directory (unpacking over it again, an editor, antivirus remediation) changes what is installed and a launch does not rehash it. Use it only for a throwaway source on the same volume; a file that cannot be linked is copied.

`doctor` and `verify-release` deliberately run full diagnostics and can be slow on Windows. Explicit `uninstall`, `purge`, `repair`, and `doctor`'s reclaim of obsolete versions and temporary directories delete trees outside the successful critical path.

## Results

All of this is macOS 27, Apple M4 Max, Node 24.21.0, warm OS and npm caches, with other processes using the machine, so treat differences of a few percent as noise. None of it is a Windows result. The tables were measured before two changes described above, hashing each file during extraction and checking the trust-bearing files at every launch: both add CPU work, not file operations, and neither has been re-measured here, so run the benchmark again before quoting these numbers for the merged result.

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

### Windows: a GitHub-hosted runner

Measured on a GitHub-hosted `windows-latest` runner with Defender real-time protection enabled and its exclusions removed for the run, seconds, each figure as forward / reversed run order, with the baseline `0752f02` against the candidate `600dea7`. This is an earlier commit than the final code, and runner noise is large: it is not a claim about any maintainer's or user's machine.

| | Baseline | Candidate, bundled | Candidate, stripped unbundled |
| --- | --- | --- | --- |
| Cold build | 276 / 217 | 171 / 158 | |
| Warm build | 332 / 247 | 0.7 / 0.5 | |
| Build after a resource change | 303 / 235 | 0.6 / 0.5 | |
| Cold release | 335 / 239 | 170 / 145 | |
| Warm release | 318 / 255 | 35 / 36 | |
| Archive install | 110 / 124 | 1.2 / 1.3 | 44 / 47 |
| Upgrade | 127 / 130 | 3.3 / 2.4 | 48 / 46 |
| First `--smoke` launch | 6.7 / 8.1 | 5.2 / 4.8 | 8.9 / 9.1 |
| Installed files | 17,170 | 117 | 7,455 |
| Archive | 31.8 MB | 4.7 MB | 26.4 MB |

On this runner the file count dominated install and upgrade, as expected, and bundling removed nearly all of it. The first launch gained little, because Node and Pi initialization, not file operations, dominate it, and the unbundled launch was slower than the baseline in this run.

### Iterative local builds

`npm run build` compiles PiShip and prepares its build-input snapshot. `piship build <manifest>` separately assembles a distribution payload, and on an unchanged manifest and lock it reuses the earlier output. A stamp beside the output (`dist/<id>.piship-build.json`, never in the payload) records the key of what decided its bytes: the build input digest, the npm lock, the locked packages and search tools, the release policy, the platform and Node version, and the bundle and strip settings. An unchanged key reuses the payload as it is; a changed manifest, lock, or resource with the same runtime key refreshes only the distribution files. `piship build --rebuild` ignores the stamp. `release` does not use the stamp; it uses the runtime cache above. Profile both without Bash or PowerShell timing wrappers:

```powershell
$profilePath = Join-Path $env:LOCALAPPDATA ('PiShipBuildProfile-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-build.mjs --root . --out $profilePath --label before --compile
```

The script copies the personal example twice, sets `release.strip: true` on both copies and `release.bundle: true` on one and `false` on the other, locks them outside the measured path, and performs two consecutive builds against each unchanged manifest and lock in the same output directory. `--compile` first records TypeScript, build-input preparation, and CLI permission stages corresponding to `npm run build`. `--release` times `piship release` instead (it needs registry access for its audits) and records its stages from the `piship-timing/v1` summary. JSON and raw logs are retained. Uninstrumented time includes process startup, cleanup, and any phase without its own timing marker; it must not be labeled as pure bundling time.

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

## Shared file store

An install or update can place the runtime, Pi package, and dependency files of a release (`node_modules/` and `pi-packages/`, files up to 1 MiB, which is nearly all of them) from a content-addressed store in the user's cache directory instead of writing them again ([architecture](architecture.md#shared-file-store), [security](security.md#shared-file-store)). Whether that is faster depends on what a created file costs. A store writes each object once and places from it, so the first install writes every file twice, and a repeat install replaces a create and a write with a lookup, a read-back and hash of the object (always: a placement trusts bytes it has hashed), and a clone, copy, or link. It can win only where creating a file is expensive, and on Windows with Defender it does (measured below).

**The default depends on the platform** (`defaultStoreMode` in `packages/core/src/store/policy.ts`): `hardlink` with `content` verification on Windows, `off` on macOS and Linux. `PISHIP_STORE=off|copy|clone|hardlink` always wins over the default (`PISHIP_STORE=off` turns the store off on Windows), and `PISHIP_STORE_HOME` moves the store. The choice of a primitive is made by measurement, not by design preference: `clone` is not used at all where the volume has no copy-on-write clones (copying through the store only adds writes, and NTFS has none), and `copy` is never a candidate, since it only adds writes. A Windows install whose store cannot be linked from (the store and the install home are on different volumes, or the file system refuses links) writes each file through a store copy until the install ends, which costs about 1.05x a direct install, or writes the files itself when the store cannot be opened; the install succeeds either way.

### What `scripts/benchmark-store.mjs` measures

The real `ContentStore` code, driven the way extraction drives it (eight writers, each file held in memory, its digest taken from the bytes), on a deterministic tree shaped like `node_modules` (a few thousand files, mostly under 20 KB, a few hundred KB, 8% identical files, 1% executable). Per primitive (`copy`, `clone`, `hardlink`), with the object check the product does (`content`) and optionally without it (`size`, measurement only):

| Scenario | What it is |
| --- | --- |
| `direct` | Extraction without a store: create and write each file. The baseline for every ratio. |
| `<p>.fresh` | A first install: an empty store is filled and the files are placed from it. |
| `<p>.warm` | A second install of the same release from a full store. |
| `<p>.update` | An update that changes a tenth of the files, from the store of the release it replaces. |
| `<p>.remove` | Deleting the installed tree (links, read-only files), against `direct.remove`, which deletes a tree extraction wrote. |

Repetitions alternate the order of the primitives; the report has medians, P95, minimum, maximum, and every sample, the primitive the volume actually gave (a refused `clone` is reported as the `copy` it became), the counts of objects created, reused, and repaired, and the host. A tree is sampled and hashed after each run, so a broken placement cannot look fast. `--store-dir` puts the store on another volume, which makes `clone` and `hardlink` fall back.

**The rule the script applies and the checked-in budgets** (`scripts/store-budgets.json`, applied by `scripts/store-budgets.mjs` and `--check`): a primitive is worth shipping only when `warm` is at most 0.70 of `direct`, `update` at most 0.85 of `direct`, and `fresh` at most 1.15 of `direct`, with the file system giving the primitive asked for. Once a mode is in force the budgets are hard: `fresh` at most 1.10x `direct`, `warm` and `update` no slower than `direct`, `remove` at most 1.10x `direct.remove`. A pull request that changes the store, the extraction, or the placement reruns the benchmark and compares it with the earlier report (`--baseline`): a median that is more than 5% worse needs an explanation, one that is stably more than 10% worse blocks the change unless the pull request justifies it.

### Results: macOS, which keeps the default off

Apple M4 Max, macOS 27, Node 24.21.0, APFS, no Defender, 3,000 files (51.9 MiB), 7 repetitions, 8 writers, medians in milliseconds, ratio to `direct` in parentheses (`--verify-modes content,size`; run on this branch while other processes were using the machine, so single figures can move by tens of percent; an earlier 5-repetition run gave the same ordering):

| Scenario | direct | copy | clone (used: copy) | hardlink | hardlink, size check only |
| --- | ---: | ---: | ---: | ---: | ---: |
| fresh | 71 | 297 (4.2x) | 299 (4.2x) | 423 (5.9x) | 416 (5.8x) |
| warm | 71 | 164 (2.3x) | 164 (2.3x) | 329 (4.6x) | 293 (4.1x) |
| update | 71 | 179 (2.5x) | 179 (2.5x) | 329 (4.6x) | 312 (4.4x) |
| remove | 153 (`direct.remove`) | 151 (1.0x) | 155 (1.0x) | 144 (0.9x) | 152 (1.0x) |

On macOS every primitive costs more than writing the files, because creating a file there is cheap: a link on APFS costs more than a create, and the read-back that makes a placement trustworthy is part of the warm cost (the size-only column shows how much, and it is not a product option). No primitive meets the rule, so macOS keeps the default off. `clone` is reported as `copy`: Node 24.21 on this macOS returns `ENOSYS` for a forced clone (`COPYFILE_FICLONE_FORCE`), so the store, which never accepts a clone it cannot confirm, does not count one. Linux has no measurement and keeps the default off.

### Results: Windows with Defender, which makes `hardlink` the default

GitHub-hosted `windows-latest` (Windows 10.0.26100, x64, 4 CPUs), Node 24.21.0, NTFS, Defender real-time protection on with the path, process, and extension exclusions removed, 3,000 files (51.9 MiB), 7 repetitions, 8 writers, `--verify-modes content,size`, medians in milliseconds, ratio to `direct` in parentheses (`direct.remove` is 386):

| Scenario | direct | copy | clone (used: copy) | hardlink | hardlink, size check only |
| --- | ---: | ---: | ---: | ---: | ---: |
| fresh | 6,841 | 7,201 (1.05x) | 7,496 (1.10x) | 6,657 (0.97x) | 6,538 (0.96x) |
| warm | 6,841 | 1,921 (0.28x) | 1,900 (0.28x) | 675 (0.10x) | 441 (0.06x) |
| update | 6,841 | 2,411 (0.35x) | 2,388 (0.35x) | 1,197 (0.17x) | 886 (0.13x) |
| remove | 386 | 324 (0.84x) | 330 (0.85x) | 270 (0.70x) | 269 (0.70x) |

Creating a file under Defender costs about 2.3 ms here (the direct extraction's median over its 3,000 files, 8 writers); a link, which creates no new content to scan, costs a fraction of it, and that is the whole gain. `hardlink` with the object check on (`content`, the only mode the product runs) is inside every budget below: a first install that fills the store costs no more than a direct one (0.97x), a repeat install 0.10x, an update 0.17x, and removing the installed tree 0.70x. `clone` falls back to `copy` on NTFS, and `copy` pays for itself only on repeat installs (0.24x to 0.28x) while a first install is 1.05x to 1.10x, so neither is a candidate; `hardlink` is the only primitive that makes a first install no slower. A second run with the store directory given separately (3 repetitions) gave the same ordering (hardlink fresh 6,821 against direct 6,968, warm 675, update 1,193, remove 302), and `scripts/store-budgets.mjs --mode hardlink` reported all three modes within budget. The `remove` row is `rmSync(tree, { recursive: true })` over a tree of read-only files that share inodes with the store, on Windows: it succeeded in every repetition, which is the removal path of `uninstall`, update, and rollback.

What these numbers do not cover. They are one runner type on one day with synthetic payload files, not the real payloads. A store on another volume than the install home cannot link and falls back to copies (about 1.05x on a first install). The Windows CI jobs of this repository now run every install, update, rollback, and uninstall test with the store on its default, which is the evidence for the paths the benchmark does not drive (the reclaim of old versions and the temporary-directory sweeps remove files with `unlinkSync`, which on Windows also removes read-only files).

### Reproduce on Windows

The manual `Windows benchmark` workflow (`.github/workflows/authoring-benchmark.yml`) runs `scripts/benchmark-store.mjs` after the install and `.cmd` measurements, on the same Defender-on runner, writes `store-report.json`, `store-summary.md`, a second report with the store on `D:` where one exists, and `store-budgets.log` (a result, not a gate), and uploads them with the rest of the evidence. By hand, in PowerShell with Defender on and a built checkout:

```powershell
$measurementPath = Join-Path $env:LOCALAPPDATA ('PiShipStore-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
node scripts/benchmark-store.mjs --out $measurementPath --files 3000 --reps 7 --verify-modes content,size
node scripts/store-budgets.mjs --store-report (Join-Path $measurementPath 'report.json') --mode hardlink
```

What to read in a Windows result before changing the default again: whether `hardlink.warm` and `.update` clear the rule with the object check on; whether `hardlink.remove` succeeds and stays within its budget (read-only linked files and a link limit of 1,023 per file on NTFS, which the placement answers by copying that file); the result with the store on another volume (everything falls back to copies); and `copy` against `clone` on a Dev Drive (ReFS), where a clone is available if Node reports it. Record the result, the host, and the revision in this section and in the changelog when the default changes. The budgets apply to the default of the platform that ran the report (`defaultMode` in the report), or to the mode named with `--mode`; a Windows run that exceeds them is the evidence to turn the default off.

## Windows launcher decision

The Windows command is `<command>.cmd`, which starts `cmd.exe`, which starts `node.exe` on the installed `launch.mjs`. A native launcher (resolve Node, `CreateProcessW`, pass the exact arguments and environment, return the exit code, and nothing else: no runtime, policy, authentication, or store logic) is worth building only if `cmd.exe` adds a measurable, stable cost. `scripts/benchmark-cmd-launch.mjs` measures it: the same installation started as `node launch.mjs --smoke` and as `<command>.cmd --smoke`, cold first starts and warm starts, repeated in alternating order, with the bare `node` and `cmd.exe` start times as reference. The manual Windows benchmark workflow runs it.

**Threshold.** Implement a native launcher only if, on a Windows machine with Defender on and at least 15 repetitions, the script's verdict says the overhead is stable (the minimums differ by at least 50 ms) and its median is at least 100 ms or 1.25x of the direct start, and a second run reproduces it. Anything smaller, a noisy difference, or a result that does not repeat is rejected, and the `.cmd` shim stays. Either outcome is recorded here; neither opens a separate pull request.

**Verdict.** Pending: no Windows measurement of the `.cmd` shim exists yet (the macOS run measures the POSIX shim and says so). When the manual workflow has produced one, write here its host, revision, repetitions, the median, P95, and minimum of both starts, the overhead, and the decision (implement, or reject because it stayed under the threshold), with the report's file name. The macOS run of the script is not evidence for a Windows decision.

## Regression budgets

`scripts/store-budgets.json` holds the rules and `scripts/store-budgets.mjs` applies them, to the reports the benchmarks already write; it is separate from any other budget file so that concerns do not collide.

- **Rule.** A median regression above 5% needs an explanation in the pull request; a stable regression above 10% blocks the change unless the pull request justifies it explicitly. The comparison is always between a candidate and a baseline of the same distribution, workload, machine, and run order.
- **Install and startup metrics** for each of the personal, managed, and developer distributions, taken from two reports of `scripts/benchmark-install.mjs` (`node scripts/store-budgets.mjs --install-report candidate/report.json --install-baseline baseline/report.json --distribution personal`): payload files, installed files, archive bytes, install, update, first startup, warm startup, startup after update, and, when the report has them, cold and warm build. Run each distribution: an optimization for the developer distribution may not regress the personal one, and the check is per distribution.
- **Store metrics** from a report of `scripts/benchmark-store.mjs`, as above.
- **Launch.** A launch performs no authoring, no deep verification, no store access, and no collection. This is structural and tested (`packages/core/src/store-boundary.test.ts`), not a time budget.

`scripts/store-budgets.mjs` reads the existing report of `scripts/benchmark-install.mjs`, which records one run per metric; a multi-run report with arrays of samples is compared by its median. The cold and warm release metrics wait on a report that carries them.

## Not measured

Windows behavior still needs the affected machine (including the shared file store and the `.cmd` launcher, above): Defender and EDR scanning cost, C: write and rename timing, file locks held by a running executable or native module, simultaneous session and update registration, process-cold versus reboot-cold boot, and network transfer latency. The code retains version directories used by runtime leases and never overwrites a receipt-retained version with different archive bytes.
