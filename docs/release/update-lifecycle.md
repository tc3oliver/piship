# Update lifecycle

How an installed distribution trusts channels, updates, rolls back, checks local data, and activates a release atomically. This page is part of the [release guide](../release.md); building and signing are in the [owner workflow](owner-workflow.md), and the archive format in the [artifact contract](artifact-contract.md).

## Channels and signed metadata

A distribution declares its channels in `updates` ([manifest](../manifest.md#lifecycle-fields-v1alpha4)). The names are `stable`, `candidate`, and `dev`; `updates.channel` (default `stable`) is where users start, and `updates.channels` lists the channels users may pick. What each channel carries is the owner's decision. `piship release --channel` records the channel a build is meant for; `sign-channel` may add the same archive to another channel, so a candidate can be promoted without a rebuild, while its `release.json` keeps the original channel.

An update source is a directory, served as static files over HTTPS or read locally, containing:

```text
stable.json        piship-channel/v1 metadata
stable.json.sig    piship-signature/v1 Ed25519 envelope over the exact bytes of stable.json
acmecode-1.1.0-linux-x64.tar.gz
acmecode-1.1.0-darwin-arm64.tar.gz
...
```

The channel metadata names the distribution and channel, a monotonic `sequence`, an `expires` time, and for each release its version, target, archive name, archive SHA-256 and size, Pi and PiShip versions, and lock SHA-256. The owner creates and signs this metadata with `piship sign-channel` ([owner workflow](owner-workflow.md#signing-a-channel)).

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
2. Resolves `updates.source` from the environment, or uses `--from`. The resolved value and `--from` are checked like the manifest: `https`, or `http` on `127.0.0.1`, `localhost`, or `[::1]`, with no credentials, query string, or fragment; any other scheme is refused with `NETWORK_DENIED`. A local directory from `updates.source` must be absolute; `--from` also accepts a relative one. Requests use the managed fetch with the distribution's proxy and CA settings, and never follow redirects. Only the host of the declared `updates.source` is added to a `privateOnly` allow list; a `--from` URL gets no such exception.
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
| Identity session | `identity/session.json` | Credential class: kept when the target reads its schema and uses the same secret store, otherwise cleared with its secret-store entry and reacquired by `login` |
| Runtime credential metadata | `credentials-metadata/inference.json` | Credential class: kept when readable and the secret store stays the same, otherwise cleared with its secret-store entry and reacquired |
| State marker | `state.json` (`piship-state/v1`) | Rewritten after each update and rollback activation with the distribution, version, Pi, and PiShip versions. One that cannot be written then keeps its previous content, is reported as a notice, and is repaired by the next update or rollback |
| Identity session | `identity/session.json` | Credential class: kept when the target reads its schema, otherwise cleared with its secret-store entry and reacquired by `login` |
| Runtime credential metadata | `credentials-metadata/inference.json` | Credential class: kept when readable, otherwise cleared with its secret-store entry and reacquired |
| File secret fallback | `secrets/` | Never copied, snapshotted, or restored; removed when any credential class is cleared |
| Preferences | `config/preferences.json` | Kept in place; `unsupported` when the target cannot read its schema; included in the snapshot |
| User policy rules | `config/policy.json` | Kept in place; included in the snapshot |
| Pi agent configuration | `agent/` | Owned by Pi and kept in place; Pi-native `auth.json` is a credential and never snapshotted |
| Sessions | `sessions/` | Kept in place; Pi migrates its session files forward. A target with an older Pi than the one that wrote existing sessions `requires-review` |
| Audit and metrics logs | `logs/` | Kept in place; `audit.jsonl` is rotated by size ([state table](../architecture.md)); `unsupported` when the target cannot read the newest audit event schema, read from the newest non-empty audit file |
| Cache | `cache/` | Not migrated; safe to delete |
| Runtime data | `data/` | Kept in place |
| Migration snapshots | `migration/snapshots/` | The last three completed pre-update snapshots |

Verdicts are `safe`, `requires-review`, or `unsupported`; the report shows each class with its action (`keep`, `clear-and-reacquire`, `review`, or `refuse`) and reason. An unreadable file of a schema-versioned non-credential class is `unsupported`: PiShip never reinterprets data under another schema.

Before activating an update, PiShip copies `config/preferences.json` and `config/policy.json` into `<state>/migration/snapshots/<sequence>-<from>-to-<to>/` with a `piship-snapshot/v1` record that lists the credential paths it excluded, the snapshot's creation sequence, and the time. The snapshot is built in a `.staging-p<pid>-*` directory beside the others, its record written last and read back, flushed to disk, and published by one rename, so a snapshot directory is always complete; a failure removes the staging directory and stops the update before activation. The last three completed snapshots are kept, by creation sequence rather than by time, so a clock set back or forward does not change which are the newest. Each snapshot also removes what interrupted ones left: staging directories of a process that no longer exists (or older than ten minutes), and snapshot directories without a valid record. No command restores a snapshot; it is a manual recovery copy.

A change of `credential.storage.provider` between the active and the target release (`file` to `system`, or `system` to `file`) is a credential transition: the other store cannot read a reference the old one holds, so a present identity session and runtime credential are `clear-and-reacquire` with the reason `The secret store changes from <old> to <new>; …`, and the switch prints `<class> was cleared because the secret store changes from <old> to <new>: its secrets were deleted from the <old> store; sign in again`. The switching release, which reads the old store, does the clearing, so the target never looks an old reference up in its own store. `update --check` and `piship migrate-check` report it the same way.

Credentials are never snapshotted, copied into a release, or restored. Rollback switches only the immutable payload, so it cannot bring back a credential that was revoked or cleared: after `logout`, a rolled-back release requires `login` again. When a credential class is cleared because the target cannot read it, the switching release first revokes the runtime credential at the broker's revoke endpoint, best effort, when the distribution declares one (a failure is a notice, and local clearing still happens). It then deletes the local secret-store entries each cleared class references and the metadata file. Identity tokens are cleared only locally: the identity provider's revocation endpoint is not called. Run `logout` first when identity tokens must also be revoked remotely.

## Install layout and atomic activation

```text
<install-home>/                           ~/.local/share/piship or PISHIP_INSTALL_HOME
  receipts/<id>.json                      piship-install/v1 receipt: the only record of the active release
  apps/<id>/launch.mjs                    reads the receipt and starts the active release
  apps/<id>/<version>/                    immutable payloads: the active one and at most one retained
  apps/<id>/.staging-*                    in-progress downloads; marked with their owner, removed by the next operation
  apps/<id>/.lifecycle.lock               one update, rollback, or uninstall at a time (piship-lifecycle-lock/v1)
<bin-home>/<command>                      shim that runs launch.mjs; <command>.cmd on Windows
```

The lifecycle lock records its holder's process ID and a random instance ID, and the holder refreshes the lock's modification time every 15 seconds while it runs. The next operation takes the lock over at once when its process no longer exists. When a process with that ID exists, the operation cannot tell the holder from an unrelated process that reused the ID after the holder crashed, and the lock's modification time against the wall clock is all it has: each command is one attempt in a fresh process, so unlike the credential lock ([credentials](../credentials.md)) it has no earlier observation of the lock to compare with. It therefore treats such a lock as abandoned only after 24 hours without a refresh. That is far above the longest step that blocks the refresh (a launch check may run for five minutes) and above the clock corrections and sleeps a running holder sees; only a clock that jumps forward, or a machine that sleeps, for more than a day while the holder cannot refresh displaces it. The cost is that a crashed holder's lock whose ID is in use blocks update, rollback, and uninstall for up to a day; the error names the lock file, which can be removed by hand when no operation is running. A holder that lost its lock anyway does not commit: update and rollback check that the lock still names them right before they write the receipt, and when it does not they fail with a retryable error, write nothing, and leave the release directories to the operation that holds the lock now. The check and the write are two steps, so a takeover between them is not caught. A lock whose content cannot be read is judged by its modification time alone (24 hours), and a directory or symlink at its path is never removed. A lock written by an earlier PiShip holds only a process ID and is handled the same way. A holder removes only its own lock.

`piship install <payload|release-dir|archive>` accepts a payload directory as before, or a release, which it verifies for this target first. `install.sh` and `install.ps1` inside an extracted release run `verify-release` and then `install` on it. The receipt records each retained release (version, payload path, install time, and for releases the target, channel, Pi and PiShip versions, lock digest, and archive digest), the active and retained versions, the selected channel (an install starts on `updates.channel`, whatever channel the archive was built for), the highest accepted channel sequences, and the last check. Receipt paths must be the owned ones or the receipt is rejected.

Before activation, every file and directory of the new payload is flushed to disk, so a power loss after the switch cannot leave the receipt naming a missing or truncated release. Windows cannot flush directories and needs write access to flush a file, so there this step is best effort. On macOS Node's file flush (libuv 1.51 in Node 22.19) issues `F_FULLFSYNC`, falling back to `F_BARRIERFSYNC` and then `fsync` where a filesystem does not support it, so data reaches stable storage past the drive's write cache. Activation is then one receipt write: a temporary file is written completely (a write that takes only part of the bytes is continued, and one that makes no progress fails), flushed to disk, and renamed over the receipt, and the directory is flushed where the filesystem allows it. A failure before the rename keeps the previous receipt byte for byte and removes the temporary; one a killed process left is never read and is removed by the next update or rollback. The state marker is written the same way. The launcher reads the receipt on every start. An interruption before the rename leaves the old release active; after it, the new one. Staging directories and payloads the receipt does not name are removed by the next update or rollback, and `doctor` reports them in the meantime. A staging directory (`.staging-*` under the install home for an install, under `apps/<id>` for an update) carries an owner marker, so an install or update killed in the middle (SIGKILL, a machine reset) does not wait for the next update: the next launch of an installed distribution, install, or update removes it once its process no longer exists, and never one a running install or update holds. The throwaway state of a launch check (`piship-launch-check-*` under the OS temp directory) and the extraction of an archive being verified (`piship-verify-*`) are reclaimed the same way ([temporary directories](../architecture.md#temporary-directories)); a directory that cannot be removed is counted in `doctor`'s Update group. Credential data the target cannot read is cleared just before the switch, so an interruption between those two steps leaves the old release active with the user signed out.

A receipt written by an earlier PiShip (without `schema`) is still read, launched, and uninstalled, but `update` and `rollback` need a reinstall: `uninstall`, then `install --use-existing-state`. `uninstall` removes the shim, launcher, every retained release, leftovers, and the receipt, and keeps state.

## Failure policy

Every failure happens before activation and leaves the active release and state unchanged, apart from the highest accepted channel sequence and the last check result, and, where noted, cleared credentials. Once the receipt has switched, the update or rollback reports success, is audited as allowed, and is counted as `ok`, whatever happens next: a state marker that cannot be written then is a notice, and the next update or rollback repairs it.

| Condition | Result |
| --- | --- |
| A release gate or required test fails, or the scan cannot run | `piship release` fails and removes its partial output |
| Archive, checksums, payload, SBOM, notices, or metadata do not verify | `INTEGRITY_FAILED` |
| No pinned keys, or no update source and no `--from` | `UPDATE_FAILED` |
| Signature by an unpinned key, altered metadata, wrong distribution or channel, expired metadata, or a replayed lower sequence | `INTEGRITY_FAILED` |
| Channel not in `updates.channels` | `POLICY_DENIED` |
| `updates.source` variable unset | `CONFIG_UNAVAILABLE` |
| Plain `http` to a non-loopback source, or another scheme | `NETWORK_DENIED` |
| Update source URL with credentials, query, or fragment, or `updates.source` resolving to a relative directory | `CONFIG_INVALID` |
| Downloaded archive differs from its signed entry | `INTEGRITY_FAILED` |
| Older release offered, target Pi recorded unsupported, launch check fails, migration `unsupported`, or `requires-review` without `--accept-review` | `UPDATE_FAILED` |
| Another update, rollback, or uninstall is running, or its lock was taken over before the receipt was written (nothing is committed) | `UPDATE_FAILED` or `ROLLBACK_FAILED` (retryable) |
| No retained release, retained release damaged or newer, different command, launch check fails, or migration `unsupported` | `ROLLBACK_FAILED` |

## Known limitations

- Clearing an unreadable credential during update or rollback revokes the runtime credential only where the distribution declares a broker revoke endpoint, and only best effort; identity tokens are cleared locally without remote revocation.
- `update --check` downloads and verifies the full archive and runs its launch check, so it costs as much network and time as an update.
- A migration snapshot has no restore command.
- The channel host is trusted for availability: it can withhold updates until the metadata expires, but it cannot forge, alter, or roll back signed metadata that a client has already seen.
- Verification detects tampering while the verifying PiShip and the pinned keys are trusted; it is not a boundary against a local administrator.
