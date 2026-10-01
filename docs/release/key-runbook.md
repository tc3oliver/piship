# Release key and rollback runbook

What a distribution owner does, step by step, to rotate a release key, respond to a compromised or lost key, recover clients that can no longer update, and take a bad release back from the whole company. The design behind it, what a client trusts and why, is in [release trust root](trust-root.md); this page does not repeat it. Commands are in the [owner workflow](owner-workflow.md#signing-a-channel), and what an installed client does with a channel in the [update lifecycle](update-lifecycle.md).

`<command>` is the distribution's branded command, `<id>` its `app.id`, and `piship` stands for `node <PiShip clone>/packages/cli/dist/bin.js`.

## What a client trusts, in one line

An installed client trusts exactly the keys pinned in the lock of its **active** release, and nothing else: no revocation list, no key from the channel, no clock-based expiry. Every procedure below follows from that ([model](trust-root.md#model-in-one-paragraph)).

## Before you need it

Do these once, before the first release that employees install. Each later procedure is shorter, or only possible, because of them.

1. **Two keys from the first release.** Generate a primary and a backup key, on the machine that signs, outside every repository, and pin both:

   ```bash
   piship keygen ~/keys/acmecode-release-2026.pem --id acmecode-release-2026
   piship keygen /media/offline/acmecode-backup-2026.pem --id acmecode-backup-2026
   ```

   Sign routinely with the primary only. Keep the backup offline, held by a different person than the primary, and never use it except in [a compromise](#compromised-key) or [a loss](#lost-key).
2. **A key record.** For each key: its ID, its `sha256:` fingerprint (printed by `keygen`), who holds it, where it is stored, and the release that first pinned it. Publish the fingerprints where employees and operators can compare them (an internal page), and keep the record with the release records below.
3. **A release record.** For every release you sign: version, target, archive SHA-256, the commit, the keys its lock pins, the channel and sequence it was signed into, and the approver. Recovery from a compromise depends on knowing which archives you signed.
4. **The channel sequence.** Note the highest sequence you have published on each channel. A recovery signs above every sequence ever published.
5. **Rollback enabled.** Keep `updates.rollback: true`, so every client keeps one known-good release to go back to ([company-wide rollback](#company-wide-rollback)).
6. **A way to reach employees outside the update channel**: device management, an internal software catalog, or at least an announcement channel. Two procedures below need it.

## Planned rotation

Rotation is release-bound: the trusted set changes only when a client activates a release that pins a different set ([rotation](trust-root.md#rotation)). Plan it over three releases, N, N+1, and N+2, where N pins only `old`.

1. **Generate and record `new`** (as above). Do not sign anything with it yet.
2. **Release N+1 pins both.** Add `new` to `updates.trust.keys` beside `old`, lock, and review `piship diff`: the added key is reported as a `high` risk change ("Changes who can publish updates"), which is expected; make sure it is the only key change. Build, approve, and sign the channel **with `old`**. Clients on N accept it, because they trust `old`, and trust both keys once they activate it.
3. **Wait for the overlap.** Leave the channel signed with `old` until the clients you intend to keep serving have activated N+1 or later. PiShip cannot tell you who has: use your own inventory (device management, the version employees report from `<command> version`, or the release your gateway or broker sees in requests). There is no deadline on the client side; a client on N+1 keeps trusting both keys until it updates again.
4. **Switch signing to `new`.** From now on, sign every channel with `new`. A client still on N cannot verify it ([stranded clients](#stranded-clients)).
5. **Release N+2 drops `old`.** Remove `old` from `updates.trust.keys`, lock, review the diff (one removed key), and sign with `new`. A client that activates N+2 refuses metadata signed with `old`, even with a higher sequence.
6. **Retire `old`.** Keep the retired key, offline, until no client you serve can still be on a release that pins only `old`, then destroy it and note the date in the key record.

Rotate the backup key the same way, in the same or a later N+1 and N+2.

## Compromised key

A compromised key can sign a channel that every client trusting it accepts, including a release that pins the attacker's keys, as long as the attacker can also serve the client's `updates.source` (or the user runs `update --from` with the attacker's source) ([compromised-key recovery](trust-root.md#compromised-key-recovery)). Act at once:

1. **Contain.** Stop signing with the key. Secure the channel host and the DNS of the `updates.source` host. Check the published channel files against your release record: a metadata file, sequence, or archive you did not sign means the key was used. Tell employees not to run `update --from` with any source they were sent.
2. **Decide which key signs the recovery.**
   - **The backup is pinned and safe:** use it. Continue with step 3.
   - **The compromised key was the only pinned key:** nothing you sign can be told apart from what the attacker signs. Go to [stranded clients](#stranded-clients), case "no trusted key you can use", for every installation, and announce the compromise out of band.
3. **Ship a release that drops the compromised key.** Pin the backup and a newly generated key (which becomes the new backup or primary), and nothing else. Review `piship diff`: the removed and added keys, and no other key change. Sign the channel with the backup key, with a sequence above every sequence ever published, including any the attacker may have published:

   ```bash
   piship sign-channel ./channel dist/releases/<id>-<version>-<target>.tar.gz \
     --channel stable --key /media/offline/acmecode-backup-2026.pem \
     --key-id acmecode-backup-2026 --sequence <far above every published sequence>
   ```

   Sign each channel employees use. A client that activates this release refuses everything the compromised key signs from then on.
4. **Tell employees not to roll back** past the recovery release. `rollback` makes the retained release, and its lock, active again; if that release still pins the compromised key, the client trusts it again until it updates ([rollback caveat](trust-root.md#compromised-key-recovery)).
5. **Find what was signed.** Compare every archive the compromised key may have signed with your release record. For any you did not build, tell employees which versions to distrust, and reinstall machines that activated one from a verified archive ([stranded clients](#stranded-clients)).
6. **Record** the incident, the keys retired, and the recovery release in the key record.

## Lost key

- **Another pinned key remains** (the backup): ship a release that drops the lost key and pins a fresh pair, signed with the remaining key, as in [compromised key](#compromised-key) step 3. Clients continue without intervention.
- **No pinned key remains:** no installed client can verify another update. Reinstall every installation ([stranded clients](#stranded-clients), "no trusted key you can use"), with a new channel whose sequence starts above the old one.

## Stranded clients

A client is stranded when its active release pins no key that signs the current channel. It keeps working on the release it has; only updates fail.

**Symptoms.** `<command> update` and `update --check` fail with `INTEGRITY_FAILED` and `Signature key <key ID> is not trusted; trusted keys: <IDs>`. `<command> doctor` shows the failed last check and the number of trusted keys in its Update section. `<command> version` names the release, which your release record maps to the keys it pins.

**Recovery, in order of preference:**

1. **A trusted key you can still use** (the old key after a rotation, while it is not compromised): sign the channel once more with it, offering an overlap release (one that pins both keys) or a later one, with a higher sequence. Stranded clients then update normally; switch signing back to the new key afterwards. Do this for as long as you still serve stragglers.
2. **No trusted key you can use** (it was retired and destroyed, lost, or compromised): reinstall each installation from an archive that pins the current keys, delivered outside the update channel (device management, an internal catalog, an internal HTTPS host). State, preferences, and sessions are kept:

   ```bash
   sha256sum <id>-<version>-<target>.tar.gz           # compare with the published value
   tar -xzf <id>-<version>-<target>.tar.gz             # creates <id>-<version>-<target>/
   node <id>-<version>-<target>/payload/piship.mjs uninstall <id>
   <id>-<version>-<target>/install.sh --use-existing-state
   ```

   On Windows, run `install.ps1 --use-existing-state` instead of `install.sh`. Compare the pinned keys in the extracted release's `payload/piship.lock` (`updates.trust.keys`) with the published fingerprints before installing. `uninstall` keeps state; never add `--purge` here.

A client that skipped releases is not stranded as long as the channel is still signed with a key it trusts: it can move from N straight to N+2, because the key it trusts signs N+2's lock digest ([rotation](trust-root.md#rotation)).

## Company-wide rollback

A released version is bad (a broken launch, a wrong policy, a regression) and should leave every machine. Clients refuse downgrades, and a channel cannot be told to offer an older version, so "rollback" is one of three actions, often together:

1. **Stop it spreading.** Clients pick the release up only on `update`. While you prepare a fix, either re-sign the channel with a fixed version (step 3), or take the channel's metadata (`<channel>.json` and `<channel>.json.sig`) off the host: clients then fail `update` with `UPDATE_FAILED`, which leaves them on what they have. `sign-channel` has no command to remove an entry, so a channel that should no longer offer the version needs a newer one.
2. **Local rollback, on each machine.** `<command> rollback` switches back to the retained release (the one active before the last update), when `updates.rollback` is true in both releases. It verifies the retained release, runs its launch check and the migration check, and keeps sessions, preferences, and user policy; a credential the older release cannot read is cleared, so the user signs in again. Push it through device management, or ask employees to run it. It refuses when there is no retained release, the retained release is newer, or the migration check says `unsupported`; those machines wait for the fix.
3. **Fix forward, for everyone.** Build the last good source again with a **higher version** (for example, revert the change and release 1.4.1 after a bad 1.4.0), review `piship diff` against the bad release, and sign it into every channel that carries the bad one, with a higher sequence. Clients that updated and clients that rolled back both move to it with `update`; it is the only step that reaches every client without per-machine work. Check its trust keys: a fix-forward release that pins different keys is also a [rotation](#planned-rotation).

A machine that rolled back stays on the retained release until the next `update`: tell employees to update once the fixed version is published. If the bad release was signed with a compromised key, follow [compromised key](#compromised-key) instead; a local rollback can make a client trust that key again.

## Checklist after any key event

- The key record shows every key's state (active, backup, retired, compromised, destroyed) and the releases that pin it.
- Every channel employees use is signed with a key the current releases pin, with a sequence above every one ever published, and expires more than a week from now (re-sign before `expires`; 30 days by default).
- Employees know which versions to distrust, whether to avoid `rollback`, and how to reinstall if they are stranded.
- The next release's `piship diff` shows exactly the key changes you intend.
