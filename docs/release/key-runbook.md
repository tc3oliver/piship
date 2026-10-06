# Release key and rollback runbook

What a distribution owner does, step by step, to set up update keys, rotate them, respond to a compromised or lost key, recover clients that can no longer update, and take a bad release back from the whole company. The design behind it is in [release trust root](trust-root.md); this page does not repeat it. Commands are in the [owner workflow](owner-workflow.md#signing-a-channel), and what an installed client does with a channel in the [update lifecycle](update-lifecycle.md).

`<command>` is the distribution's branded command, `<id>` its `app.id`, `<source>` the update source directory you publish, and `piship` stands for `node <PiShip clone>/packages/cli/dist/bin.js`.

## What a client trusts, in one line

An installed client trusts the **update root it holds in its installation trust state**, advanced only by root versions signed by both its current and the new root role, and verifies channels with that root's channel role ([model](trust-root.md#model-in-one-paragraph)). A release lock never changes it after the first install; rollback never changes it.

## Before you need it

Do these once, before the first release that employees install.

1. **Separate root and channel keys, encrypted.** Generate two root keys (held offline by two different people) and one channel key (the routine signer):

   ```bash
   piship keygen /media/offline-a/acmecode-root-2026a.pem --id acmecode-root-2026a --encrypt
   piship keygen /media/offline-b/acmecode-root-2026b.pem --id acmecode-root-2026b --encrypt
   piship keygen ~/keys/acmecode-channel-2026.pem --id acmecode-channel-2026 --encrypt
   ```

   Each holder keeps the PEM on encrypted storage and the passphrase in a password manager, never together. Root keys come online only for a root change.
2. **Pin the bootstrap.** Print the manifest block from the public keys and paste it under `updates:` in `piship.yaml` (schema `piship/v1alpha5` or later; `piship init` writes `piship/v1alpha6`):

   ```bash
   piship trust-root init \
     --key acmecode-root-2026a=<public key> --key acmecode-root-2026b=<public key> \
     --key acmecode-channel-2026=<public key> \
     --root-keys acmecode-root-2026a,acmecode-root-2026b --root-threshold 1 \
     --channel-keys acmecode-channel-2026 --channel-threshold 1 \
     --expires-days 365
   ```

   With two root keys at threshold 1, either holder can revoke a channel key alone; at threshold 2, both must agree. Choose before the first release; changing it later is itself a root change.
3. **A key record.** For each key: ID, role, `sha256:` fingerprint, holder, storage, and the root versions it appears in. Publish the fingerprints where operators can compare them.
4. **A release record.** For every release you sign: version, target, archive SHA-256, commit, the channel and sequence, and the approver.
5. **Expiry calendar.** Note the current root's `expires`; publish the next root (even one that changes nothing but the expiry) well before it. An expired newest root stops every client's updates.
6. **Rollback enabled** (`updates.rollback: true`) and **a way to reach employees outside the update channel** (device management, an internal catalog, or an announcement channel).

## Planned channel-key rotation

1. Generate and record the new channel key.
2. Publish the next root with both channel keys (an overlap), signed by the root role:

   ```bash
   piship trust-root next <source> --manifest piship.yaml \
     --add-key acmecode-channel-2027=<public key> \
     --channel-keys acmecode-channel-2026,acmecode-channel-2027 \
     --expires-days 365 \
     --sign acmecode-root-2026a=/media/offline-a/acmecode-root-2026a.pem
   ```

   Upload `root/<N+1>.json.sig`, then `root/<N+1>.json`.
3. Sign channels with the new key. While some clients may not have fetched the new root yet, sign with both: `sign-channel ... --key <old.pem> --key-id <old> --key <new.pem> --key-id <new>`. Every client fetches roots before it reads the channel, so in practice a client that can reach the source already has the new root.
4. Publish the next root without the old key: `trust-root next <source> --manifest piship.yaml --remove-key acmecode-channel-2026 --expires-days 365 --sign ...`. Clients refuse it from then on, even after a rollback.
5. Destroy the old key when no channel you publish uses it, and note the date.

## Root-key rotation

A new root must be signed by the **current** root role's threshold and the **new** root role's threshold. Bring the old and new root keys to one signing session:

```bash
piship trust-root next <source> --manifest piship.yaml \
  --add-key acmecode-root-2027a=<public key> --remove-key acmecode-root-2026a \
  --root-keys acmecode-root-2026b,acmecode-root-2027a \
  --expires-days 365 \
  --sign acmecode-root-2026a=/media/offline-a/acmecode-root-2026a.pem \
  --sign acmecode-root-2027a=/media/offline-a/acmecode-root-2027a.pem
```

`trust-root next` verifies the whole chain from the manifest bootstrap through the published roots, refuses a transition that misses either threshold, and writes nothing on any failure (a wrong passphrase, a failing signer, an unmet threshold). With several encrypted keys, it prompts once per key, or takes one passphrase for all from `--passphrase-env <NAME>`.

## Compromised channel key

1. **Contain.** Stop signing with the key. Secure the update source host and its DNS. Check the published channel files against your release record. Tell employees not to run `update --from` with any source they were sent.
2. **Publish the emergency root** without the compromised key and with a replacement, signed by the root role:

   ```bash
   piship trust-root next <source> --manifest piship.yaml \
     --remove-key acmecode-channel-2026 --add-key acmecode-channel-2026b=<public key> \
     --channel-keys acmecode-channel-2026b --expires-days 180 \
     --sign acmecode-root-2026a=/media/offline-a/acmecode-root-2026a.pem
   ```

3. **Re-sign every channel** with the replacement key at a sequence above every sequence ever published, including any the attacker may have published (`sign-channel ... --sequence <far above>`).
4. **Upload** the root pair, then the channels. A client that fetches the root refuses the compromised key before it reads the channel, so nothing it signed is downloaded or activated. `rollback` does not restore the key.
5. **Find what was signed.** Compare every archive the key may have signed with your release record; reinstall machines that activated one you did not build ([stranded clients](#stranded-clients)). The emergency root cannot fix those machines: a channel signature also authorizes code, and an activated malicious release ships the CLI that manages the installation, which can rewrite its trust state. Root rotation recovers only installations that have not yet activated a release signed with the compromised key; the others need the out-of-band reinstall.
6. **Know the limit.** This works for a client that obtains the new root. An attacker who controls what a client receives from the update source can withhold the root (answer 404) and keep serving channels signed with the compromised key; that client stays exposed until it reaches the authentic source, or until its current root or the attacker's channel metadata expires and it fails closed ([security boundary](trust-root.md#security-boundary)). Short root and channel expiries bound that window. Where you can reach machines out of band, tell users to update from the authentic source now.

## Compromised legacy key

An installation whose trust originated from v1alpha4 legacy keys (`doctor` shows origin `legacy`) holds those keys in both the root and the channel role at threshold 1, and keeps that authority until it accepts a root whose root role no longer lists them. A compromised legacy key therefore also has root authority over it: the attacker can publish roots that installation accepts, so root rotation cannot recover it. The recovery is a reinstall from an archive verified out of band ([stranded clients](#stranded-clients)). Do not wait for this: move legacy installations to a split root and channel bootstrap promptly ([v0.7 to v0.8 bridge](trust-root.md#v07-to-v08-bridge)).

## Compromised root keys

- **Below the root threshold** (for example one of two keys at threshold 2, or one of two at threshold 1 with the other safe): publish the next root with the remaining root key or keys, removing the compromised key and adding a replacement. At threshold 1 act at once: the attacker can also publish roots, and clients take whichever valid N+1 they see first.
- **At or above the threshold**: the attacker can publish roots that clients accept. Nothing signed remotely can be told apart from the attacker's. Generate a new root, pin it as the bootstrap of a new release, and re-bootstrap every installation from that release verified out of band ([stranded clients](#stranded-clients)). Announce it out of band.

## Lost key

- **A channel key, or a root key below the threshold:** publish the next root without it, signed by the remaining root keys, as above.
- **Root keys down to below the threshold:** no client can accept a new root again. The current root keeps working until it expires; before then, re-bootstrap every installation with a new root ([stranded clients](#stranded-clients)).

## Stranded clients

A client is stranded when it cannot verify the current channel: its root's channel role has no key that signs the channel, its newest root expired, or its trust state is damaged. It keeps working on the release it has; only updates fail.

**Symptoms.** `<command> update` fails with `INTEGRITY_FAILED`: `Signature key <id> is not trusted; trusted keys: <ids>`, `Update root version <n> expired`, or `Update trust state ... refusing to update`. `<command> doctor` shows the update root version, origin, expiry, channel keys, and any trust-state problem.

**Recovery, in order of preference:**

1. **Publish what it is missing.** A newer root before the expiry, or a channel also signed with a key its root still trusts.
2. **Re-bootstrap** from an archive delivered outside the update channel (device management, an internal catalog, an internal HTTPS host). State, preferences, and sessions are kept:

   ```bash
   sha256sum <id>-<version>-<target>.tar.gz           # compare with the published value
   tar -xzf <id>-<version>-<target>.tar.gz             # creates <id>-<version>-<target>/
   node <id>-<version>-<target>/payload/piship.mjs uninstall <id>
   <id>-<version>-<target>/install.sh --use-existing-state
   ```

   On Windows, run `install.ps1 --use-existing-state` instead of `install.sh`, or use `piship install <archive> --sha256 <digest> --use-existing-state`. Compare the bootstrap key fingerprints (`piship inspect <release-dir>/payload`) with the published ones first. `uninstall` keeps state and removes the trust state; never add `--purge` here. Never edit or delete the trust state file by hand to get past an error.

## Company-wide rollback

A released version is bad and should leave every machine. Clients refuse downgrades, so "rollback" is one of three actions, often together:

1. **Stop it spreading.** Re-sign the channel with a fixed version, or take `<channel>.json` and `<channel>.json.sig` off the host: clients then fail `update` with `UPDATE_FAILED` and stay on what they have.
2. **Local rollback, on each machine.** `<command> rollback` switches back to the retained release when `updates.rollback` is true in both releases. It loads the retained release's target and metadata, runs the migration check, and keeps sessions, preferences, and user policy. It does not change the update trust state, so a key a newer root removed stays refused.
3. **Fix forward, for everyone.** Release the last good source again with a **higher version**, review `piship diff`, and sign it into every channel that carries the bad one, with a higher sequence.

## Checklist after any key event

- The key record shows every key's role and state (active, retired, compromised, destroyed) and the root versions it appears in.
- `<source>/root/` holds every published version in order; the newest one expires well in the future.
- Every channel employees use is signed by the current channel role, at a sequence above every one ever published, and expires more than a week from now.
- `<command> doctor` on a test machine shows the expected update root version and channel keys.
- Employees know which versions to distrust and how to reinstall if they are stranded.
