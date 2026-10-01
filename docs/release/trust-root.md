# Release trust root and signed channels

This page covers the key that signs a distribution's update channel: where it comes from, how clients pin it, how it is rotated, revoked, and recovered, and how a channel is hosted. It is part of the [release guide](../release.md). The signing commands are in the [owner workflow](owner-workflow.md#signing-a-channel), and what a client checks when it reads a channel is in the [update lifecycle](update-lifecycle.md#channels-and-signed-metadata).

Each section separates what PiShip does today from what the distribution owner has to do, and lists the gaps. The gaps are collected under [Gaps and follow-ups](#gaps-and-follow-ups). The [examples decision](#examples) is settled: the project operates no official channel, and key custody belongs to each distribution owner.

## Model in one paragraph

Each distribution has its own trust root. The owner generates Ed25519 release keys and pins their public keys in `updates.trust.keys` of `piship.yaml`. `piship lock` copies them into `piship.lock`, and every release payload carries that lock. An installed client trusts exactly the keys in the lock of its **active** release. It accepts channel metadata only when the metadata verifies with one of those keys. The signed metadata binds the next release's archive digest and lock digest, so the next release's trust keys are authenticated by the keys the client trusts now. The trust root therefore moves forward one verified release at a time. It is never fetched from the channel and never accepted on first use.

## What the code implements today

| Property | Where | Status |
| --- | --- | --- |
| Ed25519 keys; PKCS#8 PEM private key; 44-byte SPKI DER public key, base64 | `packages/core/src/signing.ts` | Implemented |
| `piship keygen` writes the private key with mode 0600 and never overwrites one. It refuses a path inside a git work tree that is not git-ignored, unless `--force-in-worktree` is given | `writePrivateKey`, `privateKeyLocation` | Implemented |
| Key IDs: `[a-z0-9][a-z0-9.-]*`, unique within `updates.trust.keys`; a `sha256:` fingerprint of the public key DER | `checkKeyId`, schema `parseUpdates`, `keyFingerprint` | Implemented |
| Public keys pinned in the manifest and lock (`updates.trust.keys`); no private key or secret-named field accepted in the manifest | `packages/schema/src/lifecycle.ts` | Implemented |
| The client's trusted set is the active release's locked keys | `updateDistribution` (`activeLock(receipt).updates.trust.keys`) | Implemented |
| A key that an activated release stopped pinning stays refused after a rollback to a release that still pins it | receipt `retiredKeys`, `readChannel` `retired` | Implemented (see [Rollback and retired keys](#rollback-and-retired-keys)) |
| No keys pinned: update fails; there is no unsigned or trust-on-first-use mode | `updateDistribution`, `verifySignature` | Implemented |
| A signature envelope (`piship-signature/v1`) covers the exact metadata bytes. It names one key ID, and only a pinned key with that ID can verify it | `verifySignature` | Implemented |
| Channel metadata (`piship-channel/v1`) is bound to its distribution and channel, has an expiry, and carries a monotonic sequence. The client keeps a sequence floor per channel in its install receipt | `readChannel`, receipt `channelSequences` | Implemented |
| Archive size and SHA-256 must match the signed entry before extraction. The release's distribution, command, version, Pi version, and lock digest must match it after extraction | `downloadArchive`, `updateDistribution` | Implemented |
| Downgrades offered by a channel are refused | `updateDistribution` | Implemented |
| `piship diff` reports any added, removed, or replaced trust key as `high` risk ("Changes who can publish updates") | `packages/core/src/diff/areas/updates.ts` | Implemented |
| `piship install --sha256 <hex>` refuses an archive whose SHA-256 differs; `--expect-key sha256:<fingerprint>` (repeatable) refuses a release whose lock does not pin each given key. Either refusal installs nothing. `piship inspect` shows the pinned key IDs and fingerprints | `installDistribution` checks, `inspection` `trust` | Implemented (see [Distribution bootstrap](#distribution-bootstrap)) |
| Rotation with an overlap of releases that pin both keys | Release-bound, no client clock | Implemented (see [Rotation](#rotation)) |
| Rotation with a time-bounded window, or keys with `notBefore`/`notAfter` | | Not implemented |
| A revocation list, or a key a client refuses before it activates a release that drops it | | Not implemented |
| More than one signature on the channel metadata (old and new key at once) | | Not implemented |
| Signing with a key held in a hardware token, KMS, or agent, or with an encrypted PEM | | Not implemented: `sign-channel` reads an unencrypted PEM file |
| A first install that verifies the installed archive against a pinned key | | Not implemented (see [Bootstrap](#distribution-bootstrap)) |
| An official channel or a pinned production key operated by the PiShip project | | None exists. Every example pins `keys: []` |

## Key lifecycle and custody

**Generation.** `piship keygen <file> --id <key-id>` generates the key. Generate it on the machine that will sign, and write it to a path outside every repository. The command prints the `updates.trust.keys` entry and the fingerprint. Publish the fingerprint out of band so that operators and users can compare it later (see [Bootstrap](#distribution-bootstrap)).

**Storage.** The private key never enters the repository, the manifest, the lock, a release archive, CI logs, or CI artifacts:

- Repository: `keygen` refuses a tracked work tree path. The manifest parser rejects secret-named fields, and only the public key is ever pinned.
- Archive: a release is assembled from the manifest, lock, and resources, none of which holds the private key.
- CI: no PiShip workflow signs a channel. `Release qualification` and `Release candidate` build, attest, and verify; they do not sign. The CI and E2E tests generate throwaway keys at run time in temporary directories (`tests/helpers/lifecycle.ts`, `packages/core/src/*.test.ts`), and no test key is committed.
- Owner: keep the key in a file with mode 0600 on encrypted storage, offline when not in use. Sign on a machine the owner controls.

If an owner later signs from CI, keep the key in a protected deployment environment secret that only the signing job reads. Never echo the key or pass it as a command argument: `sign-channel --key` takes a file path, so write the secret to a 0600 file and delete it after the job. Never upload the channel directory's parent as an artifact if the key file sits there. That setup is the owner's decision and is outside PiShip.

**Custody.** Key custody belongs to the distribution owner: one named person or role in the owner's organization holds each key and is the only one allowed to sign. The PiShip project holds no release key for any distribution, and no agent or automation generates or pins a production key.

**Two keys from the start (recommended).** Pin a primary key and a backup key from the first release. Store the backup separately, offline, and never use it for routine signing. Today this is the only way a client can recover from a lost or compromised key without a reinstall (see below). It needs no new code, because `updates.trust.keys` already accepts several keys.

**Key IDs.** An ID is a label, not a fingerprint. Use an ID that names the distribution and generation, such as `acmecode-release-2026` and `acmecode-backup-2026`, and never reuse an ID for a different public key. The schema refuses duplicate IDs within one lock. Reusing an ID across releases for a new key still shows in `piship diff` as a changed key with `high` risk, but it makes logs and audit events, which record only the ID, ambiguous.

## Distribution bootstrap

A client must pin a key before it can accept a signed channel. Its first trust root is the `updates.trust.keys` of the **first release it installs**: `piship install` (or `install.sh` / `install.ps1` from an extracted release) runs `verify-release` and records the release's lock, and from then on that lock is the trust root.

`verify-release` proves that an archive is internally consistent: checksums, payload inventory, lock digest, SBOM, and recorded gates. It does not prove who built the archive. The first install is therefore the bootstrap point, and its authenticity comes from how the archive reached the machine:

- Managed distributions: the organization delivers the first archive through a channel it already trusts, such as device management, an internal software catalog, or an internal HTTPS host. Operators compare the archive SHA-256 with the value the owner publishes, and the pinned key fingerprints with the ones the owner publishes. When the owner builds with PiShip's `Release candidate` workflow, they also verify the GitHub artifact attestation. This is not trust on first use: the key comes inside an archive the operator verified out of band, never from the update channel.
- Personal distributions: the user does the same comparison by hand, or accepts the risk of the place they downloaded from.

TOFU (accept whatever key the first channel read presents) is not a mode PiShip offers, and it must not become the managed default. `readChannel` has no code path that adds a key, and a release with no pinned keys can never update.

`doctor` lists the active release's trusted key IDs and `sha256:` fingerprints, and any pinned key this installation retired, so an operator can compare them with the fingerprints the owner published. `piship inspect` shows the same key IDs and fingerprints for a manifest, a payload directory (in an extracted release, `<release-dir>/payload`), or an installed ID (the `trust` field with `--json`).

`install` takes the published values on the command line, so the comparison is not done by hand:

```sh
piship install acmecode-1.0.0-linux-x64.tar.gz \
  --sha256 <archive-sha256> \
  --expect-key sha256:<release-key-fingerprint> \
  --expect-key sha256:<backup-key-fingerprint>
```

- `--sha256 <hex>` is the archive's SHA-256, 64 hexadecimal characters. It is checked before the archive is extracted. It applies only to an archive: a release or payload directory has no archive digest, and `--sha256` with a directory is refused.
- `--expect-key sha256:<fingerprint>` can be given more than once. Each given fingerprint must be pinned in the release lock's `updates.trust.keys`. The check is "each given key is pinned", not "exactly these keys": the lock may pin further keys, such as a rotation overlap. To see the whole set, compare `inspect` with the published list.
- A mismatch fails before anything is installed or activated: no app directory, receipt, or command shim is written. A digest mismatch is `INTEGRITY_FAILED` from release verification; an unpinned key is `INTEGRITY_FAILED` naming the missing fingerprints; a malformed value or `--sha256` with a directory is `CONFIG_INVALID`.

`install.sh` and `install.ps1` do not take these options; run `piship install` with them, or compare by hand (`sha256sum` and `inspect`) before running the script.

## Rotation

Rotation is **release-bound**. The trusted set changes only when a client activates a release whose lock pins a different set, so the overlap window is the run of releases that pin both keys. It has no wall-clock bound: a client that stays on an overlap release keeps trusting both keys until it updates.

1. Release N pins `[old]`, and the channel is signed with `old`.
2. Release N+1 pins `[old, new]`, and the channel is still signed with `old`. Clients on N accept it because `old` is trusted, and once they activate N+1 they trust both keys.
3. Switch signing to `new` only after clients have moved to N+1 or later. A client still on N refuses metadata signed by `new` (`Signature key <new> is not trusted`). It stays on N, which is safe, and it needs a reinstall or a channel signed with `old` to move on.
4. Release N+2 pins `[new]`, and the channel is signed with `new`. Once a client activates N+2, `old` is retired: metadata signed by `old` is refused even with a higher sequence, and even after a rollback to a release that still pins it.

A channel envelope holds one signature, so during step 3 the owner chooses which clients to serve: sign with `old` to reach stragglers on N, or with `new` once they are gone. A client on N may jump straight to N+2 when the channel is still signed with `old`. That is safe, because `old` signs N+2's lock digest and N+2's keys are authenticated by it.

Covered by `packages/core/src/channel-trust.test.ts` (fast, every target) and by the update test "rotates the release key through an overlap release and then refuses the retired key" in `packages/core/src/lifecycle.test.ts`.

## Compromised-key recovery

There is no revocation list. A client refuses a compromised key only after it activates a release whose lock no longer pins that key. Until then, whoever holds the key and can serve the client's `updates.source` (the owner's host, or a host the user names with `--from`) can sign a channel the client accepts. That includes a malicious release whose lock pins the attacker's keys. Channel signatures do not protect against a holder of the private key. Only HTTPS to the declared source limits who can serve one, and a user who runs `update --from` chooses another source themselves.

Recovery, in order:

1. Stop signing with the compromised key, and secure the channel host and the `updates.source` DNS.
2. If the clients also pin an uncompromised key (the recommended backup), sign the channel with it and offer a fixed release that pins a new key set without the compromised key. Use a sequence above every sequence ever published, including any the attacker may have published, for example by jumping far ahead with `sign-channel --sequence`. Once clients activate that release, metadata signed by the compromised key is refused.
3. If the compromised key was the only pinned key, the owner cannot sign anything an attacker cannot also sign. Announce the compromise out of band and have users reinstall from an archive verified out of band that pins the new keys (`uninstall`, then `install --use-existing-state`).
4. Check the archives the compromised key signed against the owner's records, and tell users which versions to distrust.

A rollback past the revoking release does not re-trust the compromised key (see below).

## Rollback and retired keys

`rollback` switches to the retained release and its lock, and that lock may still pin a key that the newer release dropped. Without more, the client would trust that key again. The install receipt therefore records every key retired by an update on this installation:

- When `update` activates a release, each key the active release pins and the new release does not pin is added to `retiredKeys` in the receipt, with its ID, its `sha256:` public key fingerprint, and the version that retired it.
- `readChannel` refuses metadata signed by a retired key even when the active lock pins it: `Signature key <id> was retired by the <version> release of this installation; a rollback does not restore trust in it` (`INTEGRITY_FAILED`). The other pinned keys are still accepted, so a channel signed with the key that replaced it still updates the rolled-back client.
- Retirement matches the public key, not the ID. A new key pinned under a retired ID is trusted. A release that pins a retired public key again lifts its retirement when it is activated, because the owner chose to trust it again in a release signed by a key the client trusts.
- `rollback` itself retires nothing, and the per-channel sequence floor survives it, so older metadata stays refused as well.
- A receipt written before this field has retired nothing. A fresh `install` writes a new receipt with no retired keys: the installed release's lock is the whole trust root, as in [Bootstrap](#distribution-bootstrap). The documented re-bootstrap (`uninstall`, then `install --use-existing-state`) therefore starts over from the archive the operator verified.

Retirement is per installation and happens only when that installation activates the release that drops the key. A client that never activated it does not know about it; that is the revocation-list gap below.

## Lost-key recovery

- **Another pinned key remains** (the backup): sign the channel with it and ship a release that drops the lost key and pins a fresh pair. Clients continue without intervention.
- **No pinned key remains:** no installed client can verify any update again, and nothing in PiShip can re-establish trust remotely; that is the point of pinning. Each installation is re-bootstrapped: publish a new release pinning new keys, distribute it out of band as in [Bootstrap](#distribution-bootstrap), and have users reinstall it (`uninstall`, then `install --use-existing-state`, which keeps state). Start the new channel's sequence above the old one, so the old metadata can never compete.

## Channel hosting

**Layout.** One update source per distribution: a directory, served as static files over HTTPS or read locally. It holds all three channels side by side, and the archives they list:

```text
<updates.source>/
  stable.json       stable.json.sig
  candidate.json    candidate.json.sig
  dev.json          dev.json.sig
  <id>-<version>-<target>.tar.gz   (archives listed by any channel)
```

The channel names are fixed: `stable`, `candidate`, and `dev` (`RELEASE_CHANNELS`). Each channel's metadata is signed separately. A client keeps a separate sequence floor per channel, and only reads the channels its lock's `updates.channels` allows. Metadata copied from one channel to another is refused, because it names its own channel. Promotion means adding the same archive to another channel with `sign-channel --channel <name>`; the archive is not rebuilt. What each channel carries is the owner's policy. A typical policy is that `dev` takes every build, `candidate` takes qualified builds, and `stable` takes approved releases.

**Atomic publish.** A client reads `<channel>.json`, then `<channel>.json.sig`, in two requests, and verifies the signature over the exact bytes it received. A mixed or half-written pair therefore never verifies. A new metadata file with the old signature, a truncated file, or a signature without its metadata is refused with `INTEGRITY_FAILED` or `UPDATE_FAILED`. The refused read does not advance the sequence floor or change the installation, and the next `update` retries. An archive is checked against the signed size and digest, so an archive that is missing, partly uploaded, or replaced is refused before extraction. No half-published channel is ever accepted. A publish that is not atomic costs availability during the swap, not integrity.

To keep that availability window short, publish in this order:

1. Run `piship sign-channel` in a local staging copy of the source directory. It verifies each archive, verifies the existing metadata's signature, copies the archives in, and writes the metadata and signature.
2. Upload new archives first. Archive names include version and target, so they are new files; never overwrite an existing archive with different bytes.
3. Upload `<channel>.json.sig` and `<channel>.json` together. Where the host supports it, use one atomic operation: an object-store batch, or a directory rename or symlink swap on a web server.
4. Remove an archive only after no published channel lists it.

Re-sign every channel before `expires` (30 days by default). Expired metadata stops updates. That bounds how long a host can freeze clients on old metadata, but it also stops updates if the owner forgets.

`sign-channel` extends existing metadata only when it is valid channel metadata for that channel and its signature verifies with the signing key, with a key pinned by one of the releases being added, or with the key given as `--previous-key <id>=<public-key>`. Adding the overlap release, which pins both keys, lets the new key extend metadata the old key signed. Adding a release that pins only the new key (rotation step 4) on top of metadata the old key signed needs `--previous-key` with the old key's `updates.trust.keys` entry, so the owner states which key they expect to have signed it. Metadata that was edited after signing, has no signature, or was signed by any other key is refused with `INTEGRITY_FAILED` (`Existing channel metadata <path> ... refusing to extend it`), and nothing is written. Restore the published pair, or name the key that signed it with `--previous-key`. The signature is computed before anything is written, so an unusable key or key ID changes nothing. The metadata and then the signature are each written to a temporary file next to it, flushed, and renamed into place, so neither file is ever seen truncated. They keep the default file mode, because a web server serves them. A crash between the two renames leaves a new metadata file with the old signature: clients refuse that pair, and so does the next `sign-channel`, until the pair is restored from the published copy.

## GitHub Releases and signed channels

These are separate things:

| | GitHub Release (for example v0.7.1) | Signed update channel |
| --- | --- | --- |
| Proves | A GitHub artifact attestation proves which workflow, repository, and ref built an archive. A `.sha256` file proves which bytes were uploaded | The distribution owner offers this release on this channel now |
| Checked by | A person, with `gh attestation verify` and `sha256sum` | Every installed client, automatically, on `update` |
| Key | Sigstore keyless signature bound to the GitHub Actions identity | The owner's Ed25519 key, pinned in the lock |
| Freshness and rollback | None | Expiry and a monotonic sequence |

An installed client never consults GitHub, attestations, or checksum files when it updates. An attestation or asset checksum is therefore not channel trust and must not be described as one. A GitHub Release archive is at most a bootstrap input: something an operator verifies before a first install. The v0.7.0 and v0.7.1 pre-release archives pin no keys (`keys: []`), so an installation of them cannot update through any channel. That is intended.

## Examples

**Decision (#167):** the example distributions (`examples/demo-company`, `examples/personal`, `examples/enterprise-*`) only **demonstrate a distribution owner's own channel**. The PiShip project does not operate an official update channel for them and does not pin a project key in them.

Reasons, from the current code and repository:

- Every example manifest pins `updates.trust.keys: []`, and none sets `updates.source`, so nothing implies a project-operated channel.
- The E2E suites already demonstrate the full owner flow with throwaway keys generated at run time and a loopback channel (`tests/helpers/lifecycle.ts`). That covers `keygen`, pinning, `sign-channel`, update, and rollback, without any key that outlives the test.
- An official channel would make the project the update publisher for distributions whose IDs and commands (`acmecode`, `mypi`) are fictional. It would also require key custody, hosting, and re-signing every 30 days, for no user who needs it.
- A throwaway "production" key committed only to make a demo look complete would be a key whose custody nobody owns. It must not be added.

Operating an official channel would be a new decision; key generation, custody, and the first pin would then be maintainer actions, and this page and the example manifests would change in that same decision.

## Test coverage

| Requirement | Test |
| --- | --- |
| Signed metadata verification | `channel-trust.test.ts` "accepts metadata signed by any pinned key"; build-backed: `release.test.ts` "signed channels" |
| Rotation: overlap accepted, retired key refused after it | `channel-trust.test.ts` "rotation"; build-backed through real updates: `lifecycle.test.ts` "rotates the release key through an overlap release and then refuses the retired key" |
| Revoked and unknown key refusal | `channel-trust.test.ts` "refuses a revoked key however the signature names it", "refuses unknown keys and an empty trust root"; `signing.test.ts` |
| `sign-channel` refuses to extend unverified metadata and changes nothing when signing fails | `release.test.ts` "extends existing metadata only when its signature verifies", "changes nothing when signing fails, and leaves no temporary files" |
| Tamper rejection | Metadata byte change, half-published pairs, another channel's metadata, and archive digest or size mismatch: `channel-trust.test.ts`. Tampered archive in a channel: `lifecycle.test.ts`. Release contents: `release.test.ts` |
| Retired key refused after a rollback; fresh install has no history | `channel-trust.test.ts` "refuses a retired key that the active lock still pins"; build-backed: `lifecycle.test.ts` "keeps a key retired by an update retired after a rollback" |
| Rollback compatibility (replay, downgrade) | `channel-trust.test.ts` "rollback protection" (sequence floor, also across a key change); `lifecycle.test.ts` "refuses replayed older channel metadata", "refuses a downgrade offered by the channel" |

The `channel-trust.test.ts` cases build no release and run on every target in the pull request gate. The build-backed cases run where the host target has lifecycle evidence.

## Gaps and follow-ups

None of these weakens the current guarantees, and none blocks production validation. Items 1 to 4 are deferred to [#181](https://github.com/tc3oliver/piship/issues/181); each is a separate change that needs maintainer review:

1. **Time-bounded key validity.** Optional `notBefore`/`notAfter` per pinned key would let a retired key expire on clients that never update. This is a lock schema change.
2. **Revocation before activation.** Retired keys are recorded per installation, only once it activates the release that drops a key. A client that never activated that release still trusts the key, as in [Compromised-key recovery](#compromised-key-recovery). Refusing a key earlier needs a revocation list the client can authenticate.
3. **Multiple signatures per channel.** Accept a `.sig` that holds several envelopes, so one channel serves clients on both sides of a rotation.
4. **Signer hardening.** Support encrypted PEM keys, or an external signer (hardware token or KMS), in `sign-channel`.
5. **Official channel.** Not planned; see [Examples](#examples).
