# Release trust root and signed channels

This page covers the keys that authorize a distribution's updates: the update root, its root and channel roles, how an installation keeps its current root, how keys are rotated and revoked, and how a channel is hosted. It is part of the [release guide](../release.md). The commands are in the [owner workflow](owner-workflow.md#signing-a-channel), the step-by-step procedures in the [key runbook](key-runbook.md), and what a client checks when it updates in the [update lifecycle](update-lifecycle.md#channels-and-signed-metadata).

## Model in one paragraph

Each distribution has its own **update root**: a versioned set of Ed25519 public keys with two signing roles. The **root role** decides which keys are trusted; the **channel role** signs channel metadata. Each role has a threshold of distinct keys that must sign. The owner pins the first root in the manifest as `updates.trust.bootstrap` (`piship/v1alpha5`), and `piship lock` copies it into the lock. A fresh install takes that bootstrap from the release it verified and keeps it as **installation trust state**; from then on only a newer root, published as `root/<N+1>.json` in the update source and signed by both the current and the new root role, changes it. Before every update the client fetches newer roots one version at a time, persists each, and verifies the channel with the newest root's channel role. Activating a release, rolling back, switching channels, or a release lock never changes the installation's root, so a channel signer cannot gain root authority by publishing a release with another lock. Nothing is trusted on first use from the channel.

## What the code implements

| Property | Where | Status |
| --- | --- | --- |
| Ed25519 keys; PKCS#8 PEM private key (plaintext or encrypted); 44-byte SPKI DER public key, base64 | `packages/core/src/signing.ts` | Implemented |
| `piship keygen` writes the private key with mode 0600 and never overwrites one. It refuses a path inside a git work tree that is not git-ignored, unless `--force-in-worktree` is given | `writePrivateKey`, `privateKeyLocation` | Implemented |
| A bootstrap root in the manifest and lock (`updates.trust.bootstrap`): `version`, `expires`, `keys`, and `roles.root` / `roles.channel` with `keyIds` and `threshold`; no private key or secret-named field accepted | `parseUpdateRoot` in `packages/schema/src/lifecycle.ts` | Implemented |
| Installation trust state: the current root, its digest, and removed-key history in `<install home>/trust/<id>.json`, owner-only, replaced atomically | `packages/core/src/install/trust-state.ts` | Implemented |
| A fresh install starts trust state from the verified lock; activation, rollback, channel changes, and release locks never change it | `installDistribution`, `updateDistribution` | Implemented |
| Damaged or missing trust state fails closed; it is never rebuilt from the active lock | `readTrustState`, `installationTrust` | Implemented |
| Hosted roots (`piship-update-root/v1`) fetched sequentially, each version exactly N+1, signed to both the current and the new root-role threshold, persisted before the next | `refreshRoot`, `verifyRootTransition` | Implemented |
| Only an authoritative absence (HTTP 404, no such file) ends the refresh; any other failure stops the update before the channel | `readOptionalSourceFile`, `refreshRoot` | Implemented |
| Bounds: 64 KiB per root file, 64 KiB per root signature, 64 transitions per update attempt | `MAX_ROOT_BYTES`, `MAX_ROOT_SIGNATURE_BYTES`, `MAX_ROOT_TRANSITIONS` | Implemented |
| One fixed time per update attempt; the newest root must be unexpired to authorize a channel; expired intermediate roots may still advance | `updateDistribution`, `rootExpired` | Implemented |
| `piship-signature/v1` with optional `signatures[]`; distinct valid trusted signatures counted against a role threshold | `verifyThreshold` | Implemented |
| Channel metadata (`piship-channel/v1`) bound to its distribution and channel, with an expiry and a monotonic sequence; a sequence floor per channel in the install receipt | `readChannel`, receipt `channelSequences` | Implemented |
| Archive size and SHA-256 must match the signed entry before extraction; distribution, command, version, Pi version, and lock digest after | `downloadArchive`, `updateDistribution` | Implemented |
| Downgrades offered by a channel are refused | `updateDistribution` | Implemented |
| `piship diff` reports a changed bootstrap root as `high` risk ("Changes who can publish updates") | `packages/core/src/diff/areas/updates.ts` | Implemented |
| `piship install --sha256 <hex>` and `--expect-key sha256:<fingerprint>` pin the archive and the bootstrap's channel keys before anything is installed | `installDistribution` checks | Implemented |
| Owner tooling: `trust-root init` (bootstrap material) and `trust-root next` (the next signed root) | `initTrustRoot`, `nextTrustRoot` | Implemented |
| `sign-channel` with several keys, writing `signatures[]` and a legacy-compatible top-level signature, and refusing signatures that do not satisfy the releases' declared trust | `signChannel` | Implemented |
| Every signature is verified against the signer's public key before anything is written; a failing signer changes no file | `signVerified` | Implemented |
| Signing with a key held in a hardware token, KMS, or agent | Internal `Signer` interface | Not implemented: no external signer protocol |
| Collecting root signatures across separate machines (a partially signed root) | | Not implemented: `trust-root next` signs in one run |
| An official channel or a production key operated by the PiShip project | | None exists |

## Roles and thresholds

| Role | Signs | Who should hold it |
| --- | --- | --- |
| `root` | `root/<N+1>.json`: which keys exist and which role each key has | Offline keys, used only for a rotation or a revocation, held by different people |
| `channel` | `<channel>.json`: which releases each channel offers | The routine release signer |

A threshold is the number of **distinct** keys of that role whose valid signatures are required. A signature by a key outside the role, a malformed entry, or an entry that does not verify does not count, and one public key counts once even if two IDs name it (the schema refuses that anyway). A managed distribution needs distinct root and channel keys; `piship release` refuses a managed release whose roles share a key. A personal distribution may put one key in both roles.

## Installation trust state

The current root of an installation lives in `<install home>/trust/<id>.json` (`piship-update-trust/v1`), next to the install receipt, never inside `apps/<id>`:

```json
{
  "schema": "piship-update-trust/v1",
  "distribution": "acmecode",
  "origin": "bootstrap",
  "root": { "version": 1, "expires": "...", "keys": [], "roles": {} },
  "digest": "sha256-<canonical root digest>",
  "removedKeys": [{ "id": "channel-a", "fingerprint": "sha256:...", "role": "channel", "version": 2 }],
  "updatedAt": "..."
}
```

- **Fresh install.** `piship install` (and `install.sh` / `install.ps1`) verifies the release and writes the trust state from its lock's bootstrap, replacing any leftover of an earlier install. A lock whose bootstrap (or v1alpha4 key list) is not a valid root is refused with `LOCK_INVALID`, and no trust state is written; the same check applies when a pre-v0.8 receipt is migrated. The receipt records that the installation has trust state (`trustState: true`).
- **Monotonic.** Only a verified root refresh writes it. Each accepted version is written whole (temporary sibling, flush, rename, directory flush) before the next version is fetched or the channel is read. An interruption leaves the previous root or the new one, never a mix.
- **Never lowered.** Activating a release whose lock has an older (or newer) bootstrap, rolling back to a release that pins a removed key, or switching channels does not change it.
- **Fails closed.** A trust state that cannot be parsed, names another distribution or schema, holds an invalid root, or whose root does not match its digest stops `update` with `INTEGRITY_FAILED`, as does a missing one when the receipt says it should exist. PiShip never rebuilds it from the active release lock, because that lock may predate a revocation. `doctor` reports the problem.
- **Recovery** is an explicit re-bootstrap from a release verified out of band: `piship uninstall <id>` (state is kept), then `piship install <archive> --sha256 <published digest> --use-existing-state`. The new installation starts from that release's bootstrap, then catches up through the published roots on its next update.
- **Receipts written before v0.8** have no trust state. The first v0.8 update takes it once from the active lock, leaving out keys that v0.7 had retired, and marks the receipt; after that the rules above apply.
- **v1alpha4 releases** (`updates.trust.keys`) have no roles. Their keys become root version 1 with every key in both roles at threshold 1, and an expiry that never arrives (`9999-12-31T23:59:59Z`). That is exactly what v1alpha4 already trusted, no stronger: any one legacy key can sign a channel or the next root. A compromised legacy key therefore also holds root authority over such an installation (`origin: "legacy"`): root rotation cannot recover it, because the attacker can publish roots too. Recovery is a reinstall from an archive verified out of band. Owners should move these installations to a split root and channel bootstrap promptly ([bridge](#v07-to-v08-bridge)).
- **Removed channel keys reach the receipt.** When a root removes a key from the channel role, the update also records it in the receipt's `retiredKeys` (`release: "root <N>"`). A PiShip v0.7 CLI, which a rollback to a release it installed brings back, trusts its lock's keys minus those retired keys, so it does not trust the removed key again.
- The per-channel sequence floor stays in the install receipt (`channelSequences`), which `rollback` also keeps.

## Root refresh

At the start of each update attempt the client records one time and uses it for every expiry check of that attempt. Starting from its current root N:

1. Request `root/<N+1>.json`.
2. If the source answers HTTP 404 (or, for a directory source, the file does not exist), stop: N is the newest root.
3. Any other answer stops the update: a network, TLS, or proxy failure, another HTTP status (including 5xx), a body over 64 KiB, malformed JSON, or `root/<N+1>.json` without `root/<N+1>.json.sig`. The client never continues to the channel on an unknown root.
4. Require `schema: piship-update-root/v1`, this distribution, a valid body, and `version` exactly N+1.
5. Require distinct valid signatures meeting the **current** root-role threshold and, separately, the **new** root-role threshold.
6. Persist N+1 and repeat with N+2. More than 64 new versions in one attempt stops the update after persisting the first 64; the next attempt continues.
7. Require the newest root to be unexpired at the attempt's time, then verify the channel with its channel role and threshold.

An expired root may authenticate its successor, so a client that was offline for a long time catches up. An expired newest root authorizes nothing: update fails until the owner publishes a newer one, or the clock is corrected.

## Signatures

The detached signature stays `piship-signature/v1`. The `signatures[]` field is optional and additive:

```json
{
  "schema": "piship-signature/v1",
  "keyId": "acmecode-release-2026",
  "algorithm": "ed25519",
  "signature": "...",
  "signatures": [
    { "keyId": "acmecode-release-2026", "algorithm": "ed25519", "signature": "..." },
    { "keyId": "acmecode-channel-2027", "algorithm": "ed25519", "signature": "..." }
  ]
}
```

- Without `signatures[]`, the top-level signature is the only signature.
- With it, the top-level signature must equal one entry, and a key ID may appear only once; otherwise the envelope is refused.
- Unknown keys, other algorithms, and malformed or invalid signatures do not count. Only distinct valid trusted signatures count toward the role's threshold.
- PiShip v0.7 clients ignore `signatures[]` and check only the top-level signature, which is what keeps one envelope valid for both.

## v0.7 to v0.8 bridge

A distribution whose installed base runs v0.7 (v1alpha4 `updates.trust.keys`) moves to a split root without stranding anyone:

1. Generate root keys and a channel key, and pin a v1alpha5 bootstrap in the next release (`piship trust-root init`). Fresh v0.8 installs start from it.
2. Publish `root/2.json` with the same body, signed by a legacy key **and** the new root key or keys: `piship trust-root next ... --sign <legacy>=<pem> --sign <root>=<pem>`. A v0.8 client migrated from v0.7 (legacy root 1) accepts it through the legacy key; a fresh v0.8 install (bootstrap root 1) accepts it through the new root key. Both end on the same root 2. (`trust-root next` checks the transition against the manifest's bootstrap; it does not know the legacy root, so include a legacy key yourself.)
3. Sign channels with the legacy key first and the channel key second: `sign-channel ... --key <legacy.pem> --key-id <legacy> --key <channel.pem> --key-id <channel>`. The top-level signature is the legacy key, which v0.7 clients verify; v0.8 clients verify the set against the channel role.
4. When no v0.7 client remains, stop signing with the legacy key and remove it from the root (`trust-root next --remove-key <legacy>`).

Do not stay on legacy trust longer than the installed base needs: until root 2 is accepted, a migrated installation's legacy keys hold both roles at threshold 1, so a stolen legacy key can sign roots as well as channels, and only an out-of-band reinstall recovers that installation ([Installation trust state](#installation-trust-state)).

## Key lifecycle and custody

**Generation.** `piship keygen <file> --id <key-id> [--encrypt]` generates a key and prints its public key and fingerprint. Generate each key on the machine that will sign with it, outside every repository. Publish the fingerprints out of band so operators can compare them (see [Bootstrap](#distribution-bootstrap)).

**Encrypted PEM.** `keygen --encrypt` writes an AES-256-CBC encrypted PKCS#8 PEM. Signing commands (`sign-channel`, `trust-root next`) take its passphrase at a hidden prompt (one per encrypted key), from the environment variable named by `--passphrase-env <NAME>` (one passphrase for every encrypted key of the run), or from `--passphrase-stdin` (one encrypted key). The passphrase is never a command-line value and never appears in output or errors. Use encrypted PEM for every key that is not in a hardware token; keep the passphrase in a password manager separate from the key file.

**Storage.** The private key never enters the repository, the manifest, the lock, a release archive, CI logs, or CI artifacts. Keep root keys offline, on encrypted storage, held by different people, and bring them online only for a root change. The channel key is the routine signing key.

If an owner signs from CI, keep the key in a protected deployment environment secret that only the signing job reads, write it to a 0600 file for the job and delete it after, and pass the passphrase with `--passphrase-env`. Never put a root key in CI. That setup is the owner's decision and is outside PiShip.

**Custody.** Key custody belongs to the distribution owner. The PiShip project holds no key for any distribution, and no agent or automation generates or pins a production key.

**Key IDs.** An ID is a label, not a fingerprint. Use IDs that name the distribution, role, and generation (`acmecode-root-2026a`, `acmecode-channel-2026`), and never reuse an ID for a different public key.

## Distribution bootstrap

A client trusts nothing until it installs a release. Its first root is the bootstrap of the **first release it installs**. `verify-release` proves that an archive is internally consistent; it does not prove who built it. The first install's authenticity therefore comes from how the archive reached the machine:

- Managed distributions: deliver the first archive through a channel the organization already trusts (device management, an internal catalog, an internal HTTPS host). Operators compare the archive SHA-256 and the key fingerprints with the values the owner publishes.
- Personal distributions: the user does the same comparison by hand, or accepts the risk of the place they downloaded from.

```sh
piship install acmecode-1.0.0-linux-x64.tar.gz \
  --sha256 <archive-sha256> \
  --expect-key sha256:<channel-key-fingerprint>
```

`--expect-key` checks that each given fingerprint is among the channel keys of the lock's bootstrap. A mismatch installs nothing. `piship inspect` and `doctor` show the key IDs and fingerprints; `doctor` also shows the installation's current root version, its origin, its expiry, and the channel keys a newer root removed.

The bootstrap may be a later root: after a rotation, owners may pin the newest root (its version, keys, and roles) as the bootstrap of new releases, so fresh installs start there and fetch only later versions.

## Rotation

**Channel key.** Publish the next root with the new channel key in the channel role (`trust-root next --add-key <new>=<public-key> --channel-keys <old>,<new>` for an overlap, or `--remove-key <old> --add-key ... --channel-keys <new>` to switch at once), signed by the root role. A client accepts the new key as soon as it has fetched that root, before any release changes. Then sign channels with the new key. During an overlap, `sign-channel` can sign with both keys so clients that have and have not fetched the root both verify.

**Root key.** The next root names the new root keys; it must be signed by the current root role's threshold **and** the new root role's threshold (`trust-root next --sign <old>=<pem> --sign <new>=<pem>`). Each key counts once toward each threshold.

**Expiry.** Each root expires. Publish the next root (it may change nothing but the expiry) before the current one expires, or every client stops updating.

## Compromised channel key

Publish the next root without the compromised key, signed by the root role, and sign the channel with a remaining or new channel key at a sequence above every one ever published. A client that fetches that root stops counting the compromised key immediately: the root refresh runs before the channel is read, so metadata signed by it is refused before any release is downloaded or activated. `rollback` does not restore it, because rollback does not touch the trust state.

### Security boundary

This recovers from a compromised channel key **once the client obtains the authentic newer root**. It does not guarantee remote revocation. An attacker who can serve the client's update source (or whom a user names with `update --from`) can withhold `root/<N+1>.json` by answering 404, and if that attacker also holds a channel key the client still trusts, the client accepts a channel that attacker signs. That is a security exposure, not only an availability problem: the compromised key stays usable against that client until the client learns the revocation through a source the attacker does not control, or the client's current root (or the attacker's channel metadata) expires and the client fails closed. Limit it by keeping root and channel expiries short enough to bound the window, serving the update source over HTTPS from a host the attacker does not control, and telling users not to run `update --from` with a source they were sent.

A plain-HTTP channel (`updates.transport: http-allowed`) widens who can withhold: anyone on the network path between the client and the update host can forge the 404 for `root/<N+1>.json`, not only whoever controls the endpoint. Combined with a compromised channel key the client still trusts, that is the exposure above, open to the network path. HTTP does not let them forge a root, alter channel metadata, or replay an older channel: those stay signature-, digest-, and sequence-checked. Prefer HTTPS when a compromised channel key is a realistic threat, and keep expiries short on an HTTP channel.

A channel signature also authorizes code. A release the compromised key signed and a client activated ships the PiShip CLI that manages that installation from then on, and that code can rewrite the trust state, the receipt, or anything else the user can write. Root rotation therefore recovers only installations that have **not yet activated** a release signed with the compromised key. Installations that have need a reinstall from an archive verified out of band ([stranded clients](key-runbook.md#stranded-clients)); compare every archive the key may have signed with your release record to find them.

An installation whose trust came from v1alpha4 legacy keys (`origin: "legacy"`: the legacy keys hold both roles at threshold 1) gives a compromised legacy key root authority too, so no root rotation can recover it; reinstall it from an archive verified out of band, and move such installations to a split root and channel bootstrap promptly ([bridge](#v07-to-v08-bridge)).

A compromised **root** key, below the root threshold, is handled the same way: the remaining root keys publish a root without it. At or above the threshold, the attacker can publish roots; installations must be re-bootstrapped from a verified release (see the [key runbook](key-runbook.md#compromised-root-keys)).

## Channel hosting

**Layout.** One update source per distribution: a directory, served as static files over HTTPS or read locally. A distribution that sets `updates.transport: http-allowed` may serve it over plain HTTP from a private or internal host ([manifest](../manifest.md#plain-http-update-channel-v1alpha5)); the files and their verification are the same:

```text
<updates.source>/
  root/
    2.json          2.json.sig
    3.json          3.json.sig
  stable.json       stable.json.sig
  candidate.json    candidate.json.sig
  dev.json          dev.json.sig
  <id>-<version>-<target>.tar.gz   (archives listed by any channel)
```

Root version 1 is the bootstrap in the release; the first hosted root is version 2. Never delete or replace a published root: clients that are behind need every version in order. A host must answer HTTP 404 for an absent `root/<N+1>.json`; any other answer for it stops updates.

The channel names are fixed: `stable`, `candidate`, and `dev`. Each channel's metadata is signed separately, a client keeps a sequence floor per channel, and metadata copied from one channel to another is refused.

**Atomic publish.** A client verifies the signature over the exact bytes it received, so a mixed or half-written pair never verifies; the refused read changes nothing and the next update retries. `trust-root next` writes `root/<N+1>.json.sig` before `root/<N+1>.json`; upload them in that order, so a client never finds the metadata without its signature. For channels, upload new archives first, then `<channel>.json.sig` and `<channel>.json` together, and remove an archive only after no published channel lists it. Re-sign every channel before `expires` (30 days by default).

`sign-channel` extends existing metadata only when its signature verifies with one of the signing keys, a key of the releases' declared trust, a key pinned by a release being added, or `--previous-key <id>=<public-key>`. Before writing, it checks the new signatures against the trust the releases declare: the newest root in the channel directory's `root/` reached from their bootstrap (each transition verified as a client would), or for v1alpha4 releases the top-level signature against `updates.trust.keys`. Signatures that clients would refuse are not published.

## GitHub Releases and signed channels

| | GitHub Release (for example v0.7.1) | Signed update channel |
| --- | --- | --- |
| Proves | A GitHub artifact attestation proves which workflow built an archive; a `.sha256` file which bytes were uploaded | The distribution owner offers this release on this channel now |
| Checked by | A person, with `gh attestation verify` and `sha256sum` | Every installed client, automatically, on `update` |
| Key | Sigstore keyless signature bound to the GitHub Actions identity | The owner's Ed25519 keys, through the installation's update root |
| Freshness and rollback | None | Root and channel expiry, root versions, and a monotonic channel sequence |

An installed client never consults GitHub, attestations, or checksum files when it updates. A GitHub Release archive is at most a bootstrap input.

## Examples

**Decision (#167):** the example distributions only **demonstrate a distribution owner's own channel**. The PiShip project does not operate an official update channel for them and pins no project key in them. The E2E suites demonstrate the owner flow with throwaway keys generated at run time (`tests/helpers/lifecycle.ts`, `tests/helpers/update-trust.ts`).

## Test coverage

| Requirement | Test |
| --- | --- |
| Threshold signatures: legacy single, multi, top-level must match, duplicate IDs, unknown and invalid entries, v0.7 fixture, v0.7 / v0.8 bridge | `update-trust.test.ts` "threshold signatures" |
| Root refresh: N+1, skipped version, old and new thresholds, sequential catch-up, expired intermediate, missing signature, other distribution, bounds, 404 versus 5xx, 403, and transport failure over HTTP | `update-trust.test.ts` "root refresh" |
| Trust state: bootstrap, legacy keys, malformed lock trust refused, damaged state fails closed, interrupted write | `update-trust.test.ts` "installation trust state" |
| Malformed lock bootstrap refused at install and at pre-v0.8 migration, writing no trust state | `lifecycle.test.ts` "refuses to install a lock whose update trust bootstrap is malformed", "refuses to migrate an installation from before v0.8 onto a malformed bootstrap" |
| Owner tooling: `trust-root init`, `trust-root next`, root-key rotation, signer failure writes nothing | `update-trust.test.ts` "trust-root owner tooling"; `cli/src/index.test.ts` |
| A release lock never widens trust; channel key rotation through a root; removed key refused and retired in the receipt for a v0.7 CLI; rollback does not restore it | `lifecycle.test.ts` "rotates the channel key only through a signed root" |
| Emergency removal before any download | `lifecycle.test.ts` "an emergency root removes a compromised channel key before anything is downloaded" |
| Expired final root; expired intermediate root | `lifecycle.test.ts` "an expired final root cannot authorize the channel" |
| Transport failure stops before the channel | `lifecycle.test.ts` "a failed root fetch stops the update before the channel" |
| Fail closed and explicit re-bootstrap; pre-v0.8 migration; interrupted root writes | `lifecycle.test.ts` "a damaged or missing trust state fails closed", "takes an installation from before v0.8", "an update interrupted between root versions" |
| Replay and expiry of channel metadata | `channel-trust.test.ts`; `lifecycle.test.ts` "refuses replayed older channel metadata" |
| `sign-channel` declared-trust check and existing-metadata check | `release.test.ts` "signed channels" |

## Gaps and follow-ups

1. **Partial root signing.** `trust-root next` collects every signature in one run. Root key holders on separate machines need a way to add signatures to an unsigned N+1; until then, bring the keys (or their holders) to one signing session.
2. **External signers.** A hardware token or KMS signer would implement the internal `Signer` interface; no public protocol exists yet.
3. **Withheld roots.** See the [security boundary](#security-boundary); short expiries are the mitigation.
4. **Official channel.** Not planned; see [Examples](#examples).
