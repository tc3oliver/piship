# Support policy

This page is PiShip's stable compatibility and support contract from v0.11.0. It says which versions of each contract PiShip accepts, for how long, what a change may and may not do, and what is supported on which platform. It does not use "best effort" as a promise: every statement below is either guaranteed and tested, or listed as not guaranteed.

Terms used on this page:

- **Supported** means this repository's tests cover it and a defect in it is fixed in a release.
- **Accepted** means a command reads the input and gives a defined result. A schema that is accepted but not supported can be inspected and migrated, and cannot be built.
- **Migratable** means `piship migrate` moves a manifest to the current schema without broadening what it allows ([migration](manifest.md#migration)).
- **Relock** means running `piship lock` again so `piship.lock` matches the manifest and its resources.

## Contract versions

The PiShip package version, the manifest schema, and the lock schema are three separate versions, and none follows another.

| Contract | Identifier | Changes when |
| --- | --- | --- |
| PiShip package | `0.13.0` (a [SemVer](https://semver.org) version) | Every release. Decides which Pi versions and schemas a build accepts |
| Manifest | `piship/v1` | A breaking change to a manifest field, default, or rule: then `piship/v2`. Never for an additive change |
| Lock | `piship-lock/v1` | A breaking change to a lock key: then `piship-lock/v2`. Never for an additive key |
| Update root, channel, signature | `piship-update-root/v1`, `piship-channel/v1`, `piship-signature/v1` | A breaking change to that document |
| Release metadata | `piship-release/v1` | A breaking change to `release.json` |
| Local state | the schema ids in `runtime.stateSchemas` of the lock (`piship-state/v1`, `piship-identity-metadata/v1`, `piship-credential-metadata/v1`, and the others) | A breaking change to that file |
| Audit event and batch | `piship-audit/v1`, `piship-audit-batch/v1` | A breaking change to that document |
| Data lifecycle | `piship-data/v1` | A breaking change to the retention or purge contract |
| Capability contract | `piship.capability/<name>/v1` | A breaking change to what a provider of that capability must do |
| Capability provider | its own SemVer `version` in the manifest | Whenever the provider's owner releases it |

A capability provider's SemVer version and the capability contract it implements stay separate. A provider declares `version` for itself and `implements` for the contract IDs it meets. The launch loads a provider only when its contract major version matches the one PiShip knows, whatever its SemVer says; changing one never changes the other. Provider versions are not compared with PiShip's package version, a schema version, or a Pi version.

## Manifest: versions and the migration window

`piship/v1` is the current manifest schema. It freezes the semantics of `piship/v1alpha6`: every field, default, and validation rule of v1alpha6 holds in v1, and `release.bundle` and `release.strip` stay on unless a manifest sets them to `false`.

| Schema | Validate, lock, build a payload | Production release (`piship release`) | `migrate` |
| --- | --- | --- | --- |
| `piship/v1` | yes | yes | not needed |
| `piship/v1alpha6` | yes | yes | to `piship/v1` |
| `piship/v1alpha5` | yes | yes | to `piship/v1` through v1alpha6 |
| `piship/v1alpha1` to `piship/v1alpha4` | yes (`piship/v1alpha1` personal only) | no: a release needs v1alpha5 or later | to `piship/v1` through each step |

Every schema in the table can be inspected. An installed release keeps running on the manifest it was built from, whatever its schema.

**Migration window.** `piship/v1alpha6` keeps every column above through every `0.11.x` release and every `1.0.x` release. A schema leaves the build and release columns only in a new major version of PiShip, and the release notes of the release before it announce that. No schema leaves the `migrate` column before the next major version after the one that removed it from the build columns. A manifest on an older alpha schema is always inspectable, and migratable where the migration chain below it is registered, which it is for every alpha today.

This window is a policy decision taken in v0.11.0 and is part of the contract from then on. A longer window can be announced at any time. A shorter one cannot.

**What a stable schema may change.**

- Additive, backward-compatible changes keep `piship/v1`: a new optional field, a new enum value for an existing field, a new optional lock key, and a new `piship.capability` contract. A manifest that does not use the addition must still parse, lock to the same bytes, and mean the same.
- A change that removes a field or value, makes one required, narrows what one accepts, changes a default, or gives an existing field another meaning is breaking and needs `piship/v2`. A release does not make it silently, and it does not reinterpret an old manifest.
- A security fix may reject an input that was accepted and unsafe. It is listed as a behavior change in the changelog, and `validate` names the field. That is the only reason a `piship/v1` manifest may stop validating without a new schema.
- A release that uses an addition installs by update only from a release that knows it: the installed runtime does the update, and an older runtime reads only what it knows ([decision 27](decisions.md), restated for v1 in decision 34).

**An installation cannot update across a schema it does not know.** A `piship/v1` release reads a v1alpha6 release without a migration. The reverse is not true: the update is run by the runtime of the installed release, and a runtime built before `piship/v1` does not know that schema, so it refuses a `piship/v1` release with `INTEGRITY_FAILED` (`Installed manifest and lock mismatch`). To move an installed distribution, publish one bridge release first: build it with PiShip 0.11.0 and leave its manifest on `piship/v1alpha6`; installations update to it with their old runtime, and it carries the 0.11.0 runtime. Every later release can then use `piship/v1`. This was checked against the v0.10 runtime while writing this policy. A distribution whose first 0.11.0 release already has `piship/v1` works for new installations; only the update from an older release needs the bridge.

## Lock: reader compatibility and relock rules

A lock is written for one manifest by one PiShip. The rules:

- **Reader compatibility.** PiShip 0.11.x reads and verifies the locks of `piship-lock/v1alpha5`, `piship-lock/v1alpha6`, and `piship-lock/v1`, the schemas that can carry a release, for install, update, rollback, `inspect`, `doctor`, `verify-release`, and `diff`; an older lock loads as before for a payload that carries one. A lock written by an older PiShip keeps its digests: the digest of a v1alpha6 manifest is computed over the parsed manifest including its schema string, and PiShip 0.11.0 computes the same value for that manifest, so a release built by PiShip 0.10 installs, verifies, updates, and rolls back unchanged ([tests](#how-the-contract-is-tested)).
- **Relock requirements.** A lock is stale, and `build` refuses it, when the manifest, a declared resource, a Pi package, a bundled search tool, the pinned Pi version, or the PiShip version that wrote it changes the lock's content. Changing only the schema id (`piship migrate --write`) changes the manifest digest, so the lock is relocked after every migration. A relock never needs a network except for Pi packages and search tools that the lock records for the first time or changes.
- **Static reproducibility.** The same manifest, resources, package inputs, Pi version, and PiShip version produce the same lock bytes on every machine and every day: there is no timestamp, no host path, and no resolved runtime value. The lock fixes the runtime identity and version, the PiShip version, each resource's SHA-256 and trust class, each provider's resolution and capability contract, integrity values for every package, the parsed static policy, and the other static facts of the distribution.
- **What a lock never holds.** The current user's entitlement, a runtime credential or token, a resolved endpoint, live gateway state, or the state of a remote MCP server. Runtime variables are locked as `${NAME}` references, never as values. Filesystem deduplication and bundling of the payload do not change the lock: the lock describes the logical dependency graph, not the files on disk.
- **Additive lock keys** do not stale an existing lock and are never required of an older one. A reader treats an absent optional key as the documented default.

## Pi

PiShip pins exactly one Pi version at a time and runs only that version. Everything about the pin, the upgrade procedure, and the supported matrix is in [Pi compatibility](compatibility.md#compatibility-contract).

## Local state, update, and rollback

The state under `<state>/<id>` is the user's. These rules hold for every update, rollback, and migration:

- **Forward.** An update or install onto existing state reads the files it knows and never rewrites a file it cannot read. A state file whose schema the new release cannot read makes the migration check report `unsupported` and the update stops before activation, with the file's path and the way out.
- **Rollback.** A rollback switches only the immutable payload. It reads state as it is and does not restore an earlier copy. The state files an update leaves must stay readable by the release it replaced, which is why a schema id that an older release reads is never removed ([state schemas](release/update-lifecycle.md#migration-check-and-local-data)). The one exception is a credential class the target cannot read: it is cleared and the user signs in again.
- **Migration.** `piship migrate-check <id> <release>` and `update --check` report `safe`, `requires-review`, or `unsupported` for each state class before anything changes. Preferences and user policy rules are copied into a snapshot before an update. A snapshot is a recovery copy; no command restores it.
- **Credentials.** A runtime credential, an identity token, and a secret-store entry never enter a snapshot, a release, or a migration artifact, and no rollback or restore brings one back. After `logout`, a rolled-back release asks for `login`.

## Platforms, Node.js, and end of life

- **Node.js.** `22.19.0` or newer on the machine that builds, and on every machine that runs a distribution (the install shim says so when it is missing). The CI gate runs Node 22.19.x. A new Node major is added to the supported set when its gate passes on all three operating systems, and a Node major leaves it when Node upstream ends its support, with the removal announced in the release notes of the release before. npm 11 or newer is required only on the machine that runs `piship lock` for a distribution that declares Pi packages.
- **Operating systems and targets.** Release archives are built for `linux-x64`, `darwin-arm64`, and `win32-x64`, and each is tested on its own operating system in CI: Linux (Ubuntu), macOS (arm64), and Windows (x64). No other target is supported, and `release.targets` rejects one. A new target is added only with its own installed end-to-end evidence.
- **Windows.** Fully supported for the personal and managed surfaces with these exceptions: there is no native sandbox adapter (a required native sandbox fails with `SANDBOX_UNAVAILABLE`; a remote backend can be used), and the Windows sandbox is outside this contract.
- **macOS and Linux.** Fully supported, with the native sandbox (Seatbelt on macOS, bubblewrap on Linux where unprivileged user namespaces are available).
- **End of life.** A PiShip release line is supported with fixes until the next minor release, or for the release that is a [production-validation baseline](status.md) until its successor is qualified and published, whichever is later. A Pi version leaves the matrix only through the [upgrade procedure](compatibility.md#upgrading-pi), and an installed release on it keeps running. A release that is out of support keeps installing and updating; it receives no fix.

## What is not guaranteed

These are not part of the contract, so no document should present them as one: the physical layout of a payload (which files exist, whether packages are bundled or shared), the text of a message or a warning, the order of fields in human-readable output, the contents of `build-info.json`, benchmark numbers, and any behavior of an unlisted Pi version, schema, Node major, or target. A property that is guaranteed is written as a rule above, with a test.

## How the contract is tested

- `packages/schema/src/v1.test.ts`: every example manifest parses to the same manifest under `piship/v1alpha6` and `piship/v1`; the v1alpha6 defaults hold in v1; an unknown schema is refused.
- `packages/schema/src/migrations/migrations.test.ts` and its fixtures: the v1alpha6 to v1 step changes only the schema id, and `migrate --check` classifies a manifest as migratable, requires review, or cannot migrate.
- `packages/cli/src/index.test.ts`: `migrate --check` writes nothing and exits 0, 1, or 3.
- `packages/core/src/lock-v1.test.ts`: the v1alpha6 digest is frozen, a v1 lock equals the v1alpha6 lock apart from its two schema ids, and a lock round-trips.
- `packages/core/src/lifecycle-schema-compat.test.ts`: a v1alpha6 release installs and verifies, and an installation updates from it to a v1 release and rolls back with the old release unchanged.
