# Linux managed sync initialization and preview

The default-off `experimental-linux-managed-sync` feature in
`exacopy-cli` selects the Linux application assembly and enables the
corresponding platform feature. The assembly exposes
`initialize_managed_preview` and `preview_managed_history` for one raw basename
across an ordered pair of live roots. The existing P-063 signed history
format is unchanged. The CLI has no dispatch for this feature. The assembly
has no history writer, baseline advancement, or authority to mutate either
live root. [Application assembly](../../apps/exacopy-cli/src/assembly/linux/managed_sync.rs) ·
[P-063 history contract](../architecture/sync-baseline-root-contract.md)

## Init acknowledgment

The caller supplies an existing profile path and its independently selected
physical identity, a nonzero 16-byte selection ID, a positive selection
revision, and the exact policy. The policy binds the actor and cooperative
enrollment, scope and mount session, ordered endpoint and root locators,
raw basename, per-side read ceilings, and an independently selected history
directory and artifact inventory. The private canonical version-1 JSON record
is capped at 24 KiB. Its digest uses the BLAKE3 derivation context
`ExaCopy local managed sync policy v1`.

Init holds the owner-private mode-0700 profile and its exclusive cooperating
profile lock. It reads that profile's existing `owner.seed` to derive the
owner's public identity. It acquires the managed live read lease, confirms
physical disjointness of the profile, history directory and two live roots,
and authenticates the selected history against the fresh scope before it
creates the record. The profile and history paths must descend from the
whole ext4 filesystem mounted at `/` through protected ancestry without
links or mount crossings.

The store exclusively creates `managed-sync-<32 lowercase hex digits>.v1`
in the selected profile. It requires mode 0600 and one link, writes and
syncs the file, independently reads its exact bytes through EOF, and syncs
the profile directory. It rechecks the seed and record custody. The assembly
then rechecks record custody, role disjointness and the live lease before
returning the opaque `ManagedSyncSelection`. The selection binds the
profile path and identity, selection ID and revision, derived owner profile
and public key, and exact policy digest. It is the acknowledgment required
by preview. The private filename can become visible during Init. An occupied
slot is preserved and refused. If a later step fails after creation, a typed
`CreationUnconfirmed` retains the slot for owner reconciliation and issues
no acknowledgment. [Policy codec](../../apps/exacopy-cli/src/sync_preview/managed_policy/wire.rs) ·
[Profile store](../../crates/platform/exacopy-platform/src/linux/sync_profile_store.rs)

## Seed-free preview and live scope

Preview requires the acknowledged selection. It reopens the exact profile and
bounded record under a shared profile lock, validates the canonical bytes
against the pinned owner identity and policy digest, and acquires the shared
live lease before subject lookup. It opens neither the owner seed nor a
policy-write handle. It authenticates the selected P-063 root and its three
exact children using the pinned public key and independently selected member
names and references. The signed history must match the selected subject,
historical revision, scan constraint and freshly held ordered endpoints.
Missing or invalid history refuses preview with no first-run fallback.

The transfer engine independently measures the present streams with BLAKE3
and the selected Linux mode, UID and GID projection, applies the per-side
bounds, and rechecks the held observations before classification. The
assembly rechecks custody before returning. An incumbent copy candidate is
a classification result and carries no write grant.
[History binding](../../apps/exacopy-cli/src/assembly/linux/managed_sync/history.rs) ·
[Transfer engine](../../crates/engines/exacopy-transfer/src/linux/sync_preview/history.rs)

The live guard matches the selected boot, mount and user namespaces, ordinary
and unique mount IDs, common parent, and ordered direct child roots. The
parent and both roots must be mode 0700 and belong to the selected nonzero UID
and GID. Admission requires full kernel identity maps, matching real,
effective, saved and filesystem user and group IDs, and empty inheritable,
permitted, effective and ambient capability sets. The selected actor and
observed subject ownership must avoid the corresponding kernel overflow
identity and all-ones sentinel. Positive `statmount` evidence for the exact
whole ext4 selection must show clear ID mapping.

The thread-bound read lease takes a nonblocking shared `flock` on the held
common parent. Enrolled same-owner writers must take an exclusive lock on
that exact parent before affected namespace, metadata or content changes,
including changes through retained handles. The enrollment ID records the
caller's independently approved cooperation. The provisioner must exclude
uncontrolled same-owner processes, untrusted retained mutation handles and
aliases, and administrators must preserve the selected scope. The lease
provides cooperative exclusion and the preview reports a live observation.
[Managed platform guard](../../crates/platform/exacopy-platform/src/linux/sync_preview/managed.rs) ·
[Mount observation](linux-managed-sync-statmount.md)

## Native qualification

The crate-owned manifest selects the exact ignored
`production_managed_init_then_preview_exact_p063_history` case in the
`linux_managed_sync_production` target, with the singleton
`experimental-linux-managed-sync` feature on `x86_64-unknown-linux-gnu`
and Rust 1.100.0. The runner independently admits an unprivileged actor
and a writable whole-ext4 location before allocating a disposable owner-private
parent and two empty anchors. The held Rust fixture checks positive
`statmount` and acquires and rechecks the real managed lease on the anchors
before creating synthetic live, history and profile data. It constructs its
signed P-063 history independently with a public fixture-only seed. The
positive path checks the exact right-to-left incumbent copy candidate, both
content digests and preserved live files.

The same selected test checks eight controls.

1. A native root identity mismatch refuses Init before slot creation.
2. A held exclusive live writer lock refuses Init before slot creation.
3. Repeated Init refuses the occupied slot and preserves its bytes.
4. Preview succeeds with the fixture seed absent from its selected name.
5. A held exclusive live writer lock refuses preview.
6. A right-side stream beyond the selected ceiling refuses preview.
7. Missing selected history refuses preview with no first-run fallback.
8. An isolated child forces a post-create metadata refusal. Init returns no
   selection receipt, retains the empty private slot, and a retry preserves the
   same incumbent inode. The child checks unchanged seed, history and live bytes;
   its deadline, output bounds and cleanup must complete before success.

The ownership checker binds the manifest to the exact package, Cargo target,
source, feature and selector. The runner binds the exact executable and test
inventory to independent boot, mount, namespace and held anchor evidence.
The transient live identities come from the Rust fixture's held checks.
The fixture emits its success marker only after verifying cleanup. The
canonical hosted workflow runs on a push to `replicraft/ExaCopy` main and
retains the exact result and capture logs. [Fixture manifest](../../apps/exacopy-cli/verification/managed_sync_production/fixture.toml) ·
[Native test](../../apps/exacopy-cli/tests/linux_managed_sync_production.rs) ·
[Hosted workflow](../../.github/workflows/linux-managed-sync-production-qualification.yml)

The [hosted execution at `90ed5bd`](https://github.com/replicraft/ExaCopy/actions/runs/45919881456)
built and ran the exact selected test once, with all eight controls passing and
no ignored cases in that invocation. The observed host used Linux
`7.0.0-1018-aws`, an unprivileged UID/GID 1001, full identity maps and a
whole ext4 mount. Independent checks matched the selected boot, namespace,
ordinary and unique mount IDs, and six distinct anchor/live directory identities.
The test confirmed fixture cleanup; the wrapper confirmed process drain and
absence of its owned work directory. The held executable SHA-256 was
`cf053d5c5551e26fd2d2fc04ecbc5e536d230dd342cf26c089991221344811e6`.
The retained artifact archives and their uncompressed members were verified.
This qualifies the executed Init and read-only preview controls under that
native profile and finite cooperative enrollment, with synthetic signed history.
It does not qualify future CLI receipt import or mutation.

The earlier [execution at `37ba6a1`](https://github.com/replicraft/ExaCopy/actions/runs/45918433791)
compiled and selected the exact case but failed its first root-mismatch assertion.
The bare assertion did not retain its returned error; cleanup was confirmed.
The subsequent fix removed an invalid `O_NONBLOCK` flag from an `O_PATH`
`openat2` call, made the wrong-root identity distinct from every selected
directory, and retained typed refusal diagnostics. The original error variant
remains unavailable. That failed observation is preserved separately.

The observed mount had `nobarrier` and `data=writeback`. Process-crash and
power-loss qualification remain open; passing these live controls supplies
neither claim.
