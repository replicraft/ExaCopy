# Linux managed sync genesis producer

The Linux SDK entry `produce_managed_genesis` is available through
`exacopy-cli` with the default-off `experimental-linux-managed-sync` feature.
It creates one immutable generation-one P-063 history for one raw basename
in an ordered live pair. The result returns the published directory identity
and the typed root and member references for independent selection. The
producer has no CLI command, current baseline pointer, automatic adoption
or baseline advancement. It issues no live-tree content or namespace
mutation. [SDK entry](../../apps/exacopy-cli/src/assembly/linux/managed_sync/genesis.rs) ·
[Genesis decision](../architecture/sync-baseline-genesis.md)

## Independent selection and measurements

The request selects the existing owner-private profile and its native
identity, a strong canonical owner key and positive revision, the exact
native scope and raw subject, ordered endpoint and root locators, per-side
stream ceilings, a finite writer roster, and an independently selected
protected output parent. A nonzero operation ID fixes the output names.
The explicit scan, record UUIDv7s and timestamp label the record. They
supply no freshness or mutation authority.

The producer derives the profile ID from the approved key. It opens the
existing seed through the same held profile under its exclusive cooperating
lease and verifies the derived public key. Seed and EOF buffers are
zeroized. Rechecks use the same held seed custody, and the output contains
only the public signed artifacts and publication evidence.

Under the managed shared read lease, transfer measures the two present,
distinct, single-link regular files independently from offset zero through
exact EOF. It requires equal lengths and BLAKE3 digests and equal required
Linux metadata, including ordinary mode, UID and GID. A final paired recheck
binds both measurements to the selected raw names, held file identities and
stamps before signing. The held paths and pair are rechecked through output
effects and acknowledgment. [Measurement coordinator](../../crates/engines/exacopy-transfer/src/linux/sync_genesis_measurement.rs) ·
[Managed read lease](linux-managed-sync-production.md)

The enrollment must contain 1–32 strictly increasing, distinct, nonzero
participant IDs. The application recomputes a domain-separated BLAKE3
commitment over the exact roster and selected owner, native scope, endpoints
and protected output, and compares it with the independently retained
expected digest. The digest establishes agreement with the approved
selection. The provisioner remains responsible for actual participant
enrollment and for excluding uncontrolled mutators, retained writable
handles and aliases. Cooperating live writers must take the exclusive lock
on the exact common parent before changing either selected root or subject.
The output's separate exclusive lease also relies on cooperation.
[Approval binding](../../apps/exacopy-cli/src/assembly/linux/managed_sync/genesis/approval.rs)

## Protected output and acknowledgment

The existing owner-private output parent must have its selected native
identity, protected no-follow ancestry and the same ordinary and unique
whole-ext4 mount IDs. Held identity and ancestry checks keep it physically
disjoint from the profile, live parent and both roots. The writer checks
all three derived names absent before the first creation. With `id` the
lowercase hexadecimal operation ID, those names are
`.exacopy-genesis-stage-<id>`, `.exacopy-genesis-intent-<id>.v1` and
`genesis-<id>`.

The stage is mode 0700. Its exact four mode-0600 single-link files are
`root.cbor`, `left.cbor`, `right.cbor` and `leaf.cbor`. The signed
root and endpoints and paired Manifest leaf use the existing P-063
formats. Each member is bounded to 2,048 bytes and the closure to 8,192.
The platform syncs each file, retires all member writers and independently
reopens and reads the exact names through EOF. The application verifies the
staged closure with the existing authenticated P-063 reader. The platform
then synchronizes the stage directory.
[P-063 format](../architecture/sync-baseline-root-contract.md) ·
[Assembler](../../crates/engines/exacopy-transfer/src/sync_genesis/assemble.rs)

The separate private 364-byte version-1 `EXSYNINT` record binds the operation,
output and original stage identities, the application approval-and-closure
commitment and four ordered member entries. Each entry includes kind,
length, the canonical P-063 commitment and a raw BLAKE3 digest of the
complete bytes. The application commitment binds the independently selected
scope to the canonical root digest. The raw digest also covers the signed
envelope bytes. The intent has no signing material or standing authority.
The platform exclusively creates the intent, synchronizes it, retires
its writer, and independently reopens and verifies its identity, bytes and
EOF. It synchronizes the output parent before rename.

At each effect the application checks the exact selected intent and owner,
enrollment and live scope. With writers retired, the one-use permit submits
one same-parent `RENAME_NOREPLACE` for the original held stage. After kernel
success the publisher checks the exact final inode, original stage absence,
stable intent and four original member identities and bytes. It synchronizes
the parent and repeats the custody and live checks before returning the
acknowledgment.
[Native output](../../crates/platform/exacopy-platform/src/linux/sync_profile_store/genesis_output.rs) ·
[Intent codec](../../crates/platform/exacopy-platform/src/linux/sync_profile_store/genesis_output/intent.rs)

A refusal before rename is `PreSubmission`, including a known occupied
name at initial admission. A definite kernel no-replace conflict is
`KernelExists`. Other submitted errors return `SubmittedUnknown`.
A successful rename with an unconfirmed final observation or barrier
returns `KernelSuccessLaterUncertain`. All preserve incumbent and
available private evidence and withhold acknowledgment. No outcome
authorizes unlink, retry or recovery adoption.
[Typed outcomes](../../crates/platform/exacopy-platform/src/linux/sync_profile_store/genesis_output/error.rs)

## Verification scope

The retained portable sample passed 18 Plan, Manifest, assembler and
historical-reader tests. The integrated host checks passed formatting,
strict all-feature workspace Clippy, 1,056 Nextest tests with 31 skipped,
workspace doctests and the engineering policy check. The reviewed producer
source also passed Linux x86-64 strict cross-Clippy. The exact logs and
earlier failed candidates remain under
`target/agent-evidence/root-genesis-public-intent/` and
`target/agent-evidence/parallel-roadmap/sync_genesis_producer/`.

The feature-qualified ignored fixture
`production_managed_genesis_publishes_and_previews_exact_p063_history`
compiles the real producer, existing Init and authenticated preview.
It includes an optional bounded capture for independent artifact
verification. An offline capture can check canonical output bytes. It
does not demonstrate that a separate observer held the native inodes
through the run. Native Linux execution of this writer and separate
process-crash and power-loss qualification remain pending.
[Native fixture source](../../apps/exacopy-cli/tests/linux_managed_sync_genesis_production.rs)
