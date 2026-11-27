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
strict all-feature workspace Clippy, 1,058 Nextest tests with 31 skipped,
workspace doctests and the engineering policy check. The reviewed producer
source also passed Linux x86-64 strict cross-Clippy. The exact logs and
earlier failed candidates remain under
`target/agent-evidence/root-genesis-public-intent/` and
`target/agent-evidence/parallel-roadmap/sync_genesis_producer/`.

### First hosted native execution

The hosted run at `993668d` executed on whole ext4 with Linux
`7.0.0-1014-aws`, UID/GID 1001 and full identity maps. It separately ran
four ordinary Rust intent-codec tests against the held platform library
test image. They checked the v1 layout and byte order, malformed extent
and inventory, swapped same-kind members and foreign approval, and the
independent exact-selection oracle. All four passed. The 12 normal-list,
ignored-list and execution processes drained.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45940037039)

The separate feature-qualified SDK test
`production_managed_genesis_publishes_and_previews_exact_p063_history`
passed its eight controls. They cover content or metadata mismatch, absence
or aliasing, overlapping output, an occupied final name, same-operation
replay, and missing selected history. The positive path published exact
genesis, explicitly selected it through managed Init, and observed both
no change and a right-side copy candidate in read-only preview.

The runner matched the result frame to the held launch PID, ordered
anchors, actor, boot, mount and user namespaces, and ordinary and unique
mount IDs. The pinned independent oracle reproduced the four-member
signed closure and 364-byte intent with the fixture key. The canonical root
digest was `1e0fca22430315685274457f847a9cb26bc359fe52455dd654b8f8f139c84401`.
The frame SHA-256
was `8901b2283ee6582021703f54f44210d9094cfe73af330705d7b01963973638bc`. The held
platform and SDK ELF SHA-256 values were
`df2b9eeba48d02f5ed4c3da059e5e69820799b0770f86c2b548e33d59fec73a4` and
`f1c9ee9c0d1b3a3c338ccdfa09851a2003ca17f1698af91d9f4b35f599d4e340`, respectively.
The result JSON SHA-256 was
`bafc0efc0837b610d17faed155620ed81856598820b1b758e9ea58ee4dc022a3`. Source,
lockfile and fixture checks matched this revision, and the SDK's three
process groups drained. The wrapper confirmed fixture and build removal.
The retained capture permits independent artifact comparison. The inner
file identities remain observations made by the held SDK fixture.
[Native report](https://github.com/replicraft/ExaCopy/actions/runs/45940037039/artifacts/15172252732) ·
[Native fixture source](../../apps/exacopy-cli/tests/linux_managed_sync_genesis_production.rs)

This execution covers the synthetic owner-managed SDK producer and
read-only preview under the recorded cooperative ext4 profile. CLI
activation, process-crash and power-loss qualification remain open. The
mount was `/dev/mapper/cow-root` with `journal_async_commit`, `nobarrier`,
`commit=30` and `data=writeback`.
[Hosted lane](../../.github/workflows/linux-managed-sync-genesis-production-qualification.yml) ·
[Independent oracle](../../apps/exacopy-cli/verification/managed_sync_genesis_production/oracle.py)
