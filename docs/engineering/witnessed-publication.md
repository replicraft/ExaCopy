# Witnessed no-clobber publication on Linux

The selector-2 Linux components preserve a protected same-inode witness
through one live no-replace rename. Model binding `eba6c7d` and platform
component `3f61996` bring this path through a typed native observation.
Private application composition now carries this same model and native holder
through submission. The held outcome can record kind 8 once. The positive
holder can request freshly authorized durability barriers and record kind 9.
Private live receipt composition implements kinds 42 and 18 on that same
held path. Complete native application qualification and CLI dispatch remain
open. [Witnessed closeout design](../architecture/remote-witnessed-closeout.md) ·
[Remote transfer release readiness](remote-transfer-readiness.md)

## From closed capture to one rename

The original live pass holds its recovery lease, original stage,
destination, protected job directory, journal and closeout reservation.
Before kind 41, the pass must finish exact EOF on the fresh authenticated
source, close and join the source and transport, close and join the local
data writer, and establish the required file barrier and extent. These are
live observations from the original pass. Persisted history supplies no
replacement for them.

| Frame | Evidence required |
| --- | --- |
| 41, witness intent | Verify the current base grant, independently approved witness retention consent, exact scope and coverage predecessor. Sign, append, sync and independently reread kind 41 before linking. Create the derived protected name using an exclusive descriptor-bound link to the originally held stage. |
| 4, seal | Observe that the private stage and witness are the same held inode and are its only two links. Confirm the inode and protected witness directory barriers and recheck custody. |
| 5, verification | Independently read the entire witnessed stage from byte zero through exact EOF and verify the source-stream digest, expected extent and held bindings. |
| 6, metadata | Verify the selected metadata policy and required stage barrier, while retaining the exact witnessed inode and names. |
| 7, publication intent | Validate the immediately preceding seal, verification and metadata chain, current qualification and grant, separate witness approval commitment, exact target and verified absence. Append, sync and independently confirm the live intent. |

`SealedProtectedWitness::publish_witnessed` consumes the original live
holder. It requires the intent-synced phase and an application callback to
replay the complete held journal at the independently selected kind-7 head.
It then rechecks the native scope.
It completes fallible native preflight before seeking a separate logical
`RenameSubmission` and live application guard. The adapter checks the
model head, stage device and inode and unique mount ID, and the original
grant, operation-2 qualification and approval digests. With these checks
complete, the live guard covers exactly one descriptor-relative Linux
`RENAME_NOREPLACE` submission. The consumed holder supplies no repeat
submission or restart entry. [Prepublication holder](../../crates/platform/exacopy-platform/src/linux/recovery/writer/witness_reservation/continuation/witness/prepublication.rs) ·
[Submission gate](../../crates/platform/exacopy-platform/src/linux/recovery/writer/witness_reservation/continuation/witness/publication.rs)

## Application authority at the gate

The application must hold one live model state for the exact serialized
lease and continued lineage. It selects and authenticates the owner, job,
entry and signed scope, the original protected job and destination
directories, the selected raw names, and the current boot, mount and namespace
binding. It verifies the original authenticated journal from byte zero and
confirms the exact phase chain, head and current held stage and witness
observations, including writer quiescence and target absence. The model
depends on these observations supplied by the caller.

At effect admission the application must match the model lease, subject and
namespace commitments to the actual held request. It independently selects
the exact current operation-2 qualification for the measured build, native
scope and route, verifies the same base grant and the separate explicit
witness retention approval, and binds the approval's exact exclusive
deadline. A trusted current clock must confirm `now < deadline`. The
callback must be synchronous, with no I/O, await, credential change or
lease reentry. An archive, prior journal signature, default approval or
renewal substitution supplies no current authority. [Model binding and
decisions](../../crates/foundation/exacopy-model/src/witnessed_publication.rs) ·
[Live state transitions](../../crates/foundation/exacopy-model/src/witnessed_publication/state.rs)

The private application compositor derives the model subject and namespace
from the original authenticated intent and revalidated native scope. Its
per-pass lease marker supplies no authority. The same state survives the
link and confirmed frames; the seal uses the clock sample from its actual
guarded append. Before rename it checks the original scope and exact kind-7
replay, then obtains current consent under the existing guard. The returned
private handle retains both the consumed model state and native outcome.
The two application binding controls are compiled for Linux; their full
production native execution remains unqualified. [Application compositor](../../apps/exacopy-cli/src/assembly/linux/remote_continued/witness/publication.rs)

## Observation after submission

The adapter drops the submission guard when the syscall returns. Subsequent
observations are read-only and retain the original custody during checks.
They examine the exact private, protected and public names under held
directories, verifying inode identity and link count, relevant stage
metadata and extent, logical EOF and stable named bindings.

- `Published` requires native success, verified absence of the old private
  name, and the public target and protected witness held as the same original
  two-link inode.
- `Conflict` requires the definite native no-replace conflict, the intact
  two-link private stage and witness, and a separately held distinct regular
  incumbent.
- `Reconcile` retains the native return and available observations if neither
  positive case can be confirmed, including a nonregular incumbent or
  uncertain name or scope.

The component can retain the fact of the submitted call when authorization
expires after the gate. Its result supplies no subsequent effect. It does
not issue post-rename file or directory barriers, produce a receipt or turn a
historical kind 7 into a new live rename. The model's
recovery path can admit an independently held observation of an already
published object under its stricter recovery conditions. The implemented
native submission component provides no recovery mutation or closeout
dispatcher. [Native outcome checks](../../crates/platform/exacopy-platform/src/linux/recovery/writer/prefix/suffix/witness/publication.rs)

## Recording the actual submitted outcome

The one-shot outcome capability consumes the original model submission and
confirms the exact accepted kind-7 journal before constructing kind 8.
The application records only the actual native fact and checked namespace
observation. A raw kernel conflict with uncertain names remains uncertainty;
it cannot become a confirmed incumbent conflict. The narrow existing-outcome
rule permits this record after consent expiry and supplies no new mutation
authority. The same held appender confirms the proposed replay, writes and
synchronizes the bounded frame, then independently rereads and confirms it.
A possibly submitted failure retires the appender while retaining the native
outcome separately. Clean recorded uncertainty is terminal reconciliation.
No journal error erases the already observed native call.

The kind-8 outcome capability exposes neither subsequent barriers nor a new
rename. Those effects require separately current admission of the exact original
grant and matching approval, with no renewal substitution.
[Native one-shot recording](../../crates/platform/exacopy-platform/src/linux/recovery/writer/witness_reservation/continuation/witness/publication/record.rs) ·
[Application outcome binding](../../apps/exacopy-cli/src/assembly/linux/remote_continued/witness/publication/observation.rs)

## Freshly admitted durability and kind 9

A positive same-held publication with an independently confirmed kind 8 can
attempt the four ordered barriers once: the published file, original staging
directory, destination parent and protected job root. Native probes recheck the
original two-link witness/target, absent private name, exact inode metadata and
EOF, protected directories and current qualified mount. The application checks
the original full scope and obtains a fresh guard for each barrier. A separate
guard covers the proposed kind-9 append after all four barriers succeed.
The canonical producer accepts only the exact positive live kind-8 predecessor;
a historical or recovered value supplies no live capability.

The appender synchronizes kind 9, independently rereads it, and confirms the
complete semantic replay before exposing its head. Preflight refusal and an
actual failed sync are distinct. A failed effect or uncertain append stops the
appender while preserving the observed rename and kind-8 result. This capability
creates no receipt and allows no repeat rename. Confirmed barriers are evidence
under the selected native profile, not power-loss qualification.
[Native barrier capability](../../crates/platform/exacopy-platform/src/linux/recovery/writer/witness_reservation/continuation/witness/publication/durability.rs) ·
[Application checks](../../apps/exacopy-cli/src/assembly/linux/remote_continued/witness/publication/durability.rs)

The [hosted execution at `b82e95d`](https://github.com/replicraft/ExaCopy/actions/runs/45928809419)
passed the [ext4 component profile](../../crates/platform/exacopy-platform/verification/witnessed_components_ext4/README.md)'s
six exact native selectors. The cases covered the exclusive witness link,
preservation on occupied witness or refused barrier, native no-replace
rename and both incumbent classes, native reservation with unchanged
anonymous EOF, one-shot allocation latching, and exact reserved journal
append and reread. The supervised inventory confirmed each ignored selector
and one executed pass per case, drained all 18 process groups for listing
and execution, and verified owned fixture/build removal. All 13 input
digests matched the pushed source. The run used unprivileged UID 1001 and
whole ext4 on Linux `7.0.0-1020-azure`, with `nobarrier` and
`data=writeback`. The held ELF SHA-256 was
`2abd77125e81f4a55d448dc5a7fd8b7fe8886fcc18c4aa789ba607b97fc75e46`.
The result JSON SHA-256 was
`1d80567f399c8b8fde7be43b3bf7a7e2b8714026c2105646831b1c5edc855a75`.
Raw evidence for both hosted fixtures is retained in
`target/agent-evidence/hosted-b82e95d/`.

The later hosted execution at `bb6ebba` passed all seven exact component
selectors as unprivileged UID 1001 on whole ext4, Linux `7.0.0-1018-aws`.
The seventh selector confirmed sealing the original anonymous receipt
inode, linking it with `AT_EMPTY_PATH` through a separately reopened
read-only descriptor after the writer closed, and promoting the original
inode without replacing an incumbent. The evidence confirms all 21
listing and execution process drains and removal of the owned fixture
and build directories. All 14 input hashes match the exact Git revision.
The result JSON SHA-256 was
`7f1588330c759c4eddb3863174b8eb50a2a8f872fe6c3c9c9084408850634d3f`.
Raw evidence is retained under `target/agent-evidence/hosted-bb6ebba/`.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45930537061) ·
[Native component report](https://github.com/replicraft/ExaCopy/actions/runs/45930537061/artifacts/15168666404)

Both hosted runs used component-level effect callbacks and literal fixture
bytes. Authenticated application kind-8/9 recording, the kind-42/18 receipt
campaign, operational OP2 qualification, process-crash and power-loss
qualification require separate execution evidence.

## Live receipt closeout

After confirmed kind 9, private receipt composition selects the canonical
seven-phase artifact from the original held journal and checks the remaining
byte and sequence capacity. It writes the bounded receipt into the original
anonymous reservation, syncs and independently rereads it, and closes the
writer. It links the exact sealed inode at the protected pending name,
confirms sole custody and final-name absence, and completes the pending file
and job-directory barriers before committing and rereading kind 42. Kind 42
binds the pending inode and canonical bytes.

After confirming the actual kind-42 predecessor, the holder submits one
same-directory no-replace promotion, independently confirms final identity
and pending absence, and performs the final file and job-directory barriers.
It then appends and independently confirms kind 18. Each write, barrier,
link, promotion and journal append requires fresh admission of the original
grant and matching witness consent. A failure preserves the observed
publication, any known receipt namespace result and the last accepted
journal boundary. The path has no live retry after a spent phase and no
receipt reconstruction from a digest. Receipt restart and public receipt
dispatch remain open.
[Native receipt holder](../../crates/platform/exacopy-platform/src/linux/recovery/writer/witness_reservation/continuation/witness/publication/receipt.rs) ·
[Application receipt binding](../../apps/exacopy-cli/src/assembly/linux/remote_continued/witness/publication/receipt.rs)

## Read-only terminal inspection

Private application composition can inspect a clean terminal kind 18 under
one shared recovery lease. It independently selects the owner, signed scope
and archived qualification before opening the job. It authenticates the
held owner and journal from byte zero and requires the accepted terminal
boundary to equal the actual journal extent.

The native view holds the original stage directory, public target, witness
and final receipt together. It requires the original private stage name and
pending receipt name to be absent, the target and witness to name the exact
two-link inode, and the final receipt to have its recorded single-link
identity. Application read-back checks the full public BLAKE3 digest and
exact canonical receipt bytes. It rechecks namespace, metadata, EOF and the
selected native substrate before reporting a point-in-time association.
The recorded live or recovered publication outcome remains unchanged.

The inspector opens no mutation aperture and supplies no future authority.
Private archive controls and Linux ARM64 compilation cover the implemented
source. The ordinary Ubuntu 24.04 native job at `09b96f5` passed both
platform component tests in its 1,066-test run.
[Ubuntu native job](https://github.com/replicraft/ExaCopy/actions/runs/45932645166/job/140288550762)

- `terminal_inventory_pins_exact_records_and_refuses_late_pending_name`
  checked the read lease's writer exclusion and exact held owner, journal,
  public target and receipt, then refused a late pending name and preserved
  its bytes.
- `terminal_inventory_refuses_changed_journal_and_foreign_witness_inode`
  refused a foreign witness with matching bytes and a replaced journal
  segment with the original bytes.

These ordinary native component tests used fixture records. Complete
authenticated OP2 application restart qualification and CLI dispatch remain
open.
[Native terminal view](../../crates/platform/exacopy-platform/src/linux/recovery/terminal.rs) ·
[Application inspection](../../apps/exacopy-cli/src/assembly/linux/remote_journal/witnessed_inspection.rs)

## Executed evidence and remaining qualification

The retained candidate ran three platform tests as UID and GID 1000 with
empty capability sets on ARM64 LinuxKit `6.12.76-linuxkit`, using disposable
tmpfs. Two exercised the native descriptor link and preservation on an
occupied witness slot or later barrier refusal. The new syscall test observed
successful publication, preservation of a late regular incumbent as
`Conflict`, and preservation of a late directory incumbent as `Reconcile`.
The test entered below the full live kind-7 and application gate. The
original lint failure and the initial filter attempt that selected zero
tests remain in the evidence directory. The final platform cross-Clippy
and native link succeeded.

Seven host model tests passed. The P-066 TLC model generated 74,808 states,
exhausted 12,128 distinct states and left zero queued. Four deliberate
negative controls detected inode reuse despite the protected witness,
recovery from the witness alone, recovery using stale target evidence, and
a repeated rename after restart. P-066 assumes qualified continuous custody
of the witness and independently validated simultaneous observations.
It gives bounded model evidence under those assumptions.
[Model tests](../../crates/foundation/exacopy-model/tests/witnessed_publication.rs) ·
[P-066 model and scope](../../crates/foundation/exacopy-model/verification/obligations.toml)

The retained local records are under
`target/agent-evidence/witnessed-native-publication/`, including the exact
native executable digest, test logs, TLC traces and confirmed cleanup.
Operation-2 deployment qualification still requires the complete admitted
application path, retained approval and expiry controls, restart
observations, actual kind-8 recording, post-rename barriers and later journal
and receipt phases, and the full closed native campaign. Its coverage mask requires
all 24 case families on the exact selected native profile. Both the tmpfs
and hosted ext4 component observations leave combined lifecycle,
process-crash and power-loss qualification open. [Operation-2 evidence contract](../architecture/remote-witnessed-closeout.md#exact-v2-qualification-extension)
