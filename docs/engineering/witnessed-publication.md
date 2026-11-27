# Witnessed no-clobber publication on Linux

The selector-2 Linux components preserve a protected same-inode witness
through one live no-replace rename. Model binding `eba6c7d` and platform
component `3f61996` bring this path through a typed native observation.
Private application composition now carries this same model and native holder
through submission. Kind-8 closeout, receipt publication, complete native
application qualification and CLI dispatch remain open. [Witnessed closeout design](../architecture/remote-witnessed-closeout.md) ·
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
not issue post-rename file or directory barriers, append kind 8, produce
a receipt or turn a historical kind 7 into a new live rename. The model's
recovery path can admit an independently held observation of an already
published object under its stricter recovery conditions. The implemented
native submission component provides no recovery mutation or closeout
dispatcher. [Native outcome checks](../../crates/platform/exacopy-platform/src/linux/recovery/writer/prefix/suffix/witness/publication.rs)

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
observations, post-rename barriers, kind 8 and later journal and receipt
phases, and the full closed native campaign. Its coverage mask requires
all 24 case families on the exact selected native profile. This tmpfs
component run supplies no production mount, process-crash or power-loss
qualification. [Operation-2 evidence contract](../architecture/remote-witnessed-closeout.md#exact-v2-qualification-extension)
