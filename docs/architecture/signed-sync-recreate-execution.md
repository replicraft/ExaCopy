# Executing one foreground managed recreate

The proposed first execution profile covers one manually approved create-new
action for an owner-managed Linux subject with a CommonPresent baseline and
one absent peer. It composes the existing checked local copy executor with
an independent managed activation and an owner-private action journal.
This document records the selected design direction. The execution frontend,
effect capabilities and action records are pending. The bounded model below
records a separate design prerequisite.
Exact wire and replay contracts remain subject to separate selection.

The [signed recreate export](signed-sync-recreate-export.md) remains a review
artifact. Action page kind 257 (`0x0101`) is permanently review-only. Its null
grant, child approval requirement and Linux v1 receipt selector retain their
existing meanings. A separate activation references the exact reviewed
parent, action and ordinary child. It authorizes a distinct managed
execution request without changing the review, child Plan or existing
receipt encodings.

## Foreground authority

The operator independently selects an existing owner-private host selection
record and confirms its expected digest. The operator also confirms the
digest of a separate, purpose-signed activation for that exact scope.
The host selection supplies the trusted approval role, exact managed
profile, ordered roots and raw subject, expected ordinary child and its
qualification enrollment. The activation binds the host selection and the
exact approved parent action, child, limits and expiry. The owner authorship,
activation approver and qualification attestor have distinct key roles.
The reviewed bundle does not select these trust inputs. This is manual
foreground admission. Its authority premise is the operator's independently
retained selections. The existing bounded protected snapshot supplies
current-UID file custody for the selected bytes. [Protected snapshot](../../crates/platform/exacopy-platform/src/protected_snapshot.rs) · [Init selection precedent](../../apps/exacopy-cli/src/assembly/linux/managed_sync/acknowledgement.rs)

After matching the activation to the host selection and current held
evidence, the application constructs a `LocalApplyHostSelection`. It
consumes `LocalApplyIssuer::issue` with the approved ordinary child digest
and exact original held roots. The child grant remains a finite, one-use
invocation capability. A distinct live managed grant gates the same
bounded effects against the activation, ledger and original held scope.
The app confirms current revocation and the required monotonic and UTC
deadlines under both guards. Replacing a policy file does not revoke an
already materialized foreground selection. [Child issuer](../../apps/exacopy-cli/src/assembly/linux/public_stage/grant.rs) · [Checked local apply](checked-local-public-apply.md)

The production host must independently select the existing qualification
attestor, record, build and root scope. The current checked child SDK
requires a matching Arm64 Ubuntu ext4 profile. Qualification must cover
the actual combined managed executor and child on its selected host.
The managed export evidence covers review and its held source observations.
[Qualification record and scope](local-public-apply-qualification.md)

## Exclusive root and ledger custody

Acquire the managed common-parent exclusive lease before execution
observations. Keep the same parent and ordered roots held while
authenticating the selected predecessor, resolving the exact subject,
measuring the source and confirming target absence. The current
`acquire_managed_history_lease` is a shared observation capability with
unchanged directory stamps. Add an execution-specific capability that
lends the original read-only source root and a mutation-gated destination
root to the checked child. Carry those borrows through qualification,
bootstrap, publication and terminal observation. The managed capability
admits the exact scoped destination transitions for the child's private
job creation and no-replace target publication. It rechecks the unaffected
scope and refuses unexplained changes or rebinding. The common-parent
lease depends on cooperation from writers using aliases or retained
handles. The child job has a distinct exclusive lease. [Current managed lease](../../crates/platform/exacopy-platform/src/linux/sync_preview/managed.rs) · [Read root](../../crates/platform/exacopy-platform/src/linux/source.rs) · [Destination root](../../crates/platform/exacopy-platform/src/linux/stage/directory.rs)

Keep one separately selected, pre-existing owner-private action ledger
under its original exclusive lease, outside both live roots and the child
job. Pin its directory, named segment, native identity and initial
accepted boundary. A named-custody adapter must supply `DurableJournal`
with bounded append, barrier, reread and EOF observations. Replacement
slots, uncertain prefixes and prior unresolved intent refuse fresh
admission. The exact layout, prepared anchor and lock order remain
implementation contract decisions. [Durable journal](../../crates/storage/exacopy-journal/src/durable.rs)

## Prior intent and held closeout

Select the logical child job, entry, run, stage and private Plan identities
before child bootstrap. These are logical commitments. The physical job
and stage identities will be established later by the actual child.
Append kind 27 for the exact activation, live workflow scope, current
predecessor, reviewed action, expected source and target observations,
and selected child Plan and attempt. Synchronize the frame and
independently confirm the exact accepted successor at physical EOF under
the same ledger lease. An append submission alone supplies no child authority. Unknown submission,
barrier or reread leaves that invocation in reconciliation before the
child can act. Pass a typed, held confirmation to
the real `ApplyStep::Create(ApplyRole::Job)` gate before private job
creation. A reported head alone cannot open this gate. [Frame allocations](../../crates/storage/exacopy-journal/src/frame/kind.rs) · [Native child creation](../../crates/platform/exacopy-platform/src/linux/job/apply.rs)

The checked child keeps its own exact intent, exclusive no-replace
publication, barriers and v2 terminal validation. At the final rename
gate, recheck the original managed scope, current predecessor and held
kind-27 confirmation under the live guards. Extend the child success
boundary to lend the exact v2 receipt and terminal journal evidence
while the original child owner, job, journal and receipt are still held.
The current `CheckedApply` returns values after completion. It is
insufficient as the proposed custody capability. Under the original
managed and ledger guards, append kind 28 to the same ledger. Bind the
actual child and verified v2 receipt to the exact accepted kind-27
predecessor. Independently confirm the new frame and physical EOF. Only
then report a committed managed action. [Current checked result](../../crates/engines/exacopy-transfer/src/linux/local_copy/public_apply/checked.rs) · [V2 commit verification](../../crates/engines/exacopy-transfer/src/linux/receipt/public_apply/commit.rs)

A missing or uncertain child or workflow closeout requires reconciliation.
Retain the exact established native publication status, including
acknowledged publication with incomplete workflow evidence. Existing
child settlement rules apply to an already submitted rename. Uncertainty
is terminal for this invocation and authorizes no second bootstrap or
rename.

## Open decisions before execution

- **Current predecessor.** Choose an authoritative current selection
  maintained independently of the proposed action and hold it under the
  execution scope. A valid immutable P-063 generation-one root and its
  Init acknowledgement authenticate historical selection. They cannot
  establish that the root remains current or that another enrollment
  never touched the scope. A fixed empty action slot supplies neither
  fact. Define how overlapping or stale selections are refused.
- **Durable one-use admission.** Select the durable spend rule and its
  failure boundary. A kind-27 submission can become uncertain and
  leave no accepted frame at the original EOF. A later pristine read
  of that file cannot tell an untouched slot from an indistinguishable
  submission that left no bytes. Sticky reconciliation in the original
  invocation supplies no restart-persistent spend marker. Either adopt
  separately durable spend evidence with a qualified failure contract,
  or limit the profile to explicitly qualified pristine admission and
  avoid promising permanent one-use across that ambiguity. Any later
  admission requires fresh independent confirmation and the selected
  native evidence for a pristine slot. An accepted earlier intent
  continues to block fresh admission.
- **Managed child provenance after restart.** Choose a protected managed-only
  child namespace, independently reserved and enforced at actual child
  admission, or an authenticated reciprocal parent-intent commitment
  in a distinct child binding. This choice blocks execution adoption.
  A fixed private ledger and a typed live callback establish an ordered
  in-process association. After restart, matching Plan IDs, receipt
  contents and separate chain positions cannot prove that an ordinary
  child arose from the managed intent. An unresolved cut stays
  reconciliation-only.
- **Wire, scope and issuer.** Select exact canonical activation and host
  selection schemas, identifiers, version and required-feature handling.
  Specify kind-27/28 payloads, signed and hashed commitments, bounds and
  replay grammar for the already reserved journal discriminants. Select
  a real independent activation producer and the consuming foreground
  entry point. Define the prepared ledger anchor and revocation/lock
  ordering. Keep these decisions distinct from kind 257's immutable
  review contract.

The first profile requires both a source correspondence argument and
actual native qualification. Test the missing or unconfirmed prior
intent at real child bootstrap, competing or stale authority, root and
ledger substitution, late incumbent, uncertain settlement and exact
held receipt binding. A successful managed action supplies evidence for
later [successor assessment](sync-successor-assessment.md). That
assessment still requires fresh complete reads of both roots after
receipt validation. Restart reconciliation and P-028 baseline
publication remain separate. This profile contains no baseline
persistence or pointer update.

## Model prerequisite

[P-085](../../crates/foundation/exacopy-model/verification/tla/MANAGED_ACTION.md)
checks the proposed ordering in a finite model with two claimants, one
activation and one restart. A trusted durable issuer atomically spends the
activation independently of the ledger. That issuer and truthful held
observations are model assumptions; the native issuer remains unimplemented.
An apparently pristine ledger cannot replace that authority after restart.

The gate checks child creation after confirmed intent and association of the
same child's verified terminal projection. Its results apply to the exact
model, configurations and tool inputs in the evidence record. Complete paired
successor observations, preservation of the old baseline and publication of a
successor, Rust correspondence and native restart reconciliation remain
separate requirements.
