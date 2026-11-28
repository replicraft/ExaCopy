# Staging approved public content

`exacopy-transfer::linux::stage_public_apply` stages one admitted public
create-new Plan through the existing read/create/write capabilities. It
matches public and private root aliases, raw basenames, native source
identity, private entry/epoch, approved length and digest, metadata policy,
buffer budget and admission/expiry interval before bootstrap.

The coordinator persists and synchronizes the [public-apply owner](public-apply-owner.md)
before the first JobPrepared record. Its complete signed digest binds that
journal. Legacy owner and recovery readers refuse this form. The private
Plan and its digest keep their existing representation.

Staging captures the actual copied source stream's length and BLAKE3 digest
and the independent stage read-back length and digest. All four must match
the authenticated expectations before durable seal evidence is appended.
A source and stage that match each other but differ from the approved
content are refused. Metadata remains governed by the existing narrow
Linux baseline policy. Created private artifacts remain for reconciliation
on failure.

The only successful result is the signed owner's digest. No publication
intent, rename, stage handle or publication permission is returned. This
is not a public apply command. Fresh expiry and native process-crash
eligibility must gate eventual publication; public-aware inspection,
resume and retry are separate work. No native durability claim follows
from requesting process-crash durability in the Plan.

The separate `stage_public_apply_and_propose_intent` entry point prepares a
historical v2 intent proposal. Its private continuation holds the original
job, stage directory, verified reader and model session, copy binding, and
durable journal together until the proposal returns. It checks the source,
target absence, caller's current observation and original expiry interval.
It then rereads the original journal descriptor through the exact synced
metadata frame and physical EOF before constructing the proposal.

The application SDK's default-off `stage_qualified_public_apply` adds an
independently selected protected attestation before this proposer. Its
[local qualification contract](local-public-apply-qualification.md) binds
the exact action, owner, measured running image, held roots, native
environment and finite validity interval. It checks current observations
at both prebootstrap and sealed-stage boundaries. This SDK has no default
enrollment or CLI route. Its returned proposal retains the same historical
meaning. Operational enrollment and runtime qualification of publication remain open.

The separate [checked SDK continuation](checked-local-public-apply.md) now has
a source implementation retaining the original stage and appender through
publication and receipt commitment under a one-use local grant. Its runtime
verification and operational enrollment remain open. This does not change
the historical proposer's return value or grant it effect authority.

This readback checks the complete envelope chain under the existing 64 MiB
segment bound, with one extra byte for EOF detection. It restores and checks
the append cursor without writing or issuing another barrier. A stale
expected head refuses without I/O and leaves the writer usable. Once the
expected head matches, an uncertain extent, cursor, read or chain retires
the writer and retains its bytes. The proposal returns a typed seal-readback
refusal rather than producing evidence from an uncertain journal.

The check establishes envelope consistency on the original descriptor.
Fresh Linux segments additionally retain the original destination and journal
directory descriptors alongside the existing locked job descriptor, selected
raw job name, creation identities and mount. Their extent checks verify the
original job, journal and segment names and compare the named segment with
the original file. Parent checks bracket those observations. Existing durable
append and both sides of readback use these extent checks. A same-byte
replacement at any of those names causes refusal rather than adoption.

This adds two directory descriptors per fresh writer and bounded native
lookups to ordinary, public-apply and initial remote journals. It retains
one segment cursor. Recovered writers and direct descriptor barriers retain
their existing behavior. These are observations under cooperative custody,
not exclusion of actors with retained mutation rights or a namespace snapshot.
Owner authentication, semantic replay, live effect authority and native
durability remain separate obligations. Neither the proposal nor the private
continuation appends an intent, grants publication authority or performs a
rename. Publication still needs fresh, serialized authorization and native
checks, followed by independent intent, receipt and namespace confirmation.

The owned ext4 fixture includes a late readback fault control. During its
final observation it changes one early magic byte in its own private
journal while leaving the terminal metadata bytes intact. The actual
proposer must return the exact seal-readback corruption refusal, preserve
the faulted journal and original source and stage bytes and identities,
and leave the public target absent. This deliberate fixture fault tests
refusal after the cooperation premise is violated. It does not qualify
outside actors, publication or crash durability. Its execution requires
the exact integrated revision's native fixture evidence.

The ordinary Linux bootstrap tests exercise the real fresh writer after its
bootstrap scopes close. They replace each selected name with a separate
inode holding identical bytes and require append and confirmation to refuse
and retire the writer while retaining both objects. A second control replaces
the segment during the actual read, so only the post-read check can detect
the changed name. These controls require their own integrated test evidence.

`PublicApplyReceipt::validate_commit` checks a canonical v2 receipt and the
exact journal suffix after an independently accepted kind-4 seal. It requires
consecutive kinds 5, 6, 7, 8, 9 and 18, complete predecessor links, matching
selected owner and public association, stream and metadata facts, qualification
claims, original expiry, and distinct source, published file and directory
roles. Kind 18 must commit the domain digest of the supplied decoded receipt.
The legacy and stage-only readers retain their existing refusal behavior.

The suffix has a 4 KiB limit plus one EOF probe byte. All framed reads and the
terminal probe share a 16-interruption allowance; exhaustion preserves the
cause in a terminal I/O error. The generic frame parser may allocate up to
1 MiB for a malformed declared payload. Each underlying read must return.
Callers authenticate the owner and accepted prefix, select the expected facts
independently, and establish native receipt identity, complete artifact EOF,
journal custody and current authority. This method checks byte consistency
and grants no publication or recovery permission.

Eight frozen journal/receipt pairs include a valid chain and independently
relinked near misses. Controls cover an impossible source/destination-directory
alias, independent selection, original expiry, terminal bytes, truncation,
corruption and interruption exhaustion in both framing and EOF. These are
registered source controls whose execution requires integrated test evidence.

The exact Linux-target transfer tests and implementation passed strict
cross Clippy. A separately labeled macOS portable capability fixture ran
85 transfer tests. Five guard-removal controls failed their expected
assertions, covering each approved stream comparison and private entry
binding. This portable fixture temporarily exposes Linux coordinators for
testing and does not execute the native Linux adapter. Raw results and
exact source hashes remain in
`/private/tmp/exacopy-public-apply-stage.7f8wBxAQ/review.md`.

The later hosted whole-ext4 fixture at `09b96f5` exercised the real
private staging coordinator and independently reopened its result under
a read lease. Public apply, commit and interruption qualification remain
open. [Native staging and inspection result](public-stage-inspection.md#native-stage-and-inspection-evidence)
