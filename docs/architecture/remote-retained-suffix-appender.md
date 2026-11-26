# Linux retained-suffix appender and closeout contract

Scope covers R-253/A-253, R-255, and the applicable requirements from the
connection recovery contract. This is a design proposal. The current
kind-40/continued-checkpoint scanner is read-only. Existing V1 copy,
remote fresh-attempt resume, and startup reconciliation keep their own
entry points and semantics. No live continuation is enabled by this work.

## Capability ownership and lifetime

The Linux platform owns the descriptor, checked namespace, file barrier,
positioned suffix writes and native close. The journal owns canonical bytes,
first-segment limits, exact synced/read-back acknowledgement and archived
replay classification. The transfer engine owns fresh prefix proof, byte
measurements and model progression. The application composes one exact
job, source, stage, qualified strategy and current serialized grant.

- A single foreground coordinator owns the live source and its authenticated
  route. The fresh SFTP pass uses the exact signed rooted path, pinned
  authenticated host/account and admitted direct or embedded route.
  Hold the physical source view and its strictly newer epoch across prefix
  comparison, kind 40 and all remote suffix reads. No implicit reconnect
  may serve a pending read or substitute a different source epoch.
- Keep the existing protected read lease during connection establishment
  on explicit pre-intent resume. Upgrade through the existing release,
  reacquire-exclusive and independent full replay handoff. Refuse before
  retained data effects if a competing writer/intent won or a previously
  selected binding changed. A previous process's clean declared prefix is
  insufficient to prove present native identity.
- One exact `RecoveryWriteLease` spans held owner/journal/target/stage
  checks, comparison, barrier, journal write/readback, suffix capture and
  publication/reconciliation. Revalidate its owner and segment file
  identities, actual first-segment EOF, root/parent, private directories,
  exact allocated basename, nonce and held stage. Require target absence
  before continued mutation. The native lease excludes cooperating writers;
  the protected workspace contract excludes uncoordinated writable aliases.
- `RetainedPrefixRead` already holds the per-lease stage-access guard.
  Consume it into an opaque `SyncedRetainedPrefix<'lease>` without dropping
  that guard or reopening by a pathname. The new holder keeps the original
  pinned read-only file and an exact checked private `StageDirectory`.
  Its `sync_adopted` transition runs full file sync on the original held
  read-only descriptor, using the same Linux path as existing retained
  preparation. Check real identity, native attributes, stage extent and
  unchanged stamps against the held and named observations on both sides.
  Preserve the stage on every failure. This holder exposes no writer or
  publication method merely from a successful barrier.
- The app rechecks fresh prefix evidence against current grant, exact
  stage and old journal head and records kind 40 as described below. Only
  its private live acknowledgement can supply the authorization contract
  for the holder's checked `open_suffix_writer` transition. Archive replay
  and payload bytes never supply that acknowledgement. Platform borrows
  the holder's owned `StageDirectory` for the writing/closed capabilities.
  Keep these variables in one lexical stack in the foreground
  `Runtime::block_on`. No self-referential struct, raw fd, shared data
  writer, unchecked writer reopen or platform-to-journal dependency.
- The restricted native writer wraps a private checked native writer
  implementation. Its only positive data method writes the next bytes in
  the current admitted range. It exposes no resize, rewind, generic random
  write, hole, mutation metadata, unlink, replacement, or publication API.
  Do not reuse the public `RecoveryStageDirectory::open_writer` surface,
  which returns `WriteStage` with arbitrary offset and length operations.
  Reuse its internal checked inode reopen and exact native observation logic.
  Reopen without create, truncate or general append flags, then bind the
  actual held name/identity/size to the synchronized holder and active pass.
  Exact EOF and identity are checked before and after writable open.
- After the first suffix write, the original inventory's data stamps
  intentionally become stale. Keep its pinned file identity and lifetime.
  Validate state against the restricted writer, fresh held/named metadata,
  unchanged protected ancestry and current target status. Never mask a
  mismatch by rebaselining arbitrary content, and never reapply the old
  extent/stamp check to declare expected positive suffix growth failed.

The platform's exact typed phase interface is intentionally separate from
the app's journal types. A consuming native phase takes an app-owned sealed
submission gate following the existing publication fence trust pattern.
A naked digest, bool or model range is not enough. Tie the gate to this
one live held stage/lease, selection, qualified scope/grant, original pass,
new pass and confirmed kind-40 boundary. Derive model guard commitments
from independently observed native IDs and actual lease/authority binding,
using a per-admission distinct in-memory lease label. No persistent native
authority is encoded.

## Full prefix, closeout budget and write-ahead kind 40

Authenticate and replay the entire exact held segment before effects. The
first profile accepts only a clean original kind-2 preparation with
positive contiguous kind-3 checkpoint coverage. Independently authenticate
any earlier retirement under its selected V1 digest. Independently
authenticate V2 retained-append qualification, match actual measured binary,
route class and current native facts, and require the exact qualified record
digest for kind 40. Producing or reading a V2 signature is not native
eligibility. The signed owner still binds location, exact route, source,
target and metadata policy. Selection of verified reuse is explicit.

Run the existing `verify_retained_prefix` against the held source and
retained read capability. Compare all adopted bytes, including any allowed
bounded uncheckpointed tail; rehash each historical digest against exact
real bytes. Check the positive historical coverage, exact original prepared
and selection/head anchors, old and new extent limits and current source
attributes. Build the model's `Prior`, `PrefixProof`, and `Pass` only from
those checked objects. Its byte digest is fresh ordinary BLAKE3. Retain the
same borrowed source and its accumulated hasher through the next engine
step. Add crate-owned consumption of this proof that returns both; today's
public `into_source` intentionally drops the hash and cannot implement
this path. Failed comparison preserves both files and exposes no reusable
partial hash. Recheck local and remote observations around the phase
transition with the same source handle. Never unlock the stage to upgrade.

Before kind 40 even on a zero-tail pass, exclusively reserve the required
journal and receipt closeout capacity. The planner uses the checked active
boundary including byte offset and sequence. It knows the exact canonical
kind-40 width and each planned V2 checkpoint width. Width projections may
use a fixed-width digest placeholder for arithmetic only. It reserves the
entire planned checkpoint range schedule before kind 40, not merely the
next append. Choose positive ranges up to 64 MiB with at most 4,096 V2
ordinals, using bounded subwindows within each range. Use checked integer
arithmetic for source extent, sequence and exact worst-case canonical
lengths. Include a failure branch and enough bounded bytes and sequence
slots for the separately approved V2 closeout/reconciliation grammar at
every boundary. The 64 MiB first-segment cap is unchanged. Preserve the
reserve even when the final range has length zero or the checkpoint ordinal
budget is fully spent. A budget refusal preserves source, incumbent and
retained stage. Recompute the exact checkpoint-sized reservation for the
model at every range, and recheck the physical capacity retention.

Format or logical capacity is not a native allocation guarantee. Proposed
Linux implementation uses `FALLOC_FL_KEEP_SIZE` under the exact exclusive
segment descriptor, before constructing the typed durable appender (or as a
bounded lease-owned capability on it). Keep file type, identity, append
position, logical EOF and barriers checked before and after. The owning
format/planner supplies bounds; the native adapter never takes arbitrary
range inputs. Support and process-crash behavior must be demonstrated for
the qualified filesystem. An unexpected disk/quota/namespace/barrier
failure still leaves a retained reconciliation state. `statvfs` free space,
a format limit or an unbound file on the same device is not a reservation.

### Receipt reservation and independent segment readback

Do not create a named pending reservation while the file still ends
at the original V1 checkpoint. A legacy reader can see that clean
boundary without noticing the new name. The current kind-40 profile
also requires the actual V1 checkpoint as its exact immediate
predecessor. Inserting an incompatible marker alters that wire
contract and needs independently selected, versioned replay.

Prefer reviewing a lease-owned, initially unnamed native inode for
the receipt reservation. Linux `O_TMPFILE` can create an unnamed
inode on the filesystem of the exact held job directory. Use it
only under an admitted mount/profile with a separately checked link
method. Keep the inode, exact mode, ownership, mount, expected zero
link count and preallocated capacity held until canonical receipt
persistence. Logical EOF stays zero during reservation. The namespace
remains V1-compatible before kind 40 and no named object is adopted
or removed on restart. [Linux open(2)](https://man7.org/linux/man-pages/man2/open.2.html)

At the existing post-publication receipt boundary, exclusively create
the exact protected receipt directory under the live lease. Write,
full-sync and independently reread the exact canonical receipt on the
reserved descriptor. Then add only the final checked absent name by
exclusive descriptor-bound link in the same filesystem. Reobserve the
transition to one link and exact expected inode at that name, full
extent, digest and required metadata. Check receipt and job directory
barriers before kind 18. A failed or unclear link/barrier is
reconciliation. Do not retry the stage rename.

Ordinary unprivileged acquisition must not assume direct
`linkat(AT_EMPTY_PATH)` works. The Linux man page describes a
capability requirement and an alternative through procfs. Any procfs
link path must be a separately reviewed narrow native capability using
a checked held procfs directory and exact live descriptor; do not
weaken current mount-join/no-crossing rules, depend on a caller-supplied
proc path or expand privileges. A host that cannot support the reviewed
link path refuses before kind 40. A disposable static convention or
unbound reservation on the same device does not solve this. If the
unnamed strategy fails review or qualification, design a distinct
version-fenced named reservation rather than implementing the pending
name in the original draft. [Linux linkat(2)](https://man7.org/linux/man-pages/man2/link.2.html)

`FALLOC_FL_KEEP_SIZE` is scoped to positive allocated disk space beyond
the existing validated journal EOF. It can change native allocation
metadata. Retain the exact same held segment, mount, directory/filename
binding and exclusive access. After the call and required observation,
reread the entire bounded old prefix to prove its logical bytes, exact
verified chain head, accepted end and actual EOF unchanged. Match owner,
profile and exact semantic prefix again. Replacing the expected old
stamp without that replay cannot justify proceeding. This is capacity
evidence on supported filesystems and supplies no native durability
or journal confirmation for unwritten future records.
[Linux fallocate(2)](https://man7.org/linux/man-pages/man2/fallocate.2.html)

With actual reservations retained, request the native full prefix file
barrier on the original read-only held stage and confirm its exact observed
extent and unchanged native binding. Report `Continuation::prefix_barrier`
with the exact current head, bound source, selected basis and live guard.
Recheck target, lease, grant, qualification, first-segment identity and
old journal boundary before kind 40 append. Use the exact original
allocation and EntryPrepared, bootstrap, raw name, nonce, historical
checkpoint head/ordinal/end, old and new epochs, adopted end, exact scope,
fresh observation, digest, current grant and typed qualification binding.
Record no credentials, route actor generation or reusable native tokens.

Append only exact canonical kind 40 at the old boundary through the typed
durable journal. Check actual kind and predecessor digest and sequence,
verify `SyncAll` over that exact frame, then independently reopen/read
the exact bounded frame extent from the still-held inspected segment.
Revalidate segment identity, no unexpected EOF, canonical signature and
byte-for-byte agreement with the original expectation. Report the exact
head and offset to `Continuation::continued`. Lost reply, failed append or
sync, torn record, wrong independent readback, stale authority or changed
native binding poisons the live stage/ledger. Do not proceed even when a
durability result or parse result might subsequently look successful.
A clean kind 40 found after crash is historical evidence only.

## One reserved suffix range and its checkpoint

1. Start only at the checked adopted or last checkpointed end. Obtain the
   exact model `TailWrite` with `BudgetReservation` for this extent/range,
   continued head, current lease and future closeout. Reconcile a mismatch
   before physical effects. Add a read-only model permit matcher or private
   adapter equivalent that verifies its exact guard, current head, extent,
   source and range before effects. The existing `range()` exposes geometry
   alone; cross-session checking at `complete_tail` would be too late.
2. A single model permit may span multiple physical subwindows. Its native
   wrapper holds only one outstanding range and a private acknowledged
   cursor. This keeps the bounded scratch and network window while honoring
   the 4,096-record cap. Do not record a checkpoint for every SFTP request,
   and do not allocate an entire 64 MiB buffer. Fetch bytes on the same
   held source into bounded scratch, check live completion/epoch, and update
   the fresh whole-source and one range digest only from exact successful
   observations. A physical subwindow cannot pass the permitted end.
   Require the same private named inode and exact cursor before each write,
   and check the resulting extent and binding after it.
3. Check source and authority around awaits, then enforce the exact
   syscall gate described below. The exclusive job and stage lease
   intentionally span the coordinator. Route and grant synchronization
   covers only the bounded native submission and outcome.
4. Only once the physical extent and exact range completion are confirmed
   consume the permit in `complete_tail`. Full-sync the held file, confirm
   named/stage identity and exact end before/after, and bind one nonreusable
   native barrier acknowledgement to the exact range/ordinal/epoch/head.
   A later write invalidates the acknowledgement. Append its exact V2
   checkpoint using the stable kind-40 lineage head, actual immediate
   predecessor, new epochs, contiguous range and raw range digest. Check
   SyncAll and independent exact readback from the same segment. Advance
   the model head and release the completed reservation only via
   `Continuation::checkpoint`. No next range on a failed or lost result.
5. Preserve all bytes on uncertainty. Stop and fence the source, invalidate
   any outstanding permit/confirmation, block the model and retire a suspect
   ledger. If still authorized, record the exact supported kind-40-bound
   FailureRecorded through a writer whose prior effect is known. A failed
   journal sync is never retried to clear uncertainty. On revocation no
   new data/public write, no unauthorized cleanup or journal repair.
   An absent failure declaration after indeterminate effects does not
   restore authority; the exact live operation reports reconciliation.
   Restart inspection requires fresh identity and extent checks and cannot
   auto-write from a continued historical prefix.

### Exact route gate and syscall outcomes

A positive positioned short result proves only that exact returned
count. Verify that the same held stage now ends at its prior confirmed
cursor plus that count and account the corresponding source bytes
once. Reacquire the exact authority gate before attempting any
remaining bytes. An error with uncertain effect or unexpected extent
retires the writer and leaves all evidence. Gate a bounded EINTR
retry only after confirming exact unchanged current extent and live
authority. Retire after any confirmation failure.

The application prepares a gate from the exact admitted
`ConnectionBinding` before the SFTP callback borrows its SourceOwner.
Both operations keep the same owned transport generation and current
grant instance. Each native syscall requires the exact live job/stage,
epoch and current head, plus grant-then-route serialization. All
invalidations of that route generation, including embedded driver
exit, route stop, exact source cancellation and denied current grant,
must invalidate this shared gate before admitting another operation.
Do not check liveness with a detached copied boolean. The locked gate
does not call SourceOwner helpers that reacquire the same lock. It
covers exact syscall submission through outcome, without holding these
locks across unrelated I/O or an await.

## Terminal verification and continued publication

Require the current model checkpointed cursor and physical EOF to equal
the exact fresh source observation. For positive suffix growth, fully
synchronize and release the data writer before independently reopening
the private inode for full-stream readback from byte zero. At zero tail,
use the already synchronized held read-only inode and independently
reopen it for the same readback while retaining the original stage guard. Accumulate and compare the whole digest from
freshly read source bytes (including the verified prefix state), retest
actual EOF and metadata, then require SFTP terminal EOF, fresh held
observations, close and exact transport retirement/join. Recheck final
local observations after source awaits. Normal route retirement revokes
that route's submission authority, leaving the distinct publication grant
available; any terminal uncertainty denies publication.

Share the existing complete-readback/captured-stream proof core with a
new continuation-only engine entry point. Keep its proof constructor
private. A fresh `FreshStage` zero-offset contract stays unchanged.
Reuse the held closed stage and selected-stream local metadata operations,
but do not feed a continued capture through V1 `finalize_capture` or
manufacture a second EntryPrepared. V2 finalization must accept only
current clean continuation replay, exact confirmed kind 40 lineage,
new run/source, original allocation/prepared identity, verified extent,
typed V2 qualification and current scope/grant. Keep ordinary metadata,
signature/qualification, exact durable intent/readback and no-replace
publication guard. Require checked post-rename observation and barriers.
Quiescence plus secure data readback is not a publish permit.

Use a separate [1,0,15] continued finalization profile for kinds 4–9/18
and an explicit continued receipt branch. Its basis includes original
allocation, original preparation and actual continuation head. Continue
to encode source status as live observed. Use the separate proposed
continued receipt domain and bounded 6,144-byte envelope. Kind 18 must
commit the exact canonical promoted artifact and be verified against the
held journal. An unknown or post-intent result requires reconciliation;
never reissue the rename. Hold and check current grant through the actual
rename as in the existing publication bridge, and preserve observed
outcome if a later grant check fails. No qualified live activation before
the complete closeout grammar and native strategy-specific campaign exist.

## Commissioning requirement

Ordinary production admission correctly refuses an absent independently
selected V2 attestation. A native test harness or pure model pass may
exercise meaningful prerequisites while this is open, but eliding the
production gate cannot qualify that route/build. Activation requires
either an externally qualified artifact and independently issued proof,
or a separately reviewed, externally approved commissioning mode for
the exact measured binary using dedicated owned fixtures. The latter
needs explicit authorizer and scope, isolation from production inputs,
truthful exact coverage, and ordinary attested mode revalidation after
independent issuance. No automatic or owner-self signature is implied.
Ordinary selected-scope identity, current facts and current live grant
must match the same protected held root and live source pass.

## Review and evidence sequence

First land reviewed native read-only-to-synced stage preparation and
restricted append ports plus pure size/permit rechecks privately. Keep
real execution disabled until reviewed budget ownership, receipt namespace
grammar, V2 finalization/reconciliation/receipt and app activation meet.
Test model/native and journal seams jointly with real bounded independent
fault fixtures, then run the complete product strategy qualification
campaign on the selected native Linux host, destination and both supported
route classes as applicable. The documented V2 append coverage includes
pre/post barrier and frame cuts, no prefix overwrite, first-tail crash,
competing writers, same-size changed remote content, rival target,
pre/post-intent revocation and exact retained publication receipt. Test a
large interval with multiple actual bounded subwindows, the final legal
ordinal, one over budget, exact EOF/no-tail with insufficient closeout,
and cancellation of a short-write retry. Track the executed CPU, kernel,
mount/filesystem, route profile, tested build and strongest verified
process-crash evidence. No power-loss claim follows from a process-kill run.

## Proposed private APIs

- Engine `verify_continuation_input(inventory, source, reader, scratch)`
  takes the native read view by value, with the view implementing the
  existing `RetainedPrefixView`. It borrows that owned view to run the
  current verifier. On success the returned opaque engine capability owns
  both the verified source-borrow/hasher pair and the exact reader. That
  prevents consuming a fresh comparison alongside an unrelated or newly
  relocked local reader. Its consuming continuation operation delegates
  the retained native phase to an app-owned capability. No public API
  accepts a loose source handle, finalized hash and unrelated stage triple.
- Platform `RetainedPrefixRead::sync_adopted(self, exact_extent)` runs
  the held full barrier and returns `SyncedRetainedPrefix<'lease>`.
  `SyncedRetainedPrefix::open_suffix_writer(&mut self, admission)` yields
  `RetainedSuffixWriter<'_>` borrowing the held protected directory
  while the exact original stage guard stays owned by the holder. The
  app's unforgeable-in-assembly admission is supplied only after actual
  independent kind-40 readback; native refuses stale identity/extent or
  lease and checks the app authority through its structured gate.
- Model `TailWrite::matches_admission(live, expected_range)` can expose
  the exact original `Live`/range match without exposing a public permit
  constructor. The native per-range method checks the permit at original
  extent before opening its private physical subwindow cursor. One
  bounded system call advances that cursor from its existing confirmed
  offset. A positive short result must be observed at that exact new
  extent and gated again before its next chunk. EINTR is retried only
  within policy and after reaffirming the exact current extent and
  authority. Other unsuccessful syscall or incompatible size outcomes
  retire this native writer even before model completion.
- A consuming model finish check should require `Phase::Continued`,
  actual current live head and source epoch, no pending write or
  reservation, and the confirmed physical cursor and checkpoint end
  equal to the fresh source extent. Its result only permits closure and
  independent read-back. It cannot stand in for new complete stream
  verification or a later publication permit.
- The zero-tail branch never needs to open a data-writing descriptor.
  It keeps the synchronized held read-only inode and verifies the real
  absence of a stage writer, same clean current journal and complete
  admitted extent. Borrow a native read-only close-like capability for
  whole-stage verification and selected-stream local metadata under the
  original retained-stage guard. Do not use a local-source metadata type
  to produce this remote evidence. Its route/EOF/readback checks, upfront
  budget, synced kind 40 and V2 finalization are identical to the
  nonempty-tail branch.
- A private `ObservedContinuedCapture` result binds the exact live
  source completion and independent whole stage to kind 40, the latest
  admitted checkpoint boundary and the retained closeout reservation.
  The continued finalizer consumes that exact result and independently
  confirmed continued replay. It must never accept a naked tuple of
  measured digests or infer liveness from a historical kind-40 frame.
