# Proposed managed APFS metadata and stage identity handoff

This work package covers one regular file on owner-managed local APFS. It
applies R-016, R-026, R-039–041, R-043, R-045 and R-062 with their corresponding
acceptance cases. INV-001–006, INV-009, INV-013, INV-019 and INV-020 govern
the source, stage, history and publication decisions. The existing
[P-001–003 foundation obligations](../foundation.md) continue to govern
preserve-mode effects. New metadata and identity transitions need their own
traceability and replay tests before operation admission.
[Current single-file contract](../verified-staging.md)

## Observed boundaries

ExaCopy `96fea04634aee308193b177d7fbdd9f00ff10513` was built with
`experimental-apfs-copy` against the verified Pomologie archive at
`aa75bcb6d219fdb5c4c0fba39adc3ccdc9a1518f`. The mounted library tree
`6a0998846242784668ec1b656d1fb3e3d2907643` is identical to the previous
pin. On native ARM64 macOS 14.7.2 on local APFS, the strict copy fixture
returned `Admission(Source(BasicMetadata(ExtendedAttributes)))` before
job creation. The strict restart fixture returned
`StageReadBack(Platform(Managed(BasicMetadata(ExtendedAttributes))))`
before payload read-back. Neither reached its success oracle. Four exact
controls passed for source admission refusal, an already prepared entry's
refusal before writing data or intent, refusal before recovery payload I/O,
and recovery inventory. Their assertions preserve source bytes, keep the
prepared stage empty and its journal unchanged, and keep the live incumbent observation
separate from historical replay.

Separate held-descriptor, size-only observations of an owned synthetic
source, empty stage and private record each found `com.apple.provenance`
at 11 bytes in both xattr views. Names, identity, lengths and timestamps
remained stable across those observations. Attribute payloads, write
permissions and portability of provenance evidence were not established.
Management artifacts and payloads have separate policies. The private
record probe does not turn strict stream metadata admission into a
requirement on an owner's immutable control artifact.

The pinned companion's existing
`caller_can_require_zero_initial_flags_and_unchanged_birth_time` fixture
passed separately. Installing earlier access and modification times on a
disposable private inode returned `TimesAppliedButUnverified(Changed)`
under `BirthTimePolicy::Preserve`. The inode number was unchanged, and the
retained file's birth seconds matched the requested earlier modification
seconds. These are native refusal and observation results. Full local
publication, strict restart read-back, process-crash execution and
power-loss qualification remain open.
[Existing private-stage recovery contract](apfs-recovery-handoff.md)

## Checked surfaces at the pinned revision

| Phase | Pomologie mounted interfaces | ExaCopy binding and policy |
| --- | --- | --- |
| Source admission and reading | `PinnedSource::open_leased`, `with_metadata`, `read_exact_at`, `revalidate`. `MetadataView::stat`, `extended_security`, `security_guids`, `list_xattrs`, `read_xattr`, `read_resource_fork`, `resource_fork`. | `ManagedRegularFile` retains its held lease and source identity. `BasicMetadata` checks regular type, 0600, one link, zero flags, basic ACL/GUID policy, absent fork, and empty `Visible` and `IncludingCompression` xattr inventories. The pre-read check binds the captured access time. |
| Private fresh stage | `PrivateWriter::create_with_initial_flags`, `write_next`, `flush_and_close`; `ClosedFile::open_read_back` and the scoped `ReadBack`. | ExaCopy selects the private name and bound extent, joins the sole writer, independently checks positioned bytes and EOF, and compares BLAKE3 before metadata completion. |
| Metadata transition | `ClosedFile::apply_times_checked`, `BirthTimePolicy::{Preserve, AllowDarwinAdjustment}`, and the callback's `BeforeUpdate`, `AfterUpdate`, `AfterBarrier` phases. `ClosedFile::seal_checked` seals current metadata and times. `MetadataReadyFile::with_metadata` and `with_held_metadata` inspect its read-only descriptor, including after rename. | `ClosedStage::apply_basic_metadata` checks strict inventory, UID/GID equality and required source times while retaining the accepted original stage birth identity. The pin exposes no closed-stage operation for applying selected xattrs. The observation callbacks convey a read-only metadata view. |
| Publication | `attempt_exclusive_rename`, `attempt_exclusive_rename_checked`, `RenamedEntry::observe`, `sync_directories`. The checked variant holds the returned caller guard through one exclusive rename. | `MetadataReadyStage` and the coordinator require an exact bound, durable publication intent and one no-clobber permit. They validate both names, held metadata and directory barriers before recording successful publication evidence. |
| Restart observations | `OwnedEventEntry::open_named` and `with_observation`; `ReopenedStage::open_named`, `with_observation`, `read_exact_at`, `confirm_eof`. | Recovery rebinds exact private spelling, lease, identity, extent and current metadata. ExaCopy compares recorded verification and metadata with fresh initial and final observations. Read-back can advance access time. Mismatch preserves the entry for reconciliation. |
| Private control files | `write_private_artifact_checked` returns a `ClosedFile` after exclusive creation, file barrier, checked close and independent byte/EOF read-back. | Owner and plan use the helper with separate namespace barriers. Migrating receipt staging is separate. It must retain checked promotion, exact bytes, final identity and each existing uncertainty phase. |

The existing API can continue to enforce the current strict policy. It
cannot turn an admitted visible attribute into faithfully preserved
metadata on a separate stage. The consumer currently rejects the source
before creating a stage and independently rejects an attributed recovered
stage. Applying a new setter only at staging would leave both gates and
the persisted fidelity contract unresolved.

## Pomologie mounted work

Add a checked metadata-only transition on a consumed `ClosedFile`, for a
bounded, caller-selected attribute plan. It should share the held/name
stability checks, observation phases and full file barrier already used
for timestamps. Keep it within the mounted library, with no APFS
container parsing or product journal policy.

- Before any application, check the lease or acquire the caller's
  authorization at the effect boundary. Validate the private directory,
  exact stored component, held event anchor, freshly reopened descriptor,
  all native identity components, extent, owner, mode, one link, flags
  and live stamp. Require bounded raw attribute names, per-value size,
  attribute count and total value bytes, with unambiguous absent versus
  zero-length semantics. Deny unknown attributes by caller policy.
- Apply only the approved metadata to the already owned inode through
  the checked descriptor. Use the least native rights the platform
  supports, with no public write, rename, removal, payload-write handle
  or materialization fallback. Keep kernel-managed, protected and
  otherwise unqualified names outside any writable set. The caller can
  require that a pre-existing observed attribute match exactly; an
  unconfirmed name, value or access right stops the transition.
- Read back all required metadata and validate both visibility views,
  the extent, exact spelling, held/named identity and expected mutable
  stamps. Repeat the checks after the full file barrier before returning
  `MetadataReadyFile`. The new interface must let the caller preserve
  current scalar metadata and compare the result on the same descriptor
  used for transition. Any later timestamp update must use the same
  fully checked lifecycle before publication.
- Distinguish definite pre-effect refusal, syscall failure with possible
  effects, partial multi-attribute application, post-effect mismatch,
  failed barrier, barrier followed by failed verification, and failed
  restoration of the thread policy. Keep the owned stage on every
  incomplete result. Issue no metadata-ready authority for an uncertain
  operation or unconfirmed required attribute.
- On the exact host profile, qualify the supported attribute classes
  independently of visibility. An equal name and length cannot prove
  equal bytes or equivalent provenance security state. There is no
  evidence here that the observed provenance attribute can be safely
  installed on a different inode. Apple's descriptor-level xattr and copy
  interfaces document general mechanisms. Their presence supplies no
  exact provenance preservation guarantee.
  [Apple fsetxattr](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsetxattr.2.html)
  · [Apple fcopyfile](https://github.com/apple-oss-distributions/copyfile/blob/main/copyfile.3)

Qualify timestamp installation separately. One possible mechanism would
request the retained birth time together with the required access and
modification times through a descriptor-scoped attribute update. Apple
documents read/write creation, modification and access attributes. A
companion test must establish exact results on an authorized private inode
and distinguish post-effect failure. The current `apply_times_checked`
path already proves a safe refusal when `Preserve` cannot hold. Its
`AllowDarwinAdjustment` path checks a narrowly permitted birth change on
the live held inode. That live mechanism needs the consumer protocol
below before use in this operation.
[Apple attribute definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getattrlist.2)

## ExaCopy consumer work

1. Keep the current profile, record decoding and refusal behavior. Define
   an explicitly selected versioned fidelity profile that identifies
   which metadata is required and which native class can preserve it.
   Bind the profile and bounded canonical metadata commitment into the
   signed plan and ownership chain. Bind source inventory observations
   before payload I/O, stage verification, post-barrier recorded metadata
   and the receipt. Define any immutable private evidence needed to
   recover and compare metadata without exposing raw attribute values in
   diagnostics. Keep fork and extended security policy explicit. Reject
   incomplete, unsupported or unknown inventory before authorizing
   publication.
2. If the companion can verify timestamp updates with unchanged birth,
   retain the current exact stage identity comparison. If the profile
   intentionally allows the observed adjustment, add a versioned
   transition protocol. `DarwinFileIdentity` includes birth time.
   `DarwinStageSealed` validates the exact kind-2 prepared identity,
   `DarwinMetadataRecorded` compares that identity through the stage
   verification, and kind-7 intent, recovery and receipt validation
   consume those identities. Merely assigning the new live birth value
   would rewrite the meaning of the prepared record. A new protocol must
   persist an exact, synchronized pre-effect authorization binding both
   permitted births, source time, same volume/inode/generation, stage
   name, directory identity, extent and accepted digest. It must then
   bind the same live held stage through a checked post-effect record and
   file barrier before publication intent. A restart between those
   records has an incomplete transition and requires reconciliation. The
   reopen path must not authorize mutation from matching inode alone.
3. Extend read-only recovery to select the exact recorded version and
   compare complete initial and final live metadata on the reopened stage
   against its committed policy. Check effect-unknown suffixes, target
   occupancy and both name bindings under the original authorization.
   Keep recovery read-only while semantics for any separate mutation
   executor are designed and verified. Do not restore access times as a
   side effect of inspection.
4. Require native eligible and refused sources, wrong and extra visible
   attributes, empty/absent distinction, hidden compression-visible
   entries, access refusal, rebound names, earlier mtime, failed or
   partial application, post-effect mismatches and barriers. Add
   deterministic old-profile and changed-stage replay controls, including
   every journal interruption before intent and around exclusive rename
   and receipt commitment. Complete native process-crash qualification
   separately before expanding the supported CLI or durability claim.

An explicitly chosen native qualification source must satisfy its profile
as observed. The reported fixture refusals remain recorded; fixture
surgery or metadata exemptions would invalidate the evidence.

## Hosted profile observations on 2026-11-27

The [ordinary-source run at `ea2b867`](https://github.com/replicraft/ExaCopy/actions/runs/45972819734)
reached private metadata application on ARM64 macOS 15.8.2 and local journaled
APFS, then refused an observed birth-time adjustment. Before cleanup, its
oracle checked unchanged source bytes, retained stage identity, absent target
and receipt, and no publication intent or later publication frames.

The [separate timestamp-eligible run at `9a3f6b8`](https://github.com/replicraft/ExaCopy/actions/runs/45973390568)
passed the exact copy-through-receipt fixture with a synthetic source mtime
later than stage birth. Strict metadata and identity checks remained active.
This result qualifies that synthetic case, leaving ordinary-source success,
restart and power-loss qualification open. The current `8c13b1d` companion pin
has identical mounted code and build inputs to the pin used by both runs.
The [fixture profiles](../../apps/exacopy-cli/verification/macos_apfs_publication/README.md)
describe their separate input conditions and oracles.
