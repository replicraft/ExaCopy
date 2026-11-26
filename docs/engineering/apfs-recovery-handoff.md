# APFS private-stage recovery handoff

The selected mounted APFS companion is public commit
`af97d38523881265c037b91b0504242eec84e392` (`apfs-mounted` 0.1.0).
A fresh exact-commit Git fetch and the pinned canonical archive digest were
verified on 2026-11-26. Commit `52f8b79` supplies the requested observation-only
`ReopenedStage`: leased pre-open admission, an anchored read-only descriptor,
bounded reads, live metadata and a real EOF check. This supersedes the earlier
request to add that basic capability. ExaCopy has updated the source pin;
its recovery adapter has not yet migrated to this API.

The companion also provides independent read-back from a live `ClosedFile`
and metadata queries on a live `MetadataReadyFile`, including after rename.
[Mounted APFS requirements](../architecture/apfs-library-requirements.md)

## Current ExaCopy recovery

ExaCopy admits the recovery root and job, then observes the selected private
stage and public target under current directory leases. Its inventory retains
event-only handles for present names and verifies exact stored spelling for the
private entry. Public spelling aliases count as occupancy. The inventory
records native identity and logical length. The public target is
observed without opening its payload. [Recovery inventory](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/recovery/inventory.rs)

Before read-back, inspection compares the newly observed stage directory,
stage identity and length with the accepted journal evidence. The recovery
adapter opens only that private entry read-only, preserves the live name and
identity checks across bounded positioned reads, and probes EOF at the
declared extent. The inspection coordinator compares the measured stream
digest and, when the journal carries a metadata record, both initial and
final metadata with their exact expected values. [Recovery stage reader](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/recovery/inventory/readback.rs) · [Inspection read-back](../../crates/engines/exacopy-transfer/src/macos/inspection/readback.rs)

## Recovery adoption contract

Use `ReopenedStage` with a freshly authorized stage directory, its currently
held exclusive lease, the exact raw component and an event anchor obtained
from fresh inventory. The expected identity and logical extent are comparison
inputs. ExaCopy keeps its exclusive stage-directory lease and protected
ancestry checks. The following are integration requirements, not a claim
that these capabilities are absent from the latest companion.

- Before opening, confirm that the caller's lease covers the live directory
  and that it belongs to the acquiring process. Confirm the relative no-follow
  lookup, exact stored spelling and held event anchor against the expected
  signed native device number, ordered physical filesystem ID, nonzero inode, optional
  generation, normalized birth time and bounded extent.
- Gate the data descriptor on an admitted, materialized regular file with one
  link. Keep dataless materialization disabled during admission and I/O. Let the
  caller inspect ownership, exact mode 0600, zero BSD flags and event-handle ACL
  evidence. Bind an independently opened read-only descriptor
  to that same inode and name. Recheck the current lease, extent and live stamp
  before returning the reader.
- Keep both metadata and read operations scoped to that descriptor. Supply
  bounded positioned reads and a real EOF probe at the expected extent. Check
  the held identity, name, lease, extent and live content stamp before and
  after those operations. Report failures or incomplete observations with
  enough detail for the caller to discard bytes and require reconciliation.
- Expose bounded ACL, resource-fork and both xattr views for ExaCopy's strict
  metadata policy. Return initial and final live access and modification times.
  A routine read or EOF probe may advance access time. The reader must report
  the resulting access time and leave any recorded metadata comparison to
  ExaCopy.

ExaCopy retains signed job and journal admission, accepted framing, the
private/public namespace comparison, BLAKE3 verification, and decisions
about recovery. A journal record supplies an expectation to check against
fresh observations. This reader grants observation authority only. It
cannot establish live writer closure, a new durability barrier, permission
to mutate, or publication authority.

## Remaining upstream boundaries

The recovery API currently borrows an `EventEntry`, which itself borrows a
`Directory` and `EntryName`. ExaCopy's returned reader cannot borrow an anchor
created inside its open method. Adoption can use a scoped callback with the
name and anchor kept outside the read scope. An upstream ownership-oriented
reader constructor, such as `open_named(&Directory, EntryName, &Lease,
expected_length, admit)`, is an alternative, provided it owns the necessary
name and anchor without a self-reference; merely consuming the borrowed
`EventEntry` does not remove its name lifetime. This is an integration
choice, not a missing read primitive.

A coherent, observation-only event API would remove remaining consumer
`stat` plus physical-FSID joins. It should return initial and revalidated
native identity, extent, change stamp and bounded metadata from the same
held anchor; support exact stored spelling for private stages and ordinary
lookup spelling for public occupancy; and permit reuse by `ReopenedStage`.
ExaCopy must still compare the original inventory baseline throughout
recovery, including the public name and protected ancestry. The reader's
fresh baseline alone cannot replace that history check. Its initial metadata
is pre-open; preserve ExaCopy's post-open initial access-time comparison using
the live metadata view. Ordinary reads may advance access time.

Typed `ObjectFlags` already exist upstream. Remaining consumer firmlink and
dataless bit interpretation should use those APIs. Post-publication named
identity/metadata observation belongs to the same reusable native boundary;
ExaCopy keeps the comparison with its recorded publication expectation.
Existing `Directory::create_private_directory` can also replace consumer
`mkdirat`/open/barrier scaffolding, while preserving separate created,
existing and created-but-unconfirmed outcomes and ExaCopy's strict 0700/ACL
admission. A reusable checked private-artifact lifecycle (exclusive create,
held/name observation, barrier, checked close and read-only reopen) could
serve immutable job records and receipts. It must not absorb their names,
formats, journal cursor, resource reservations or publication ordering.
The existing stage writer is not a replacement for an append-only journal.

A checked protected ancestor walk and final read would be reusable upstream
if macOS protected snapshot support is added. That path currently refuses
on macOS; this is a future capability request rather than active duplication.
ExaCopy retains protected-operation authorization and content verification.

Generic descriptor barriers and checked close may be shared upstream when
their error phases match, but journal framing, allocation limits and signed
record semantics remain ExaCopy responsibilities.

## Earlier modification times on Darwin

ExaCopy installs the source's captured access and modification times with
`BirthTimePolicy::Preserve`. Its prepared and sealed stage identity includes
birth time. The companion applies timestamps first, then reads back the
result and verifies the original identity before issuing a metadata-ready
capability. [Live stage metadata](../../crates/platform/exacopy-platform/src/macos/staging/metadata.rs)

The pinned companion's native
`caller_can_require_zero_initial_flags_and_unchanged_birth_time` fixture sets
timestamps one second before a private stage's captured birth time. Its
macOS ARM64 14.7.2 run observes the same private inode with an earlier birth
time and requires `TimesAppliedButUnverified(Changed)`. This establishes a
post-update refusal on that fixture. The successful companion publication
fixture sets an earlier access time while keeping the stage's existing
modification time.

A source whose modification time predates a fresh stage's birth can therefore
stop an otherwise eligible copy when Darwin lowers the stage's birth time.
The result retains the changed private entry and issues no metadata-ready
capability or publication authorization. Recovery must compare the retained
inode's current birth time with the exact accepted identity even when its
inode number matches. A changed birth time requires reconciliation. Treating
the new birth time as the prepared identity would change the journal and
replay contract and requires separate review.

## Mutation-free seal for fresh selected streams

The independently read-back stage for an SFTP data-only capture does not
need source timestamps installed. The companion currently creates a
`MetadataReadyFile` through its checked timestamp operation. Add a separate
checked transition from the live `ClosedFile` that seals its current local
metadata without applying timestamps. An illustrative API name is
`seal_existing_metadata_checked`; it remains an upstream request.

Use the original closed-writer capability, private name, lease and event
anchor. Obtain and retain the companion's own checked read-only descriptor,
observe the live metadata, run a bounded caller policy callback, perform the
required file barrier, and revalidate the same identity, name, extent and
metadata before and after the post-barrier callback. Preserve the exact
observed access and modification times and require stable change time during
this transition. Retain the private entry on any incomplete observation or
barrier result. Issue the ordinary metadata-ready capability only after all
checks succeed, so its existing post-rename held view can be reused.

The callback lets ExaCopy require local mode 0600, admitted ownership, one
link, zero flags and its explicit ACL/fork/xattr policy. The companion must
not embed SFTP policy, digest comparison, grant, journal or receipt semantics.
ExaCopy still requires writer quiescence, complete independent read-back,
durable intent, qualification and one no-clobber permit before publication.
No duplicate consumer descriptor, raw barrier fallback or timestamp mutation
is needed for this seal.
