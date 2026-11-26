# APFS private-stage recovery handoff

The mounted APFS companion at `fc71ded0c7b6d5d433317edf90490b3dcef9a2c0`
provides independent read-back from a live `ClosedFile` and metadata queries on
a live `MetadataReadyFile`. Its held metadata view can check the original
sealed inode after publication. Both capabilities originate from the original
private writer. A restarted process has fresh directory and entry observations
instead. It needs a separate read-only stage reader. [Mounted APFS requirements](../architecture/apfs-library-requirements.md)

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

## Companion API requirement

Add an observation-only reopen capable of borrowing a freshly authorized
stage directory, its currently held matching lease, the exact raw component
and an event anchor obtained from fresh inventory. The expected identity and
logical extent are comparison inputs. ExaCopy will keep its current exclusive
stage-directory lease and protected ancestry checks.

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
