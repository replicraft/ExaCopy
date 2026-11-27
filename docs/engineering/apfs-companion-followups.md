# Mounted APFS companion follow-ups

ExaCopy uses `apfs-mounted` 0.1.0 at public commit
`8c13b1da5aba2f31a012daa48756fef5cf0752dc`. Public main matched the pin
on 2026-11-27. The pending requests concern mounted directory and
file operations. ExaCopy retains grants, metadata acceptance, record
names and schemas, durable intent, barrier ordering and reconciliation.
[Source pin](../../specs/dependencies/apfs-source.toml) ·
[Pinned mounted companion](https://github.com/pomologie/apfs/tree/8c13b1da5aba2f31a012daa48756fef5cf0752dc/crates/platform/apfs-mounted)

## Checked creation of a private directory

ExaCopy requests exclusive 0700 creation, samples the named child's
mount and full identity without following links, and only then opens
that child as a directory. It compares the held identity with the earlier
name sample before using the child. ExaCopy then checks the owner, exact
mode, flags and ACL under the lease and rechecks the parent. The pinned
helper opens before returning any named observation and folds exact-mode
refusal into the same unconfirmed result as reopen failure.
[ExaCopy job creation](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs.rs#L239) ·
[Pinned directory creation API](https://github.com/pomologie/apfs/blob/8c13b1da5aba2f31a012daa48756fef5cf0752dc/crates/platform/apfs-mounted/src/scope.rs#L149-L177)

Provide an opaque created-directory operation with a checked point
after successful mkdir and before the readable open. Carry the named
identity, including physical FSID, through that open. Allow the caller
to authorize the reopen and check its exact mode and ACL policy in
the existing order. Return a held directory suitable for leasing,
without a second path lookup or a fallible descriptor duplication.
Distinguish an incumbent from a failed create attempt and a created
entry whose open or admission could not be confirmed. Preserve a typed
mode refusal if the companion checks mode. Retain restrictive-umask
results without correcting permissions or deleting the new directory.

Native acceptance on local journaled APFS should exercise exclusive
0700 creation with matching named and held identity, occupied exact
names and aliases with incumbent preservation, and rejection of a
different named identity between the first sample and reopen. Check
a process-isolated umask that yields readable 0500, a separate
post-create reopen error, and retained entries with the correct Bind
cause. Recheck the existing child-then-parent barriers and strict ACL
admission in the consumer test. [Job fixtures](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/tests.rs)

## Pending receipt through final observation

ExaCopy synchronizes the sole writer, then opens and validates an
independent readable descriptor while the writer is still held. After
consuming the writer through checked close, it reads the exact bytes
and retains that same reader through promotion, the directory barrier
and final identity and metadata checks. The pinned artifact helper
closes before reopening. It verifies the bytes and EOF, drops its
reader, and returns an event anchor. Its ordinary metadata accessor
reopens the original name. Its separate sealing API opens another
reader and adds a full-file barrier.
[ExaCopy receipt lifecycle](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/receipt.rs#L88) ·
[Pinned artifact helper](https://github.com/pomologie/apfs/blob/8c13b1da5aba2f31a012daa48756fef5cf0752dc/crates/platform/apfs-mounted/src/writer/artifact.rs#L93-L158) ·
[Pinned sealing API](https://github.com/pomologie/apfs/blob/8c13b1da5aba2f31a012daa48756fef5cf0752dc/crates/platform/apfs-mounted/src/writer/seal.rs#L30-L76)

Provide a checked artifact operation that binds the independent reader
after the writer barrier and before checked close. Verify bytes after
close, then return an opaque verified-reader continuation usable for
caller-authorized exclusive promotion and bounded post-rename metadata
checks. Keep the same readable handle through those observations.
Avoid public access to mutable or raw file handles. Keep write, file
barrier, reopen and binding, close, and read-back errors separately
projectable, including their native causes and retained-entry effects.
A failed reopen takes precedence over a later checked close. ExaCopy
still controls promotion, the namespace barrier, and final evidence.

Native acceptance should verify reader continuity and this failure
order, partial-write retention, same-length corruption refusal, and
pending-name replacement after successful file sync. A competing final
name must survive. A failed directory barrier must retain the complete
final bytes for reconciliation. A repopulated pending name must prevent
a confirmed receipt while preserving both inodes.
[Receipt fixtures](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/tests/receipt.rs)

## Qualification scope

ExaCopy has delegated journal and job barriers to the pinned companion.
The hosted macOS component suite at `11d2134` passed eight direct
mounted-job cases and 23 nested cases. That result covers the tested
component operations. The ordinary-source strict copy refused the
observed birth-time adjustment. A separate timestamp-eligible synthetic
case passed through receipt. Ordinary-source success, crash recovery
and power-loss qualification remain open.
[Hosted macOS component job](https://github.com/replicraft/ExaCopy/actions/runs/46070224005/job/140745109905) ·
[Strict copy fixture outcomes](proposed-apfs-metadata-and-birth-handoff.md#hosted-profile-observations-on-2026-11-27)
