# Filesystem companion ownership audit

Reviewed the tracked ExaCopy tree at
`f0825715c9860e7e578b1137a2f2965972c40a74`. The ExaCopy manifest
selects `apfs-mounted` only through the macOS platform package
([workspace dependency](../../Cargo.toml#L68),
[platform dependency](../../crates/platform/exacopy-platform/Cargo.toml#L25)).
Its [source pin](../../specs/dependencies/apfs-source.toml#L2) is
`fdcc3ea51e4cdc694453b7bfeb626f4d03367e1a`. The clean local companion
was at `987ce56de4d41cac349d139418407024ebf9296e`. A Git diff
between those revisions under `crates/platform/apfs-mounted` was empty,
so the mounted source findings apply to both. The clean local HFS+
companion was at `ecef68f5d7f2e4dc2886a144155adf2b9b880cc3`.
This was a source and API review. It did not run a native test or
change either companion.

## 1. Mounted APFS identity, admission and leased reads

ExaCopy still reads APFS mount identity and flags itself, duplicates the
rest of the native object identity around the companion's physical FSID
query, decodes firmlink and dataless object flags, and implements
both shared and exclusive process-bound directory leases. The source
reader separately checks named and held identity, captures a native
metadata stamp, reads exact ranges and probes EOF. Recovery uses the
same live-observation primitives and separately checks private stored
spelling and public alias occupancy.
[Managed root and mount checks](../../crates/platform/exacopy-platform/src/macos/managed.rs#L36).
[Shared lease](../../crates/platform/exacopy-platform/src/macos/managed.rs#L153).
[Pre-open source admission](../../crates/platform/exacopy-platform/src/macos/managed.rs#L229).
[Physical identity projection](../../crates/platform/exacopy-platform/src/macos/managed/physical_fsid.rs#L15).
[Live reads](../../crates/platform/exacopy-platform/src/macos/managed/file.rs#L152).
[Exclusive directory lease](../../crates/platform/exacopy-platform/src/macos/staging/directory.rs#L311).
[Recovery inventory](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/recovery/inventory.rs#L175).

**Available in APFS.** `Volume::is_apfs`, `Locality`, mount flags
and reported capabilities exist in `apfs-mounted/src/volume.rs:76`
and `:114`. `ObjectIdentity::{held,named,revalidate_held,revalidate_named}`
and its typed device/FSID/inode/generation/birth accessors are in
`identity.rs:91`. The bounded Darwin `fgetattrlist/getattrlistat`
ABI and physical identity response parsing already live in
`identity/native.rs:40`. `Lease` supports shared/exclusive held and
named acquisitions, contention and process-aware release in
`lease.rs:99`. `PinnedSource` covers checked live source reads and
EOF in `source.rs:176`. `publication::pin_entry` and
`scope::stored_name` supply event-only identity and native spelling.

**Work package.** Project mount facts and the full companion object
identity into ExaCopy's existing observed/recorded values. Eliminate
the duplicate `fstatfs` interpretation and physical-FSID-only query
path. Add typed mounted object flags and a checked pre-open source
observation that binds to a companion `Lease` or can be paired with
one throughout each operation. The current `PinnedSource::open`
takes a directory and name, checks type and same mount, and opens
before it can enforce ExaCopy's owner, mode, single-link and
firmlink/dataless requirements. A post-open check alone would change
the current admission boundary. The companion source API also needs
bounded access to the pinned descriptor's ACL, fork, attribute and
pre-read access-time evidence. Compose shared/exclusive locks with
the same provisioned-root and named-child rules, without fallback or
in-place conversion. Preserve the original root checks, the read
recheck before and after I/O, and missing/changed/unavailable evidence.
Keep ExaCopy's attestation and its chosen permission, ownership,
metadata and alias policies in the platform facade. Preserve the
existing identity representation in signed records and receipts.

## 2. APFS stage lifecycle and post-close metadata

The private stage uses a native held writer, an event-only anchor, a
second independent reader, checked writer close, and timestamp
installation with new observations. The firewall around metadata is
ExaCopy's strict unnamed-stream profile. The metadata and object
observations must bind to the correct stage before the transfer
coordinator can use them.
[Stage write and close](../../crates/platform/exacopy-platform/src/macos/staging/file.rs#L129).
[Independent read-back](../../crates/platform/exacopy-platform/src/macos/staging/reader.rs#L12).
[Metadata installation and barrier](../../crates/platform/exacopy-platform/src/macos/staging/metadata.rs#L27).
[Fork, ACL and compression visibility policy](../../crates/platform/exacopy-platform/src/macos/managed/metadata.rs#L139).

**Available in APFS.** `PrivateWriter`, `ClosedFile`, `ReadBack`
and `MetadataReadyFile` are implemented in `writer.rs:40`,
`writer.rs:135`, `writer/read_back.rs:15` and `writer.rs:194`.
The implementation owns the native stage anchor, exact extent,
retirement on failed write, full-file barrier and checked close.
`writer/observation.rs:88` checks the native exact spelling and no
ACL entries. The companion checks owner, mode and link count and
compares the live flags between observations. ExaCopy currently
requires stage flags to be zero at admission. The companion confirms
the specific permitted Darwin birth-time change on timestamp update
in `writer/observation.rs:134`. ExaCopy currently holds the original
birth time in its equality check. `metadata::{extended_security,
resource_fork,read_resource_fork,list_xattrs}` already provides
the kernel-facing observations.

**Work package.** First migrate low-level stage operations to the
companion's owned writer states. Carry ExaCopy's model binding,
stage ID and leases in its facade. Extend the mounted stage API to
expose pre/post metadata inventory and retained live identity at the
points needed by the current adapter, including support for rejecting
nonzero initial flags and observable resource forks, compression and
other xattrs. Check both named and held state after barriers. Specify
whether the timestamp operation can update birth time through a
separate reviewed profile change. The initial ownership refactor
must preserve the existing refusal behavior and journal identity.
Translate companion effects such as created but unverified and closed
but unverified into precise existing or reviewed ExaCopy uncertainty
outcomes. Keep independent read-back verification, model quiescence,
epoch binding, recovery decisions and durable intent in ExaCopy.

## 3. Exclusive publication primitive and native evidence

ExaCopy embeds the raw Darwin no-follow rename flag and uses its
helper for both user destination publication and private receipt
promotion. The current user destination path checks volume capability
and stage authority, asks the kernel for one no-clobber rename
without a destination prelookup, attempts both directory barriers
after rename success, and then observes leases, names, metadata and
target identity. A scope restoration error can accompany any outcome.
[Native rename](../../crates/platform/exacopy-platform/src/macos/publication/native.rs#L7).
[Publication ordering and typed results](../../crates/platform/exacopy-platform/src/macos/publication/attempt.rs#L63).
[Receipt promotion](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/receipt.rs#L101).

**Available in APFS.** `publication::exclusive_rename` at
`apfs-mounted/src/publication.rs:185` owns the syscall flags,
checks the held identity and source name, performs destination
preflight, classifies conflict versus uncertainty, and samples
post-rename observations before its caller invokes separate
`sync_directories` at `:279`. The native primitive is private
at `:222`.

**Work package.** Expose a narrow safe companion operation for the
existing kernel-exclusive transition with no destination prelookup,
or an explicitly equivalent exact-order operation. Preserve a
different result for pre-call refusal, conflict, uncertain syscall
effect, and a rename followed by incomplete barrier or observation
evidence. Keep both independent barrier outcomes. ExaCopy can then
project the outcomes and continue to check final metadata, both
leases, former-name absence and target native identity after the
barriers. The private receipt path requires its existing single
directory barrier and post-barrier revalidation. Preserve the
durable intent before the syscall, incumbent preservation on
conflict, and the absence of automatic cleanup or retry on
uncertainty. Leave receipt codecs, authorization and reconciliation
in ExaCopy.

## Existing boundary and HFS+ scope

The raw Darwin dataless policy ABI, physical FSID, volume attributes,
stored-name observation and ACL/fork/xattr ABIs are already consumed
from the companion. ExaCopy's [thread policy](../../crates/platform/exacopy-platform/src/macos/managed/thread_policy.rs#L3),
[ACL projection](../../crates/platform/exacopy-platform/src/macos/managed/acl.rs#L4)
and [stored-name check](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/recovery/name.rs#L4)
are policy and error adapters. The remaining direct Rust unsafe call
in this macOS source tree is the [checked close](../../crates/platform/exacopy-platform/src/macos/staging/close.rs#L6).
The file-stage close can be shared with the companion writer. A
checked descriptor close, held relative opens, positioned file I/O,
`fsync` and `F_FULLFSYNC` are OS operations. ExaCopy's
[job journal](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/journal.rs#L75),
[signed record](../../crates/platform/exacopy-platform/src/macos/staging/directory/jobs/record.rs#L97)
and receipt persistence can retain native platform adapters for
those operations. The interpretation of a successful syscall remains
separate from crash or power-loss qualification. The dependency
pin, build policy and release provenance remain consumer obligations.

The tracked production source, native helper, script and manifest
inventory yielded no HFS+/HFSX-specific parser, writer, raw hook,
qualification path or Cargo dependency in ExaCopy. Its mounted copy
profile explicitly admits APFS. The HFS+ workspace has an on-disk
format, reader, builder and core with no mounted adapter member.
Examples in the local HFS+ tree include
`hfsplus-reader/src/volume.rs:106` for on-disk volume admission,
`catalog/finder_info.rs:67` for Finder information and
`decmpfs.rs:210` for reading logical compressed data. There is
no HFS+ ownership migration indicated by this inventory. ExaCopy's
[uninstall resource-fork refusal](../../tools/installer/store.sh#L181)
is a mounted Darwin no-loss policy. It does not interpret HFS+
disk metadata and should remain independent of either image reader.
