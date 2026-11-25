# APFS library requirements for ExaCopy

This integration contract records the capabilities needed to replace ExaCopy's
mounted APFS implementation. The original accounting used ExaCopy
`6e24897d3a185bc5b4a3a99b6931233f24501503`; the consumer update below uses
`885b74e`. The inspected Pomologie revision is
`8f19cd36c1d1ddf7a16a45adb849d389797dee89`, whose clean checkout now contains
`crates/platform/apfs-mounted`. Available library APIs, consumer integration
and native qualification are separate statuses.

**Ownership**

Pomologie should own APFS format interpretation, native filesystem semantics,
Darwin attribute layouts and the reusable mounted filesystem implementation.
ExaCopy should consume safe typed capabilities and observations. Its copy
model, authorization, integrity verification, journal and recovery policy
remain operation-engine responsibilities.

Pomologie supplies portable image-oriented core, format, container and reader
crates, plus the macOS-only hosted `apfs-mounted` companion. The reader uses
`no_std` and forbids unsafe code. The companion keeps Darwin and `std` outside
the portable crates. Its documented item-level native-binding exceptions
remain a separate safety and qualification boundary.

**What the existing unsafe code does**

At the ExaCopy checkpoint there are 14 production unsafe blocks in nine macOS
files, plus one external declaration block. Three additional macOS unsafe
blocks create test fixtures. The 22 Windows unsafe blocks are confined to
the default-off native qualification fixture. The authored Linux and Windows
production implementation contains no unsafe blocks.

| Existing macOS owner | Production blocks | Operation |
| --- | --- | --- |
| `managed/acl.rs` | 2 | Query extended security and provision an explicit empty ACL on a new private directory. |
| `managed/metadata.rs` | 3 | Query visible xattrs, compression-visible xattrs and resource fork information. |
| `managed/physical_fsid.rs` | 2 | Query real filesystem identity through a held descriptor and a relative name. |
| `managed/volume.rs` | 1 | Query supported and valid volume capability bits. |
| `managed/thread_policy.rs` | 2 | Read and change the calling thread's dataless materialization policy. |
| `publication/native.rs` | 1 | Exclusive, no-follow relative rename. |
| `staging/directory/jobs/recovery/name.rs` | 1 | Obtain the actual private entry spelling from a held descriptor. |
| `staging/entropy.rs` | 1 | Obtain a random nonce. |
| `staging/close.rs` | 1 | Consume a writer and report its close result. |

The subsequent wrapper cleanup replaces exclusive rename with safe `rustix`
and entropy with safe `getrandom`, leaving 12 production unsafe blocks.

These bindings call Darwin, and some decode its syscall response layouts.
APFS object maps,
on-disk B-trees, checkpoints and raw allocation structures belong to the
Pomologie format stack. ExaCopy's mounted implementation uses kernel
filesystem operations.

**Why mounted hooks are needed**

The current copy engine does not require raw APFS access. It neither reads
filesystem blocks nor parses or modifies APFS trees, checkpoints or allocation
structures. Darwin's mounted interfaces supply the live identity, metadata,
materialization policy, exclusive publication and synchronization observations
needed by the copy contract. Most are Darwin filesystem operations used on
APFS rather than APFS format operations. Moving their implementation into
Pomologie preserves those checks while removing native layouts and bindings
from ExaCopy. A raw image reader is a separate future input capability.

**Consumer changes and current library support**

At ExaCopy `885b74e`, native macOS composition lives in `exacopy-engine`.
`exacopy-transfer` owns generic admission, staging, publication and read-only
recovery policies without importing the platform or engine crates. Safe
`rustix` exclusive rename and `getrandom` entropy have already replaced two
direct unsafe calls. These are ExaCopy changes; the independently committed
Pomologie companion is a separate workstream. The companion is not yet a
production dependency at this consumer checkpoint. An independent archive run
of Pomologie `8f19cd3` on native ARM64 macOS with Rust 1.100.0 passed its 50
unit tests and one private-publication integration test. That integration
test does not impose ExaCopy's strict xattr admission, journal intent or crash
protocol; it is library evidence rather than an ExaCopy copy qualification.

The inspected companion exports scoped directories and byte-preserving names,
held/named identities, volume observations, owned advisory leases, dataless
policy scopes, pinned source reads, metadata observations/application, private
writers, independent read-back and exclusive publication with separate
barrier results. ExaCopy must translate these observations into its existing
strict admission policy and persisted records. The presence of each API does
not establish that the full consumer migration has passed.

The first integration can delegate ACL/GUID, xattr/fork, volume, filesystem
identity, materialization policy and stored-name queries independently of
writer ownership. Required fidelity remains unchanged: visible attributes,
including `com.apple.provenance`, cannot be ignored to obtain a passing copy.

**Remaining full-port seams**

- **Owning source and stage capabilities.** `PinnedSource` borrows its root
  and entry name; the writer lifecycle also retains borrowed locations.
  ExaCopy constructs names during open/create and returns owning capabilities.
  An owned-name/owned-root variant or a consumer scope redesign is needed;
  a wrapper must not become self-referential or use unsafe lifetime extension.
  The current `Lease` already owns its independently opened descriptor and
  named binding, so lease ownership is no longer a missing capability.
- **Appendable private records.** `PrivateWriter` has a declared final extent
  and performs its full-file barrier while consuming and closing the writer.
  The authoritative journal needs a confirmed new empty inode, bounded growth,
  a full-file barrier after each frame, and later same-inode read/write reopen
  at an accepted extent. The current first-segment bound is 64 MiB. Pomologie
  can expose generic bounded private-file operations; ExaCopy keeps frame
  encoding, accepted-prefix validation, chain heads and intent ordering.
  Read-only recovery inventory alone does not provide append authority.
- **Metadata of the actual held source.** Scalar captured source metadata is
  available, but the consumer must also bracket current timestamps and strict
  ACL/GUID/xattr/fork observations against that same held inode. A scoped safe
  observation method can supply this without opening a second source by name.
  Post-metadata and post-publication checks also retain the complete ExaCopy
  predicate rather than only the library's baseline writer checks.
- **Birth-time changes during metadata application.** APFS can change birth
  time when applying an earlier modification time. The companion returns the
  resulting live identity. ExaCopy's existing prepared-stage journal identity
  includes birth time and sealing requires it to remain equal. The current
  protocol must refuse an identity change while retaining the artifact, or
  adopt an explicit compatible record/replay transition. Dropping the birth
  field or substituting the earlier identity would hide the discrepancy.
- **Diagnostic and effect preservation.** Unknown volume capabilities remain
  refusals. If an API collapses a native unsupported error into `Unknown`, its
  original errno is unavailable to the consumer. Dataless restoration failure
  must retain an already-observed filesystem effect and the original cause.
  Query ordering must preserve a known unsupported metadata condition even
  when a later independent query fails.

These are reusable filesystem capability requirements. None requires
Pomologie to depend on ExaCopy's model, journal format or publication policy.

**Existing libraries**

`mach2` 0.7.0 provides Mach user-space interfaces such as ports, tasks, virtual
memory and Mach thread policies. The attribute, xattr, rename and VFS
materialization calls above use Darwin filesystem interfaces. Its Mach
thread-policy module does not supply `getiopolicy_np` or `setiopolicy_np`.
[mach2 API](https://docs.rs/mach2/0.7.0/mach2/)

`fs4` 1.1.0 provides file locks, allocation and filesystem space information.
Its Unix locking implementation calls `rustix::fs::flock`, which ExaCopy
already uses through a safe API. It can serve a broader convenience API in
Pomologie, but it does not supply the mounted capabilities below. Space
statistics also cannot establish real object identity or reserve capacity
against concurrent allocation. [fs4 API](https://docs.rs/fs4/1.1.0/fs4/)
[fs4 Unix implementation](https://docs.rs/fs4/1.1.0/src/fs4/unix.rs.html)

Pinned `rustix` already covers descriptor-relative filesystem operations,
stat calls, advisory locks, timestamp updates,
directory synchronization and Darwin full-file synchronization. It also
covers exclusive rename with retained Darwin flags. A safe entropy API can
replace the nonce call. Both direct unsafe calls were removed before
extraction. Checked consuming close still needs an API that returns the
actual close failure. Ordinary destructor completion cannot establish that
result. Library selection should preserve each operation's exact semantics.
Positioned file reads and writes currently use Rust's Unix `FileExt` methods
with ExaCopy's bounded short-I/O loops.
[Pinned rustix Apple rename implementation](https://github.com/bytecodealliance/rustix/blob/4a563ad698b2c20ff848515821023d2265a788d0/src/backend/libc/fs/syscalls.rs#L585-L624)

**Required mounted capabilities for the current copy slice**

1. **Mount and volume observations.** Accept a held directory and report
   filesystem type, local or remote state, ownership/permission support,
   ACL support, advisory lock support and exclusive rename support. Preserve
   the distinction between a supported capability and an unavailable or
   invalid capability bit. ExaCopy selects its currently admitted managed
   APFS profile.

2. **Native object identity.** Observe a held object and a single relative
   name without following a final symlink. Return native device, real FSID,
   nonzero inode, optional generation and normalized birth time. A zero
   generation means unavailable. Include enough observations to detect a
   rebound name, mount transition and changed object. Where the original
   name remains authorized, recheck its relationship to the held parent.
   A held root can remain the same object after its original path is renamed.
   A live mount identity needs fresh validation after reopening. Any stable
   volume UUID is a separate field with separately documented semantics.

3. **Scoped directory handles and names.** Accept already authorized
   directory handles, validate one raw component, and perform relative
   lookup, open, exclusive creation and directory creation. Preserve bytes.
   Reject traversal and unwanted link following. Expose the actual stored
   spelling for private fixed names. A public case alias counts as an
   occupied destination. Return event-only identity anchors when observing
   an occupied object must leave its payload unopened.

   The current managed grant assumes a non-root owner, owner-private
   `0700` roots with an explicit empty ACL, protected ancestors, cooperating
   writers, and the exclusion of remote mounts, automounts and File Provider
   namespaces. Its mutation scope also constrains descriptor inheritance
   while a stage writer is live. These are explicit provisioning and caller
   assumptions. They do not follow from accepting an arbitrary path.

4. **Shared and exclusive advisory leases.** Provide nonblocking typed
   acquisition, busy results, revalidation and process-aware release.
   Independently opened handles and inherited handles need explicit
   lifetime semantics. Document that advisory leases require cooperating
   writers. They cannot establish a snapshot or exclude arbitrary writers.

5. **Dataless behavior.** Permit metadata observation and bounded file
   access with automatic materialization disabled. Establish and verify
   the calling thread's policy, keep the scope on that thread, verify
   restoration on normal return, and attempt restoration during unwind.
   Report normal-path restoration failures. Preserve any already-observed filesystem effect when policy
   restoration fails. Return an explicit unavailable-content result when
   data cannot be read under the selected policy.

6. **Pinned source reads.** Open a selected regular file read-only under
   a held root, record its logical length and metadata, and provide bounded
   positioned reads that handle short progress and bounded interruption
   internally, returning exact success or typed bounds, EOF, I/O and change
   failures. Revalidate the held object and selected name before and after
   relevant operations. Describe the observation as live unless the
   library supplies an independently qualified immutable view.

7. **General metadata observations.** Expose type, length, owner/group,
   permissions, link count, BSD flags, access/modification/change/birth
   times, extended-security presence and contents, xattr names and values,
   compression-visible attributes, FinderInfo and resource forks. Use
   bounded reads and pagination where required. The present copy profile
   needs complete inventory and presence/absence evidence. Attribute values
   and richer typed metadata enable later fidelity profiles. Distinguish verified
   absence, empty data, partial visibility, unsupported representation,
   permission denial and I/O failure. Preserve opaque bytes where their
   interpretation is unnecessary.

   ExaCopy's current basic profile accepts a one-link regular file with
   mode `0600`, zero BSD flags, no visible xattrs, no ACL entries or extended
   security GUIDs, and no resource fork. The library should expose facts
   broadly. ExaCopy owns this admission policy. The observed
   `com.apple.provenance` attribute remains a real metadata condition.

8. **Metadata application.** The immediate slice needs captured access and
   modification times applied to held private files, read-back of the result,
   correct permissions at creation, and empty-ACL provisioning for newly
   created private directories. Ownership/mode changes, rich xattrs, forks,
   ACLs and flags belong to later profiles with explicit capability and
   fidelity results. A system-managed
   attribute that cannot be recreated must produce a visible limitation.

9. **Private file lifecycle.** Exclusively create private files and
   directories beneath a held directory. Provide a sole owned writer,
   bounded positioned writes, a full-file barrier,
   checked consuming close and an independent read-only reopen of the same
   inode. Preserve uncertain creation outcomes and existing entries. The
   library supplies mechanisms. ExaCopy chooses its private layout,
   determines completion and computes the independent content digest.

10. **Precise barriers.** The current slice requires Darwin `F_FULLFSYNC`
    and directory synchronization with typed outcomes. Keep ordinary file
    synchronization distinct if that operation is also offered.
    ExaCopy sequences barriers for owner files, plans,
    journal segments, stages and receipts. Its journal currently calls
    `rustix::fs::fcntl_fullfsync` directly, so that caller is part of the
    integration accounting. A returned barrier result alone cannot certify
    hardware power-loss recovery.

11. **Exclusive publication.** Perform relative exclusive rename with
    the required no-follow behavior. Report conflict, uncertain effect,
    confirmed rename and incomplete post-rename evidence distinctly.
    Revalidate the target and former private name against the held inode.
    Expose the operations for both affected directory barriers and retain
    their individual outcomes. ExaCopy owns the intent-before-effect ordering,
    consumes its model authorization before calling the primitive, and decides how an
    ambiguous outcome enters reconciliation.

12. **Read-only recovery inventory.** Reopen bounded private records and
    inventory selected private/public names under freshly authorized held
    directories. Report present, absent and inconclusive independently.
    Preserve pending artifacts. Permit explicit private-stage read-back
    bound to the expected live inode, extent, EOF and metadata. Namespace
    inspection should offer an event-only path without opening public
    target payloads. Persisted identity bytes never manufacture a live handle.

**ExaCopy responsibilities after extraction**

- User grants, permitted roots, metadata policy and operation selection.
- Job IDs, entry IDs, epochs, private names and directory layout.
- The preserve-mode state machine and publication authorization.
- BLAKE3 source and read-back measurements and acceptance decisions.
- Ed25519 ownership, key handling, canonical record encodings and receipts.
- Journal append ordering and interpretation of synchronized intent.
- Replay, conflict classification, resume/retry and reconciliation decisions.
- Application error mapping, CLI output and reported assurance levels.

The integration adapter translates Pomologie observations into existing
ExaCopy identity and metadata records. Pomologie should remain independent
of ExaCopy's model and journal crates. Library extraction must preserve
existing persisted bytes or introduce an explicit compatible transition.

**Further APFS representation and future ExaCopy use**

| Capability | Current Pomologie reader evidence | ExaCopy use |
| --- | --- | --- |
| Xattrs, forks and FinderInfo | Implemented for documented native storage profiles. | Extend metadata fidelity and use immutable images as independent fixtures. |
| Hard links | Ordinary regular-file sibling/name validation is implemented. | Preserve a multi-file link graph when the transfer profile supports it. |
| Sparse files | An explicitly qualified sparse profile is implemented. | Preserve logical content immediately, physical sparseness through a later capability. |
| Name equivalence | Bytewise and admitted Unicode 9 normalized/folded lookup are implemented. | Image lookup and differential fixtures. The mounted destination kernel determines actual namespace collisions. |
| Clones and shared extents | Reader currently refuses these payload profiles. | Read ordinary cloned source files and later qualify clone-assisted copying. |
| Compression | Reader currently refuses compressed payloads. | Read logical bytes with declared metadata fidelity and materialization behavior. |
| Snapshots | Snapshot processing remains outside the current reader profile. | Bind source reads to an identified immutable view with lifetime and permissions evidence. |
| Encryption and broader volume consistency | Outside the ordinary unencrypted reader profile. | Extend admitted image sources and capability reports when separately implemented. |

These are separate milestones for a fully representative APFS library.
The mounted copy slice can progress independently of a raw allocator,
checkpoint writer or block-level transaction engine. The image stack owns
those additional APFS internals and their proofs.

**Acceptance evidence for the extraction**

Run the existing native cases through the Pomologie API and the ExaCopy
adapter. Exercise relative-name changes, case
aliases, links, busy leases, metadata visibility, short
I/O, changed extents, close failure, full-file and directory barrier
failure, late incumbents, rename outcomes and retained private artifacts.
Test thread-policy restoration after success, failure and unwind.
Genuine dataless files and cross-volume substitutions require additional
native qualification fixtures. Their absence remains visible in the results.

Include independent native observations for metadata and identities.
Use synthetic redistributable images to compare mounted observations
with Pomologie's raw reader where its profile admits them. Preserve
unknown and unavailable outcomes. Keep native adapter, process-crash
and hardware power-loss qualification as separate evidence.

The current strict APFS end-to-end fixture stops at extended-attribute
admission. Moving that implementation into Pomologie preserves this
status until an eligible fixture or a qualified richer metadata profile
establishes the required fidelity.

Implementation references are the [current adapter contract](../local-adapter.md),
[managed identity observation](../../crates/endpoints/platform/src/macos/managed/observation.rs),
[publication primitive](../../crates/endpoints/platform/src/macos/publication/native.rs)
and [journal barrier](../../crates/storage/journal/src/durable.rs).

**Local development integration**

The current checkouts are siblings under `replicraft/`. A Cargo path
dependency can consume the companion directly while both repositories
retain their own workspaces and Git histories. The companion package now
exists at the following path; these declarations remain the consumer
integration plan at the checkpoint above.

In ExaCopy's root `Cargo.toml`, extend the existing dependency table.

```toml
[workspace.dependencies]
apfs-mounted = { path = "../pomologie/apfs/crates/platform/apfs-mounted", default-features = false }
```

In the consuming platform package, extend its existing macOS table.

```toml
[target.'cfg(target_os = "macos")'.dependencies]
apfs-mounted.workspace = true
```

Cargo reads the package's `Cargo.toml` at the named directory and rebuilds
changed dependency source. The dependency retains its own workspace
inheritance. ExaCopy uses its root lockfile for the resolved build.
The package exists in the inspected local revision. Supply that source to
clean-room builds before enabling the dependency.
[Cargo path dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)

After the first API slice is available, integrate it through thin ExaCopy
wrappers implementing the existing endpoint contracts. Update the dependency
matrix, feature and suitability inventories, lockfile and owning native
tests with that slice. Keep the experimental copy admission gates in place
through qualification.

Record both repository revisions for native integration evidence. Path
dependencies have mutable source, and the lockfile records their package
version without pinning the checkout's contents. A dirty library checkout
needs its changed-source evidence. CI must supply the sibling checkout in
the same relative layout, or use a separately reviewed commit-pinned source.
Cargo dependency resolution may need the sibling manifest even when the
current build target excludes macOS code.

**Commit-pinned Git integration**

Once the companion package is available in its repository, replace the path
entry with the Git source and a reviewed full commit hash. The example uses
the repository URL declared by the inspected Pomologie workspace.

```toml
[workspace.dependencies]
apfs-mounted = { git = "https://github.com/pomologie/apfs", rev = "<full-commit-sha>", default-features = false }
```

The consuming package continues to inherit `apfs-mounted.workspace = true`
in its macOS dependency table. Cargo locates the named package in the Git
repository. Update and commit the ExaCopy lockfile and provenance inventories
with the resolved revision and run the affected native integration tests.
The Git entry is an integration plan until the package and revision exist.

During local development, a workspace-root override can select the sibling
source while the normal dependency declaration remains commit-pinned.

```toml
[patch."https://github.com/pomologie/apfs"]
apfs-mounted = { path = "../pomologie/apfs/crates/platform/apfs-mounted" }
```

The local package version must satisfy the consumer's dependency requirements.
The resulting lockfile and native evidence identify that local-source run.
[Cargo Git dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories)
[Cargo dependency overrides](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#the-patch-section)
