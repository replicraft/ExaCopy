# Single-file verification, publication, and replay

`exacopy-content` owns bounded standard BLAKE3-256 stream measurement. `exacopy-transfer` owns Linux copy sequencing, its private plan and receipt, and journal replay. `exacopy-journal` owns framing, canonical payloads, and signed owner records. `exacopy-diff` provides read-only byte comparison on Linux and managed APFS.

| Scope | Requirements and acceptance cases | Invariants |
| --- | --- | --- |
| Private write, quiescence, and independent BLAKE3 read-back | R-007/A-007, R-018/A-018, R-021/A-021, R-023/A-023, R-025/A-025 | INV-001, INV-002, INV-003, INV-004, INV-013 |
| Live source observation and selected native metadata | R-016/A-016, R-026/A-026, R-043/A-043, R-062/A-062 | INV-003, INV-005, INV-019, INV-020 |
| Signed ownership, framed records, and first durable intent prerequisites | R-039/A-039, R-040/A-040, R-041/A-041, R-045/A-045 | INV-006, INV-009, INV-019 |
| Flush-backed range checkpoints and immutable pages | R-042/A-042 | INV-006, INV-009 |
| Explicit reuse of eligible live-observed ranges under a fresh epoch | R-043/A-043 | INV-003, INV-020, INV-024 |

## Verified private stage

The transfer reads the held regular file in logical order into bounded caller-owned scratch. It hashes the bytes actually read while writing the private stage. It checks for observable source changes, sets the exact stage length, flushes the stage, and drops its writer. A separately opened read-only descriptor verifies the stage by reading its logical bytes and independently computing BLAKE3. The operating system can serve that read through its cache. The source is live observed, and stage verification is digest read-back.

The Linux baseline checks that source attributes can be inspected and no extended attribute names are visible. It refuses special mode bits and incompatible stage ownership. It preserves ordinary permissions, UID/GID by equality with the new inode, and the captured access and modification times. Hidden attributes, link topology, sparse allocation and the inode change time fall outside this fidelity profile. A hash match never upgrades the source or metadata claim.

`stage_verified` returns a `VerifiedStage` with the pinned stage and its `ReadyToPublish` model state. It exposes phase, length, identity, and digest. The copy coordinator uses the same staging path and records `EntryPrepared` before writing any stage data. Its source consistency checks include a bounded EOF probe at the recorded length. A copy, metadata, or prepublication barrier failure leaves any allocated stage private.

On managed APFS, `copy_verified_stage` streams the authorized source into an unwritten private stage of the same length with at most 1 MiB of caller-owned scratch. It independently reads and hashes the closed stage after the file barrier, then revalidates the source. A successful result owns the verified private stage and its digest. An error carries the allocated stage identity for reconciliation. Required metadata, the durable journal and publication are separate coordinator work.

`copy_with_basic_metadata` checks strict source metadata before streaming and uses the same source capability to apply and confirm metadata on the independently verified stage. The stage stays private and retains its digest and binding for the journal coordinator.

## Versioned private job evidence

The already authorized destination can create a new owner-private job directory. Its capabilities exclusively create `owner.cbor`, `journal/`, the first segment `journal/00000000000000000001.exajnl`, and `stage/`. `PreparedJob` writes the signed owner file, requests its file barrier, and synchronizes the segment entry and both enclosing namespace levels. It then writes a canonical `JobPrepared` frame binding the signed owner digest, canonical plan digest, capability UUID and held destination identity. The writer only returns evidence after `sync_all` succeeds. Any failure preserves the entries already created, and an existing job name cannot be adopted by bootstrap.

The initial local owner profile uses strict Ed25519 verification over `ExaCopy/owner/v1\0` followed by the exact deterministic CBOR body. Verification requires the independently expected profile and key. Linux device and inode are stored as fixed little-endian values with unavailable generation recorded explicitly. A persisted identity is an observation and requires revalidation after reopening.

The managed APFS owner codec has an explicit profile version and a distinct Ed25519 signature domain. Its signed claims bind the job and plan to a Darwin device, physical FSID, inode and the non-root owner's UID. The codec records unavailable inode generation as null and retains birth time as a supporting observation. Both decoders enforce their selected profile, and the Linux v1 golden bytes remain valid. A future Darwin coordinator must validate live directory authority and identity before using the authenticated claims to prepare or recover a job.

The managed APFS plan binds the profile and job, source and destination grants, raw names, native identities, source extent and strict basic metadata. The job directory name derives from the job UUID. The journal binds the actual private stage name and identity after exclusive creation. The Darwin plan uses its own canonical version and digest domain.

The Darwin preparation records use kinds 1 and 2 under the managed APFS payload profile. The job record binds the signed owner digest and held destination. The entry record binds the source and its holding directory, the stage inode and its parent, the stage ID and raw component, and the observed absence of the exact public target. The record association also checks the owner, plan and run context.

The `EXAJNL01` frame codec bounds payloads before allocation, checks version and kind, and verifies CRC32C and a domain-separated BLAKE3 predecessor chain. The reader stops at corruption or an incomplete trailing record and retains the last verified boundary. It never searches for later magic. The kind-7 verification reference is a domain-separated digest of the complete canonical kind-5 payload.

The journal writer holds its selected file barrier for the lifetime of an open segment. The standard writer uses `File::sync_all`. A Darwin caller can select `F_FULLFSYNC` for each append and for the prefix check when resuming. Failed barriers leave the written bytes available for reconciliation and retire the writer. A successful call identifies the requested barrier. Filesystem qualification still depends on the relevant namespace and storage evidence. [Darwin file barrier](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)

## Range checkpoints

During a journaled copy, the synchronous stage writer measures consecutive ranges of the unnamed stream. A range ends at 64 MiB or at the first completed read after two seconds. The writer finishes that chunk, checks the source observation and flushes the held stage. It then exclusively creates and synchronizes the canonical page in the owner-approved `checkpoints/` directory before synchronizing the kind-3 journal frame. The page includes the range bounds and BLAKE3 digest. The journal binds its ordinal, exact encoded length, domain-separated page digest, and the measurement identifier derived from the original `EntryPrepared` payload.

The local profile records up to 4,096 ranges. The remaining bytes still feed the whole-file digest and go through the independent stage read-back. Recovery resolves only pages referenced by an accepted journal prefix. It checks their digest, source observation, ordinal, and contiguous coverage within the prepared extent. A process interruption can leave a synchronized page without a journal reference. That page remains private and contributes no accepted evidence.

Current readers accept earlier local jobs without the checkpoint directory. New local plans use the existing plan and receipt encodings, and their signed owner record allows the additional directory. Older recovery readers refuse that layout and do not accept the new stage checkpoint sequence.

## Publication and recovery evidence

`plan_new_file` observes a regular source and an absent target under caller-authorized roots. Its private v1 CBOR plan binds the root capabilities, device and inode observations, raw components, logical length, modification and change times, and the fixed verification and metadata policies. Applying the plan reopens the source under the same authorization and checks those observations again. The coordinator synchronizes the plan and signed owner artifacts before the preparation frame. The caller supplies the trusted local profile key and fresh ownership token.

The coordinator journals the stage seal, independent measurements, and required metadata. It obtains the model's publication token only after synchronizing the exact `PublishIntent` frame. Linux `renameat2(RENAME_NOREPLACE)` decides whether publication wins against an incumbent. After a successful rename, the adapter synchronizes both directories and checks the target identity and absence of the former private name. The coordinator records those observations, synchronizes `receipts/receipt.cbor` and its directory chain, and synchronizes `ReceiptCommitted`. The receipt claims a live-observed source, buffered independent read-back, baseline metadata, and completed barrier calls. Filesystem power-loss qualification remains unconfirmed.

Read-only recovery handles reopen fixed private records and inspect stage and target names under the caller's destination handle. Replay validates the exact local record order and cross-checks ownership, plan, identities, measurements, and receipt references. It distinguishes clean early EOF, a torn trailing frame, and a rejected chain. Inspection holds a shared job lease while it validates the profile signature, rebinds current objects, and freshly measures the known stage or published stream. It identifies conflicting targets, incomplete publication or receipts, and verified committed jobs. [Linux advisory locking](https://man7.org/linux/man-pages/man2/flock.2.html)

For a clean accepted journal and an already-published target, `recover finish` holds an exclusive job lease, verifies the current names and stream again, and reopens the original segment for bounded append. The segment's complete accepted bytes are read and synchronized before it appends anything. Each recovery generation records the exact active intent, predecessor, owner, and freshly checked target before requesting barriers or committing missing receipt evidence. An interrupted generation can be followed by a new one, and a committed receipt is terminal.

`recover retry` addresses R-039, R-041, R-045 and INV-003, INV-006, INV-009 and INV-024 for a retained sealed stage. A current, independently supplied source grant must match the signed plan. Recovery checks the held source identity, metadata, extent, EOF, and full BLAKE3 against the original evidence. It synchronizes and independently rereads the private stage and revalidates required metadata, including access time. The first recovery decision records the current checked stage-directory identity under the signed job root. Later decisions must match it.

For a retry, the journal appends kinds 19, 5, 6, 20, and 7 in order. Kind 20 uses a distinct retry discriminator and reserves a new sequence even if interrupted before kind 7. The existing already-published decision encoding remains readable. The previous intent remains active until a new compatible kind 7 is accepted. That new intent binds the fresh verification digest, and Linux publication requires the model's one-shot authorization after synchronization. Publication observations, barriers, and the receipt refer to that active effect. Replay rejects contradictory evidence and preserves torn segments.

## Resume a checkpointed Linux copy

`recover resume` explicitly authorizes continuing a retained copy with the original source-root grant. The supported job has a clean pre-intent journal, a matching private single-link stage, and an absent target. The engine checks the source root, inode, extent, change and modification times, permissions, ownership, and link count. Observable source changes require a fresh copy plan. The original access time remains the selected metadata even if source reads have since advanced it.

Under an exclusive lease, a synchronized pre-intent kind-19 record binds the fresh run epoch to the exact original preparation frame, predecessor, authenticated owner, private stage and stage directory. Its four-field body has a local resume discriminator. The legacy post-intent three-field body retains its encoding. Older checkpoint readers refuse the pre-intent kind-19 record. The single-segment writer reserves 16 KiB for a new attempt and its completion records. The old epoch's seal, verification and metadata supply no authority for the new run.

With a writable `0600` stage, the resume worker reuses a range only when the original digest matches both held stage bytes and freshly read source bytes. It rewrites damaged, missing and uncheckpointed ranges, including the whole file when the journal has no checkpoint. A second source read for rewriting must agree with the first read of that range. The entire source contributes to a new BLAKE3 digest. The private writer closes after flushing, and a separately opened stage descriptor must read back the same complete stream.

If a crash left the stage in the planned mode with the full source length, the engine opens a read-only data handle and compares fresh full-stream source and stage digests before writing a new resume record. Agreement permits it to finish and verify the planned metadata on the same inode. The stage contents stay untouched. Both paths synchronize intent before an exclusive rename. The receipt reports `live_observed` source consistency.

A new resume can recheck the original pages or reverify a fully copied stage after an interrupted pre-intent attempt. Once a publication intent exists, `recover retry` or `recover finish` handles its outcome. An unresolved or torn history remains available for inspection.

The process-kill tests cover synchronized preparation through receipt commitment, including the range page and its journal reference. They also stop a partial resume after its start record, after the data flush, and after its intent. Retained-publication retry has separate kill cases after decision, intent and rename. Late-incumbent tests exercise preservation at exclusive publication. These experiments exercise a running kernel and its caches. Power-loss qualification needs storage fault evidence.

## Checks

```sh
cargo nextest run --locked -p exacopy-content -p exacopy-journal
cargo test --locked -p exacopy-platform -p exacopy-transfer
```

The native tests use private Linux fixtures. The [journal frame fuzz target](../crates/storage/journal/fuzz/README.md) independently checks framing boundaries under AddressSanitizer.
