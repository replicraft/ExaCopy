# Single-file verification, publication, and replay

`exacopy-content` owns bounded standard BLAKE3-256 stream measurement. `exacopy-transfer` owns Linux copy sequencing, its private plan and receipt, and journal replay. `exacopy-journal` owns framing, canonical payloads, and signed owner records. `exacopy-diff` provides read-only byte comparison for the Linux command line.

| Scope | Requirements and acceptance cases | Invariants |
| --- | --- | --- |
| Private write, quiescence, and independent BLAKE3 read-back | R-007/A-007, R-018/A-018, R-021/A-021, R-023/A-023, R-025/A-025 | INV-001, INV-002, INV-003, INV-004, INV-013 |
| Live source observation and selected native metadata | R-016/A-016, R-026/A-026, R-043/A-043, R-062/A-062 | INV-003, INV-005, INV-019, INV-020 |
| Signed ownership, framed records, and first durable intent prerequisites | R-039/A-039, R-040/A-040, R-041/A-041, R-045/A-045 | INV-006, INV-009, INV-019 |

## Verified private stage

The transfer reads the held regular file in logical order into bounded caller-owned scratch. It hashes the bytes actually read while writing the private stage. It checks for observable source changes, sets the exact stage length, flushes the stage, and drops its writer. A separately opened read-only descriptor verifies the stage by reading its logical bytes and independently computing BLAKE3. The operating system can serve that read through its cache. The source is live observed, and stage verification is digest read-back.

The Linux baseline checks that source attributes can be inspected and no extended attribute names are visible. It refuses special mode bits and incompatible stage ownership. It preserves ordinary permissions, UID/GID by equality with the new inode, and the captured access and modification times. Hidden attributes, link topology, sparse allocation and the inode change time fall outside this fidelity profile. A hash match never upgrades the source or metadata claim.

`stage_verified` returns a `VerifiedStage` with the pinned stage and its `ReadyToPublish` model state. It exposes phase, length, identity, and digest. The copy coordinator uses the same staging path and records `EntryPrepared` before writing any stage data. Its source consistency checks include a bounded EOF probe at the recorded length. A copy, metadata, or prepublication barrier failure leaves any allocated stage private.

## Versioned private job evidence

The already authorized destination can create a new owner-private job directory. Its capabilities exclusively create `owner.cbor`, `journal/`, the first segment `journal/00000000000000000001.exajnl`, and `stage/`. `PreparedJob` writes the signed owner file, requests its file barrier, and synchronizes the segment entry and both enclosing namespace levels. It then writes a canonical `JobPrepared` frame binding the signed owner digest, canonical plan digest, capability UUID and held destination identity. The writer only returns evidence after `sync_all` succeeds. Any failure preserves the entries already created, and an existing job name cannot be adopted by bootstrap.

The initial local owner profile uses strict Ed25519 verification over `ExaCopy/owner/v1\0` followed by the exact deterministic CBOR body. Verification requires the independently expected profile and key. Linux device and inode are stored as fixed little-endian values with unavailable generation recorded explicitly. A persisted identity is an observation and requires revalidation after reopening.

The `EXAJNL01` frame codec bounds payloads before allocation, checks version and kind, and verifies CRC32C and a domain-separated BLAKE3 predecessor chain. The reader stops at corruption or an incomplete trailing record and retains the last verified boundary. It never searches for later magic. The kind-7 verification reference is a domain-separated digest of the complete canonical kind-5 payload.

## Publication and recovery evidence

`plan_new_file` observes a regular source and an absent target under caller-authorized roots. Its private v1 CBOR plan binds the root capabilities, device and inode observations, raw components, logical length, modification and change times, and the fixed verification and metadata policies. Applying the plan reopens the source under the same authorization and checks those observations again. The coordinator synchronizes the plan and signed owner artifacts before the preparation frame. The caller supplies the trusted local profile key and fresh ownership token.

The coordinator journals the stage seal, independent measurements, and required metadata. It obtains the model's publication token only after synchronizing the exact `PublishIntent` frame. Linux `renameat2(RENAME_NOREPLACE)` decides whether publication wins against an incumbent. After a successful rename, the adapter synchronizes both directories and checks the target identity and absence of the former private name. The coordinator records those observations, synchronizes `receipts/receipt.cbor` and its directory chain, and synchronizes `ReceiptCommitted`. The receipt claims a live-observed source, buffered independent read-back, baseline metadata, and completed barrier calls. Filesystem power-loss qualification remains unconfirmed.

Read-only recovery handles reopen fixed private records and inspect stage and target names under the caller's destination handle. Replay validates the exact local record order and cross-checks ownership, plan, identities, measurements, and receipt references. It distinguishes clean early EOF, a torn trailing frame, and a rejected chain. Inspection holds a shared job lease while it validates the profile signature, rebinds current objects, and freshly measures the known stage or published stream. It identifies conflicting targets, incomplete publication or receipts, and verified committed jobs. Automatic repair and resume remain open. [Linux advisory locking](https://man7.org/linux/man-pages/man2/flock.2.html)

The process-kill tests stop the actual copy process at six boundaries from synchronized preparation through receipt commitment. A separate late-incumbent test introduces a target after synchronized intent and checks the original inode, private stage, and incumbent. These experiments exercise a running kernel and its caches. Power-loss qualification needs storage fault evidence.

## Checks

```sh
cargo nextest run --locked -p exacopy-content -p exacopy-journal
cargo test --locked -p exacopy-platform -p exacopy-transfer
```

The native tests use private Linux fixtures. The [journal frame fuzz target](../crates/storage/journal/fuzz/README.md) independently checks framing boundaries under AddressSanitizer.
