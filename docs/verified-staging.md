# Single-file verification and journal preparation

`exacopy-content` owns bounded standard BLAKE3-256 stream measurement. `exacopy-transfer` owns the sequencing of one private Linux stage and the initial persisted job. `exacopy-journal` owns the bounded frame, canonical payload, and signed owner codecs. This work implements parts of the architecture pack's PR 3 and PR 4 packages.

| Scope | Requirements and acceptance cases | Invariants |
| --- | --- | --- |
| Private write, quiescence, and independent BLAKE3 read-back | R-007/A-007, R-018/A-018, R-021/A-021, R-023/A-023, R-025/A-025 | INV-001, INV-002, INV-003, INV-004, INV-013 |
| Live source observation and selected native metadata | R-016/A-016, R-026/A-026, R-043/A-043, R-062/A-062 | INV-003, INV-005, INV-019, INV-020 |
| Signed ownership, framed records, and first durable intent prerequisites | R-039/A-039, R-040/A-040, R-041/A-041, R-045/A-045 | INV-006, INV-009, INV-019 |

## Verified private stage

The transfer reads the held regular file in logical order into bounded caller-owned scratch. It hashes the bytes actually read while writing the private stage. It checks for observable source changes, sets the exact stage length, flushes the stage, and drops its writer. A separately opened read-only descriptor verifies the stage by reading its logical bytes and independently computing BLAKE3. The operating system can serve that read through its cache. The source is live observed, and stage verification is digest read-back.

The Linux baseline checks that source attributes can be inspected and no extended attribute names are visible. It refuses special mode bits and incompatible stage ownership. It preserves ordinary permissions, UID/GID by equality with the new inode, and the captured access and modification times. Hidden attributes, link topology, sparse allocation and the inode change time fall outside this fidelity profile. A hash match never upgrades the source or metadata claim.

`VerifiedStage` holds the pinned stage and its `ReadyToPublish` model state. It exposes phase, length, identity and digest. Production publication needs further journaled evidence and authorization. This work never creates the copy target. A copy, metadata or barrier failure leaves any allocated stage private.

## Versioned private job evidence

The already authorized destination can create a new owner-private job directory. Its capabilities exclusively create `owner.cbor`, `journal/`, the first segment `journal/00000000000000000001.exajnl`, and `stage/`. `PreparedJob` writes the signed owner file, requests its file barrier, and synchronizes the segment entry and both enclosing namespace levels. It then writes a canonical `JobPrepared` frame binding the signed owner digest, canonical plan digest, capability UUID and held destination identity. The writer only returns evidence after `sync_all` succeeds. Any failure preserves the entries already created, and an existing job name cannot be adopted by bootstrap.

The initial local owner profile uses strict Ed25519 verification over `ExaCopy/owner/v1\0` followed by the exact deterministic CBOR body. Verification requires the independently expected profile and key. Linux device and inode are stored as fixed little-endian values with unavailable generation recorded explicitly. A persisted identity is an observation and requires revalidation after reopening.

The `EXAJNL01` frame codec bounds payloads before allocating, enforces version and kind, and checks CRC32C and domain-separated BLAKE3 predecessor chaining. The reader stops at corruption or an incomplete trailing record and retains the last verified boundary. It never searches for later magic. The local canonical codecs support `JobPrepared`, `EntryPrepared`, `StageSealed`, `VerificationRecorded`, `MetadataRecorded`, and `PublishIntent`. The kind-7 verification reference is a domain-separated digest of the complete canonical kind-5 payload. These codecs describe observations. They do not manufacture effect authority from bytes on disk.

The current bootstrap is an application-library entry point. Profile-key custody, canonical plan persistence, the coordinator's append and publication sequence, CLI receipts, and restart reconciliation remain separate work. Completed barriers in the tested adapter do not establish a power-loss profile.

## Checks

```sh
cargo nextest run --locked -p exacopy-content -p exacopy-journal
cargo test --locked -p exacopy-platform -p exacopy-transfer
```

The native tests use private Linux fixtures. The [journal frame fuzz target](../crates/storage/journal/fuzz/README.md) independently checks framing boundaries under AddressSanitizer.
