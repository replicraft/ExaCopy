# PR 2. Linux local adapter and fault simulator

`exacopy-endpoint` owns checked positioned I/O and lossless local name validation. `exacopy-platform` owns the Linux descriptor boundary. `exacopy-test-support` owns the independent in-memory filesystem used in tests. The work package uses ADR-013, ADR-014, ADR-019, ADR-020, ADR-021, ADR-031 through ADR-033, and ADR-071 from the local architecture pack.

| Scope | Requirements and acceptance cases | Invariants |
| --- | --- | --- |
| Held read-only scope, regular-file selection and identity | R-007/A-007, R-016/A-016, R-024/A-024, R-049/A-049, R-058/A-058, R-059/A-059, R-067/A-067 | INV-001, INV-005, INV-013, INV-016, INV-019 |
| Private stage and positioned writes | R-018/A-018, R-019/A-019, R-021/A-021, R-022/A-022, R-023/A-023, and the adapter portion of R-025/A-025 | INV-002–005, INV-013 |
| Exclusive publication, barriers and uncertain outcomes | R-008/A-008, R-013/A-013, R-015/A-015, R-027/A-027, R-028/A-028, R-045/A-045 | INV-002, INV-003, INV-006, INV-009, INV-019 |
| Fault simulation and platform evidence | R-056/A-056, R-184/A-184, R-328/A-328 | INV-020, INV-032 |

## Common operation contract

Positioned I/O validates the whole byte range against the signed 64-bit file extent before touching the backend. A partial call advances only by its confirmed count, and an interruption retries at the same position. Sixteen consecutive retries without progress return the original OS error. Early EOF, zero progress during writes and counts larger than the supplied suffix have separate errors. An I/O failure can leave the buffer or private stage partially changed. All storage handles remain private and an operation returns only after its synchronous request completes.

The Unix component type preserves raw bytes and accepts at most 255 bytes. It rejects NUL, slash, empty names, `.` and `..`. The Windows adapter will require its own lossless UTF-16 component and handle rules. Exclusive new-name publication and independently reported barriers are common requirements. Linux uses `RENAME_NOREPLACE` and `fsync` on held directories. The specified Windows and macOS candidates use their corresponding handle-based and exclusive rename primitives and require separate native evidence.

## Linux authority and ordering

The caller supplies already authorized directory handles. Source selection pins one child with `openat2`, refuses symlinks and mount crossings, and rejects special files before opening a stream. The read-only descriptor is reopened through the calling thread's validated procfs descriptor directory and checked against the pinned device and inode. This assumes a trusted Linux kernel and mount namespace through reopen. A device and inode pair is used for comparison while both objects are held. Persisted identity and live source snapshot semantics require separate contracts. Read access may update atime.

The destination parent belongs to the effective user. If other principals have write access, the sticky bit must protect its owned entries. The adapter creates a fresh owner-private directory and a single-link owner-private stage using exclusive creation. It accepts no pre-existing lookalike as an owned stage. Each stage remembers its validated target bytes and copy binding before the first write. Flush observations and a pinned read-only reopen guard the transition out of the writer. A file `fsync` error permanently revokes that writer and leaves the private stage for reconciliation. Linux can report a writeback error only once per open file. A later mutation or name rebind that the adapter detects fails closed.

Publication consumes a matching model authorization and the read-only stage. The coordinator owns independent verification, required metadata, durable intent for that target and uniqueness of the binding. The adapter rechecks the stage before a single no-replace rename. A late incumbent leaves the stage and incumbent in place. An uncertain rename keeps evidence for reconciliation. If a directory barrier fails after rename, the error reports the completed rename separately. Both affected directories are synchronized on the success path. The adapter performs no deletion or rollback. Privileged or malicious same-principal mutation is outside this adapter contract.

## Evidence scope

The native tests create private fixtures and exercise descriptor-scoped reads, hard-link identity, raw names, special-file and symlink refusal, stage rebind, flush prerequisites, matching authorization, and late incumbents. They passed on ARM64 Ubuntu 24.04.5 with Linux 6.8.0-147 and ext4 in a disposable VM. Syscall fault injection exercised each post-rename directory barrier separately.

The simulator exercised 120 bounded histories, including short I/O, ambiguous effects, conflicts, process restart, and loss of volatile namespace and data. The filename [fuzz target](../crates/endpoints/endpoint/fuzz/README.md) checks raw component acceptance and byte preservation. These checks cover fixture behavior and tested adapter semantics. Process-kill recovery, physical storage fault campaigns and filesystem profile qualification remain separate requirements.

The Linux run measured 105 of 117 endpoint lines and 483 of 520 platform lines. Nightly CI checks each package against the 85% line coverage target. The [P-013 evidence gate](../crates/endpoints/endpoint/verification/obligations.toml) verifies every byte sequence of length 0 through 255 within its symbolic array model and rejects every sequence at the first oversized length. This verifies component admission and byte borrowing. Filesystem containment is exercised by native adapter tests under their stated assumptions.

```sh
cargo test --locked -p exacopy-platform
cargo nextest run --locked -p exacopy-endpoint -p exacopy-test-support
```

This work package has no on-disk application format, public CLI or application publication path. The next work package couples these operations to streamed hash verification and the coordinator. The application release gate still requires the locked dependency audits.
