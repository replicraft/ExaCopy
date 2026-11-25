# Experimental Windows private staging

This work package implements part of R-003/A-003, R-014/A-014,
R-018/A-018 and R-019/A-019 under INV-002, INV-004, INV-013 and INV-019.
`exacopy-platform/experimental-windows-copy` is disabled by default and
compiled only for Windows. It exposes private stage mechanisms; the
Windows CLI copy and recovery routes remain unsupported.

The caller supplies an authorized, held local NTFS directory and establishes
its private ACL, ancestor provenance and exclusion of other namespace
writers. The API does not infer those properties from an arbitrary path.
Held observations reject non-disk objects, reparses, data-recall attributes,
delete-pending objects and unidentifiable volumes or files.

`WindowsStageDirectory::create` opens a validated single UTF-16 component
relative to that directory with `FILE_CREATE`, `OBJ_DONT_REPARSE` and
`FILE_OPEN_REPARSE_POINT`. It requires a confirmed new, empty, single-link
regular file before returning a writer. Existing names remain occupied;
uncertain creation results require reconciliation. No deletion primitive
or source mutation capability is exposed.

Writes are synchronous and contiguous, limited to 4 MiB per call and the
declared signed file extent. Positive ranges use the model's extracted
`checked_range_end` guard covered by P-004. An explicit zero-length read
case checks its offset; zero-length writes are refused. Observation or I/O
failure retires the writer and retains the partial artifact. Errors retain
typed causes and the I/O failure offset.

Finish requires the complete extent, successful `File::sync_all` and a
successful consuming `CloseHandle`. A separate read-only identity pin
bridges writer close. The final independently opened read handle excludes
write and delete sharing. Read-back checks the held and named identities,
one-link extent, modification/change observations and EOF. These mechanisms
do not compute the product content digest, seal a copy, journal intent,
publish a destination or establish namespace or power-loss durability.

The existing read fixture shares only the native ABI, observation and
counted-open implementation. Its original rights, sharing and open flags
are retained. Application workflow policy remains outside the adapter.

Rust 1.100.0 Windows x86-64 MSVC library code generation and cross-checks
passed for the individual and combined feature profiles. Independent
review led to a typed error-chain regression and separate occupied and
dangling symlink controls. The manual NTFS workflow has a Stage mode with
three contract controls, five ordinary native cases and two optional symlink
cases. Its selection controls passed against a host libtest skeleton;
that skeleton has empty bodies and is not native behavioral evidence.
The third contract case additionally requires a non-file event handle to
retain the native `GetFileType` error rather than classify a failed query
as an ordinary non-disk object.
The Windows tests and PowerShell execution remain unqualified until run
on the declared fixed local NTFS profile. Raw candidate checks and retained
failures are at `/private/tmp/exacopy-windows-stage.4KuUIu`.

The [native qualification guide](../testing.md) describes the manual lane.
Successful cross-compilation alone does not qualify this capability or
enable Windows product copy/recovery.
