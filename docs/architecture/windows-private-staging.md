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

## Fresh-parent native publication component

The same default-off feature now includes an isolated publication component
for a fresh stage and a newly created destination parent. The caller supplies
a continuously controlled, authorized outer directory on a fixed local
NTFS volume. `WindowsPublicationRoot::create_destination` exclusively
creates one direct child and confirms the held directory and its exact
name. It refuses an existing directory. The fresh parent and continuous
custody avoid historical target-name reuse. The stage parent and destination
parent must be distinct and on the same physical NTFS volume. Bindings
include the volume GUID and serial, full 128-bit native file IDs, and
exact counted UTF-16 components.
[Destination custody](../../crates/platform/exacopy-platform/src/windows/stage/publication/destination.rs)

The caller must exclude prior and competing file and namespace mutation
handles through final observation. Authorized participants may create a
new incumbent. Deletion, rename-in, name reuse, parent delete-child
effects, alternate data streams and writes to attributes, DACL or ownership
are outside this custody contract. The adapter checks metadata and security
descriptors for drift. Its read pin denies writes to the selected unnamed
stream. The caller supplies the broader exclusion.

`finish_for_publication` flushes and consumes the fresh stage writer, then
provides an independently reopened read-back path for the exact placement.
The coordinator verifies the complete stream and selects required metadata
before sealing and supplying a matching one-shot model permit. The narrow
stage profile checks one unnamed stream of the verified extent, owner and
DACL, creation and last-write times, and supported attributes including
ARCHIVE. The adapter keeps identity pinned across the DELETE-access open
and makes one held-handle `NtSetInformationFile(FileRenameInformation)` call
with replacement disabled. No pathname fallback is available. After a
successful return it rechecks both parents, absence of the former name,
and the exact target inode, spelling, metadata and EOF. It distinguishes
pre-submission refusal, kernel collision, uncertain submission and a
reported rename whose observations remain unconfirmed. Evidence stays
held for reconciliation.
[Publication component](../../crates/platform/exacopy-platform/src/windows/stage/publication.rs)

The native request uses the documented WDK layout and buffer size, a held
destination directory, one counted component and replacement disabled.
Set-information completion is synchronous. Only exact `STATUS_SUCCESS`
reports kernel success; unexpected statuses remain uncertain. No absolute-path
fallback or retry is added.
[Native rename contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information) ·
[Synchronous set-information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ioisoperationsynchronous)

The separate Windows Server 2025 x64 workflow selects the platform test
image with the exact experimental feature, two ordinary ABI and status
controls, and five ignored native cases. The owned fixed-NTFS fixture
requires the hosted administrative token and a synthetic directory
reparse control. The runner binds the exact image and selectors to the
revision, checks process drainage and removes only verified owned
artifacts. Strict Windows cross-Clippy and copy-only library code
generation passed. Workflow and portable selection controls passed.
Strict v1 still stops at its compiler-job timeout before native cases run.
[Fixture manifest](../../crates/platform/exacopy-platform/verification/windows_ntfs_publication/fixture.toml) ·
[Hosted workflow](../../.github/workflows/windows-ntfs-publication.yml)

The separate owned-build preparation profile uses the same test cases on
the hosted Windows image. Its build first establishes whole-job quiescence,
then admits the held test executable from verified compiler output. Case
execution still requires strict natural completion. At `b116813`, the profile
passed both ABI/status controls and all five native cases, with process drainage
and fixture deletion verified. At `0f6051e`, compilation, owned-job quiescence
and held-image admission succeeded. Two ABI/status controls and two native
refusal cases passed; three positive publication cases returned Win32 error 87
before observation. Cleanup reported an unexpected entry and remained
unconfirmed. The native-call correction subsequently passed the declared cases.
The exact origin of the Win32 error remains unconfirmed: current Microsoft documentation
also permits a relative held root in the former Win32 request. The strict v1
results remain separately scoped.

The passing artifact retains the compiler transcript, graph, held-image
identity/digest receipt, process records and exact test outputs. It does not
include the PE image bytes; image binding relies on the on-runner held-file
verification. This qualification covers the component and declared hosted
fixed-NTFS matrix, not Windows CLI composition, restart or power-loss behavior.
[Passing native v2 run](https://github.com/replicraft/ExaCopy/actions/runs/46013234916) ·
[Artifact](https://github.com/replicraft/ExaCopy/actions/runs/46013234916/artifacts/15204776248)
[Preparation fixture](../../crates/platform/exacopy-platform/verification/windows_ntfs_publication_preparation/fixture.toml) ·
[Preparation workflow](../../.github/workflows/windows-ntfs-publication-preparation.yml)

This component supplies no product copy command, durable intent writer,
receipt, namespace durability, process-crash or power-loss qualification.
The separate Stage qualification retains its own scope.

## Reopened target inspection

The default-off copy feature includes a read-only probe for an existing
destination parent. It uses the caller's freshly held, authenticated root,
recorded root identity, exact parent component and independently admitted
placement binding. It checks fixed local NTFS, case-insensitive directory
mode, direct parent identity and spelling, and the target's full physical
identity and exact spelling.
A missing target lookup, the expected native ID and an unrelated regular
entry are distinct observations. Other results, including aliases that
resolve without matching the stored spelling, require reconciliation.
The caller must hold the root and its ancestry and exclude concurrent
namespace changes during inspection.

The probe returns a sampled name/identity fact without any file handle,
publication permit, or proof of content, metadata, journal admission, or
durability. The native fixture includes cases for a retained private stage with an
absent or unrelated public entry and for reopening the target after releasing
all original attempt handles. Their native execution remains unqualified. It contributes to R-044/A-044 and INV-009
without executing the required process-kill or barrier-replay campaign.

Successful cross-compilation alone does not qualify this capability or
enable Windows product copy/recovery.
