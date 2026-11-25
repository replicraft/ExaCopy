# Public single-file plan and local apply

Decision PLN-003, 2026-11-25. The fixed Linux metadata-policy identifier
and requested grant names below are selected for the initial local profile.
The canonical body and page codecs and the [read-only Linux export](read-only-plan-export.md)
are implemented. Apply, durable recovery binding and integrated qualification
remain open.

This work package maps the public Plan v1 envelope and the existing
[one-entry page codec](public-plan-pages.md) to a local Linux create-new
copy. It covers R-007–R-009, R-011, R-013–R-016, R-043, R-062, R-154–R-157
and R-193, with the matching A-IDs. Its gates include INV-001–INV-006,
INV-009, INV-013–INV-014 and INV-018–INV-020. At `a9aad2d` the public
page codec and private Linux copy/recovery exist. The bridge and its
qualification remain open.

## One selectable profile

| Field | Planned or accepted value |
| --- | --- |
| Operation and scope | `copy`, exactly one `create_new` regular-file entry and one unnamed stream. One root-relative raw Unix basename on each side. Complete selection, one level-zero `plan_entries` page, one entry, zero conflicts. Expected incumbent is null, meaning checked absence. |
| Safety policy | `preserve`, conflict `error`, `blake3_readback`, `independent` writes, `per_file` publication, `live_observed` consistency, `required-data` fidelity through the reviewed Linux policy below, no source retirement, and no symlink following. No extensions in this profile. |
| Minimum durability | Default to `process_crash` under SAFETY §3, ADR-021 and `inventories/defaults.json`. `qualified_power_loss` is the stronger explicit selection. Record the selected minimum before digesting the plan. Apply must reject either minimum unless the held root profile is qualified for it. |
| Resource limits | Emit the admitted streaming buffer budget and one in-flight I/O. The initial producer records its supplied scratch length, bounded to 4 MiB. This data-buffer limit is distinct from bounded codec/export workspace and the pack's global default memory ceiling of 536,870,912 bytes. Reject impossible effective limits before allocation. Estimated working bytes may equal logical length and remain an estimate of staging data, not a reservation or total disk requirement. |
| Source view | Exactly one `live_observed` descriptor, provider `live-observation`, non-nil independent view and measurement IDs, actual source-root ID, source observation, measured-at UTC time, null snapshot token and null stable-until. |
| Grants and approval | Required grant names `read-content`, `create-new`, in that order. Those names describe requested rights. This profile sets `approval_required` and requires the exact out-of-band `--approve` digest plus independent local root and owner-profile selection. |
| Time | UUIDv7 Plan ID. Emit normalized UTC creation and observation times, with observation at or before creation. The local plan has no expiry unless explicitly requested. For a finite expiry, require creation before expiry and current wall time strictly before expiry at admission and again before issuing intent. Revalidate on restart using a current trusted clock. |

The pack assigns the public Plan body numeric keys 0–16 and 127. Use
its exact nested policy, view, resource and document-reference projections.
Hash `ExaCopy/plan/v1\0` followed by the canonical CBOR body with ordinary
BLAKE3. Normalize JSON UUIDs, padded base64, decimal strings and timestamps
into typed values before hashing. Bound the envelope before allocating and
reject duplicate fields, unknown required fields, unsupported profiles and
trailing values. Display labels convey no authority. The plan entry's raw
basenames, stream length/digest and metadata policy are bound through its
one verified page reference. Preserve distinct Plan, DocumentRef, ordinary
content and private journal digests.

## Plan creation

The read-only Linux exporter runs independently of apply.
A caller selects source and destination using the normal two pathname
arguments, the local owner profile, and an explicit export output outside
both selected roots. Hold both parent capabilities. Check that the target
is absent using a descriptor-relative metadata observation. Reject the
profile seed by held inode identity before hashing. Select the source with
`ReadRoot` and its named-file recheck, reject unsupported metadata before
reading, measure the logical stream with `exacopy-content`, then check held
stamp, EOF, named binding, metadata eligibility and target absence again.
Return a conflict for an occupied target; completeness cannot hide one.

Use the existing read-only source handle. Ordinary kernel atime updates are
allowed under the architecture pack's source-preservation contract. Planning
and preview issue no source content or namespace mutations and create no job,
staging directory or source-side spool. The authorized export bundle is the
only application-written artifact.

Use the `LocalProfile::root_id` derivation from the selected profile key
and each held directory's device and inode. Cross-check both root IDs in
the entry, the source-view root ID and the held roots; accept one equal
root ID for a same-directory copy only if the held identities agree and
the names are distinct. Define the Linux source identity as platform 0,
eight little-endian device bytes and eight little-endian inode bytes, with
null generation for the current adapter. These atoms describe observed
Linux VFS identities, with no long-term mount or inode-reuse guarantee.
The leaf and descriptor must carry the same non-null identity for this
profile. Neither timestamps nor path spellings substitute for generation.

Publish the explicitly requested export through one held private bundle
parent. Create `pages/<lowercase-page-id>.exc` by exact reference using only
derived names. Commit the page before exclusively making the requested Plan
JSON visible. Synchronize the applicable file and directory chain and refuse
an incumbent output. A failed export can leave private artifacts; never
delete or replace an unknown entry as cleanup. Load the bundle from its
explicitly selected parent, enforce fixed names, no symlink following and
bounded held-file reads, and require the single referenced page to match
kind, length, count, digest and canonical encoding. A path supplied inside
JSON cannot select a bundle member or a source/destination root.

## Apply admission and authority

Apply accepts the caller's explicit bundle, `--source-root DIR`,
`--destination-root DIR`, `--profile DIR` and `--approve PLAN_DIGEST`.
The root arguments convey the local intent to read one file and create one
new file through authorized held directories. This is bounded operating
system and operator authority, without peer or persistent grant semantics.
Opening the profile proves local key access and gives the recovery
principal; the profile key alone does not authorize arbitrary roots. The
CLI digest is the operator's confirmation for this one call. It is neither
verification of an Ed25519 signature nor transportable authorization.
Reject embedded `approval` for the initial CLI profile. Authenticating a
portable Approval requires an allocated, separately reviewed signature
domain, canonical body and independently trusted principal/grant store.
The pack registers an Owner signature domain for private job ownership.
It cannot authenticate a public approval.

Validate request, bounded envelope, public digest, reference closure,
local authorization, expiry and minimum durability before creating private
job state. Open existing source and destination roots through the selected
adapter, verify root IDs and recheck the exact names on the held handles.
Inspect source identity/size/stamp, eligible metadata and destination
absence, then compute the private `LocalCopyPlan` from those live observations
and a fresh private job/attempt. Its digest remains the sole digest in
existing journal contexts and the signed owner plan field. The candidate
public digest identifies the approved semantics in separate apply evidence.

PLN-003 assigns the Linux metadata-policy identifier as ordinary BLAKE3 of
the exact bytes
`ExaCopy/metadata-policy/linux-baseline/v1\0`. The single implementation
definition is `linux_baseline_metadata_policy_digest` in the transfer
planner. Its independently computed digest is
`7c124934135712b89a782516402f3bc5d6f657908fb1dadabbb218a710d8d0c3`.
The versioned policy admits
only a regular file with one ordinary stream, inspectable empty visible
xattr list and no special mode bits. Preserve ordinary permission bits,
actual UID/GID by equality with the staging inode, and selected captured
atime/mtime, with independent or reported metadata observations as applicable.
Use the existing stage admission, application and read-back predicate.
Record visibility limits and unpreserved creation/change time, hard-link
topology and sparse layout in the fidelity projection. If a required-data
selection makes any unrepresented fact mandatory, use a stricter admission
predicate or refuse before publication. The metadata-policy digest freezes
this policy, not file metadata values or authority. Plan v1 has no field for
an exact historical atime/mode snapshot in the leaf. Fresh qualifying metadata
may be selected at execution only if the plan explicitly uses this policy.

Use the stream measurement from the actual single held-source copy and
independent stage read-back before synchronized `PublishIntent`. Both must
match the approved length/digest. A stable live source whose length or
measurement differs from the approved stream is stale (exit 3). Disagreement
between the actual source measurement and independent stage read-back is an
integrity failure (exit 5). A planning-time or preflight hash alone cannot
authorize publication of later bytes. Recheck the held source and
its name at the seal and intent boundary. Use the existing model permit,
private stage, full file and directory barriers, exact intent synchronization,
exclusive rename, and observation and receipt ordering. Unknown effect or
barrier outcomes retain evidence for reconciliation.

## Durable apply binding and recovery

Add a separately versioned private apply binding before the first
mutation-capable job preparation frame. The binding covers the public Plan
digest, exact entry, root IDs, policy, content length/digest, local profile,
private plan digest, and admission/expiry. Carry it in a signed owner
extension with a mandatory Linux owner feature, or a bounded synchronized
artifact whose digest is signed by that mandatory owner form. Existing
Linux v1 owners and `LocalCopyPlan` bytes remain unchanged. Readers that
lack the apply feature must refuse the new owner form, including partially
created jobs. Never add a removable sidecar to an otherwise resumable
ordinary job. The current recovery commands could otherwise recompute a
fresh digest and bypass the public expectation.

For initial apply support, keep pre-intent resume and retry disabled for
this job flavor. Permit inspection and evidence-only reconciliation of an
already performed effect after verifying the binding, accepted journal,
exact current target and its content. An unperformed effect must pass
fresh scope, approval, expiry and the public expected-stream gate before
any later rename is enabled. Expiring while an effect is uncertain requires
reconciliation with retained private evidence. Record both public and
private plan digests in the apply result and in recoverable authenticated
evidence. Keep public receipt fields separate from private receipt bytes.

The existing Linux CLI receipt explicitly reports durability `unconfirmed`.
The bridge must resolve that implementation gap to satisfy the default. Start
with a narrow local ext4 process-crash qualification: scope it to the tested
kernel/profile and barriers, trusted mount namespace, held destination and
same-mount private job and stage, and a still-running kernel with intact
storage. A capability must positively bind the actual held mount and runtime
profile. A filesystem magic number shared by ext filesystems or a caller's
label alone is insufficient. Verify mount identity and filesystem type at
admission and before intent using held native evidence. Exclude backing and
namespace combinations outside the qualified profile. Preserve the default
unconfirmed claim for ordinary receipts that lack this evidence.

Use the existing process-kill and post-rename barrier tests as inputs to that
qualification. Add bridge tests around durable binding, stream comparison,
intent, rename and observed receipt persistence. Construct the public
`process_crash` claim only from the admitted profile plus completed barrier
and receipt evidence. Refuse `qualified_power_loss` before private bootstrap
unless a separately qualified implementation exists. Any actual flush failure
stays fatal, even under the process-crash profile.

## Implementation order and acceptance

1. `exacopy-codec` owns the bounded Plan envelope, exact canonical vectors
   and parser/fuzz gates. Allocate the metadata-policy digest and cross-check
   the already implemented page and stream code assignments. Independently
   vary JSON ordering, display, the raw path, digest/count/kind, policy,
   expiry, root/view IDs, unknown fields and approval. Route A-155 and A-193
   to the canonical plan/page validators.
2. CLI and Linux runtime compose the read-only planner and secure bundle
   export. Test raw non-UTF-8 names and empty files, incumbent refusal,
   read/extent/rebinding failures, profile-seed refusal, page sync failure,
   output collisions, safe human preview and source/target preservation.
   A-156 compares root namespaces and file contents before and after an
   export, permitting documented kernel atime behavior.
3. Transfer and journal owners implement the typed apply binding, the
   expected-stream gate shared by fresh and any future resume/retry path,
   and version-aware recovery refusal. Old parsers must reject a new public
   owner before a mutation. Preserve old journal vectors. Tests tamper with
   the public or private digest, swap owner/profile/root, change source
   bytes after preflight, and verify the retained partial record cannot
   re-enter an ordinary recovery path. A committed receipt binds both
   domains and exactly one plan entry.
4. The platform and engine owners qualify the process-crash capability and
   run native tests for one successful create-and-apply, explicit stronger
   durability refusal, symlink/root/late-incumbent conflicts, and kills at
   each new durability boundary. CLI does not accept an apply-time profile
   override that changes the approved policy. Preserve pre-effect exit 2
   for malformed input, 3 for stale source, expiry or target conflict,
   4 for native I/O, 5 for corrupt bytes/digest or read-back integrity,
   6 for unsupported capability or required fidelity, and 8 for absent or
   mismatched authorization. Report 9 when publication or its barriers
   leave an uncertain effect requiring reconciliation. Do not claim success
   merely because a preflight report and immutable Plan exist.
