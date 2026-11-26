# Signed synchronization genesis root and closure

**Status** Proposed. This profile covers read-only admission of one explicit
generation-one seed for R-269, R-270 and R-276 under INV-025/026. It uses the
existing [paired baseline leaf](../../crates/formats/exacopy-manifest/verification/sync_baseline/README.md)
and [genesis admission](sync-baseline-genesis.md). Registry allocation,
implementation, independent wire vectors and review are required before
enabling a reader. A writer, current pointer, successor and sync effects
require separate authority and qualification.

## Closure and trust

The closure has exactly four members supplied as bounded byte slices or
through a digest-directed reader. This profile allocates no outer bundle
encoding. The signed kind-6 root commits to
two signed kind-1 EndpointBindings in left/right order and one level-zero
kind-0x0100 leaf. All four members are required. A reader of a standalone
bundle must reject duplicates, extra members and incorrect types, byte
lengths, digests and counts. A content-addressed resolver may contain other
objects. It reads only these three exact child references, treats a
missing object as an error, and never follows a path supplied by the record.
The restricted graph needs no recursive reader, generic manifest traversal,
or dependency resolution through filenames.

Independent selection supplies the exact expected root digest, expected
raw **subject basename**, owner profile ID and revision, provisioned Ed25519
public key, and a typed expected endpoint for each side in left/right order.
Each endpoint expectation supplies the endpoint ID, selected child-root
locator, common-parent capability locator, raw child-root basename, expected
boot and mount/user-namespace identities, unique mount ID, parent and child
device/inode facts, and exact configured limits. The two expected parent
locators and native parents must agree. Independently compute the one-subject
filter and required policy from the selection. An optional independently
expected scan labels historical observations. It cannot establish that a
scan is current. When omitted, report the signed root's historical scan.

Historical expectations come from an independent owner-approved selection
or retained selection record. A child artifact's assertions cannot fill
missing expectations. Only a root selected by exact digest can become
preview history. Missing or invalid selected history stops that request.
Explicit no-history mode is a separate selection.

All signed members use the same independently trusted owner key and
profile. Compare the envelope public key bytes to that key, reject a weak
key, and use strict Ed25519 verification. A root-embedded key, endpoint
key, optional unsigned export or second key with a valid signature cannot
supply trust. Authenticate before exposing parsed claims. The root UUID
and creation timestamp are recorded data. They do not select history,
prove freshness or confer authority.

Admission starts with only the root. Bound and decode its exact envelope,
match its independently selected non-weak key and verify its strict kind-6
signature and expected digest. Require canonical root shape and version,
profile, independently expected basename, filter/policy, pair, scope and
scan selection, genesis constraints and the three exact typed reference
shapes. Scope can be projected at this point from the independently
expected native facts and child digests authenticated by the root. Then
check total declared closure size with checked arithmetic and require
distinct references. Any failure through this point makes zero child
resolver calls. A foreign but validly signed root cannot request child
I/O.

For each authenticated reference, resolve the exact kind, digest and
encoded length, and require the single item count. Authenticate and
canonicalize each signed endpoint under the same independently selected
key and profile before comparing its typed fields to that side's
independent expectation. The root-committed reference addresses the
historical child body and specifies its envelope length. Current native
selection does not regenerate historical endpoint UUIDs or timestamps.

## Exact wire shape

All containers are definite length. Map keys and integer widths use
deterministic CBOR ordering and shortest encodings. Reject duplicate,
missing, additional, reordered or differently typed fields, tags,
trailing bytes, and encodings that differ from canonical re-encoding.
There are no optional extension fields. Grammar below is CDDL with
semantic constraints stated after it.

```cddl
digest = bstr .size 32
uuid = bstr .size 16
u32 = 0..4294967295
u64 = 0..18446744073709551615
positive = 1..18446744073709551615
stream-length = 0..9223372036854775807
time = [-9223372036854775808..9223372036854775807, 0..999999999]
component = bstr .size (1..255)
unix-component = {0: 1, 1: component}
rooted-child-path = {0: uuid, 1: [unix-component]}
local-evidence = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 3, 6: 2, 7: null}
endpoint-version = {0: 1, 1: 0, 2: 1}
root-version = {0: 1, 1: 0, 2: 69}

; 69 = endpoint binding, two-way baseline, scoped completeness.
envelope = {0: bstr, 1: digest, 2: bstr .size 64, 3: 32}
endpoint-ref = {0: digest, 1: 1, 2: 1..2048, 3: 1}
leaf-ref = {0: digest, 1: 256, 2: 1..2048, 3: 1}

device = [u32, u32]
object = [device, positive]                 ; inode
namespace = [device, positive]              ; native namespace inode
linux-location = [
  uuid,                                     ; kernel boot ID
  namespace,                                ; mount namespace
  namespace,                                ; user/ownership namespace
  positive,                                 ; unique live mount ID
  object,                                   ; authorized common parent
  object                                    ; selected root
]

endpoint-body = {
  0: endpoint-version, 1: 1, 2: uuid, 3: uuid, 4: null,
  5: endpoint-data, 6: time, 7: 1
}
endpoint-data = {
  0: uuid,                                  ; selected endpoint ID
  1: 0,                                     ; local provider
  2: positive,                              ; owner profile revision
  3: null,                                  ; no remote principal
  4: digest,                                ; fixed local-only policy
  5: uuid,                                  ; authorized root locator
  6: bstr,                                  ; canonical linux-location bytes
  7: "linux-managed-local-sync-genesis-v1",
  8: local-evidence,
  9: rooted-child-path,                     ; one child of common parent
  10: {0: stream-length, 1: 1, 2: 1, 3: 1}, ; bytes, entries, I/O, depth
  11: null                                  ; no mutation grant
}

root-body = {
  0: root-version, 1: 6, 2: uuid, 3: uuid, 4: null,
  5: root-data, 6: time, 7: 1
}
root-data = {
  0: digest,                                ; ordered pair ID
  1: 1,                                     ; genesis generation
  2: null,                                  ; no preceding baseline
  3: [endpoint-ref, endpoint-ref],
  4: {0: digest, 1: digest},                 ; filter, policy
  5: {0: 0, 1: 0, 2: digest, 3: positive, 4: unix-component},
                                            ; left complete, right complete,
                                            ; scope digest, scan, exact subject
  6: [leaf-ref],
  7: 1,                                     ; one row
  8: [],                                    ; no action receipts
  9: []                                     ; no tombstones
}
```

Envelope key 0 contains exactly one body encoded by the relevant grammar.
Before any decoding or crypto, cap each root or EndpointBinding envelope
at 2,048 bytes and each leaf at its existing 2,048 bytes. Before decoding
embedded `linux-location`, cap it at 128 bytes. Bound the raw basename
at 255 bytes and use the existing Unix component validator. All UUIDs
are nonzero. Envelope record IDs are UUIDv7. The three signed records
must have distinct record IDs, and ordered endpoint IDs, locators and
child names must each be distinct. Key 7 is the first immutable record
revision. It is distinct from the owner profile revision in EndpointBinding
key 2. Unix times are informational wall-clock values. The rooted Path
uses the registered common map. Path key 0 is the independently selected
common-parent capability locator and key 1 is the single raw child
component. Omit display key 2. The endpoint's selected child-root locator
stays at EndpointBinding key 5. The root's completeness subject is a
component applied to both independently selected roots.

The registered Evidence map declares `not_published`, verification
`none`, `live_observed`, durability `unconfirmed`, `preserve`,
redundancy `unknown`, metadata `explicitly_omitted`, and no
qualification profile. The paired leaf carries the historical content
and selected metadata observations. This endpoint ceiling claims no
publication or independent endpoint verification. No network route,
principal or grant is encoded for this profile.

Use `record_input(kind, body) = "ExaCopy/workflow-record/v1" || NUL ||
kind:u16le || canonical_body_bytes`. Sign these exact bytes with Ed25519.
Use ordinary BLAKE3 of these same bytes as the record digest. It selects
the canonical kind and body, not a particular signature byte string. The
signer and signature require independent checks. The length of a signed `WorkflowRef` counts the entire encoded signed envelope, which
must be checked separately from the body-domain digest. The leaf uses
`"ExaCopy/workflow-page/v1" || NUL || kind:u16le || byte_len:u64le ||
canonical_page_bytes` for its existing BLAKE3 commitment. Its reference
length covers the complete unsigned page. No signed-record digest is
accepted in the page domain or vice versa. The maximum explicit bundle
payload is 8,192 bytes, excluding any separately specified transport
framing. Bound external reads by the declared length and the member cap,
and check exact EOF before decoding child bytes. A short or longer member
refuses. Limit typed body and envelope shapes before buffering references.

## Derivations and independent matching

Let `H(domain, x)` be BLAKE3 of the UTF-8 domain string, one NUL, and
deterministic CBOR of `x`. These derivations use arrays with exactly the
fields shown. They add no wire fields to the paired leaf. The scope
derivation embeds each `linux_location` as its decoded, typed,
canonically encoded array. EndpointBinding key 6 carries the canonical
bytes of that array inside a byte string. The scope hash does not
embed that byte-string wrapper.

| Value | Domain | Canonical value |
| --- | --- | --- |
| Local-only route policy | `ExaCopy/sync-baseline/local-only/v1` | `null` |
| Native root or file observation ID | `ExaCopy/sync-baseline/linux-object/v1` | `[boot_id, [device_major, device_minor], inode]` |
| Filter digest | `ExaCopy/sync-baseline/filter/v1` | `[unix_component]` for the one selected basename |
| Policy digest | `ExaCopy/sync-baseline/policy/v1` | `[0, 0, 0, 0]` for strict independent BLAKE3, unnamed stream only, Linux owner-and-mode v1, and live regular single-link observations |
| Pair ID | `ExaCopy/sync-baseline/pair/v1` | `[profile_id, profile_revision, [left_endpoint_id, left_root_locator], [right_endpoint_id, right_root_locator], filter_digest, policy_digest]` |
| Observation scope | `ExaCopy/sync-baseline/scope/v1` | `[pair_id, owner_key_bytes, left_endpoint_record_digest, right_endpoint_record_digest, left_native_root_id, right_native_root_id, linux_location_left, linux_location_right]` |
| Native stability stamp | `ExaCopy/sync-baseline/linux-stability/v1` | `[native_object_id, length, native_mode_u32, uid_u32, gid_u32, nlink_u64, mtime, ctime]` |

The selected policy reports ACLs, xattrs, timestamps and other filesystem
metadata outside the Linux owner-and-mode v1 digest. Modification and
change times take part in stability. Access time may change from reading.
The strict profile omits alternate streams, forks, sparse allocation
shape and sharing layout from its comparison. No portable snapshot,
tree-completeness or metadata-equivalence claim follows from the seed.

Each resolved child must match its signed reference, and its parsed endpoint
claims must match the independently expected binding for that side, including
recorded owner/profile revision, raw child name, root locator, authorized
limit and native facts. Both records bind the same
boot, mount and user namespace, unique mount ID and common parent. Their
root identities are physically distinct and neither aliases the parent.
The common parent and both root devices must agree with the held mount
within the selected profile. Raw
root names are checked as exact children, not as independent absolute
paths. Recompute the native root IDs, pair, filter, policy and scope.
The pair ID uses the stable selected locators. Native binding and the
full session live in the scope, which changes when the live namespace
binding changes. A native object identity hash has no root/path input.
Physical alias checks still belong to the held native adapter.

Match the root's exact selected basename, scope, policy and scan to
the leaf's expected selection, using the two independently checked root
IDs and the parent-committed leaf digest, length, kind and count. Use
the existing leaf decoder and matched independent-read rules. The
closure additionally rejects a leaf file ID equal to either root ID or
to the common-parent ID, computed in the same native object domain.
For an empty stream, both sides must record ordinary BLAKE3 of zero
bytes (`af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`).
Nonempty stream digests, file IDs and stability stamps remain signed
historical reports. The artifact reader cannot recompute those reports
from live files. Check the measured length against each endpoint limit.
Complete means both
ordered observations for the sole basename under exactly this scan and
scope, with required final rechecks. Neither signed completeness codes
nor a matching signature can replace leaf verification. No root is
complete on missing, unstable, denied, unsupported or unknown evidence.
There is no shared-baseline successor or automatic history discovery in
this profile.

Native admission obtains the boot ID from a verified procfs, checks held
mount and ownership namespaces, and obtains a unique mount ID and held
device/inode facts from the kernel. Missing or unqualified observations
refuse the profile. The writer and current preview would separately need
read-only held common-parent and child roots on the admitted managed Linux
mount, deterministic cooperation with the root stability contract, no
symlinks or mount crossing, and repeated full observations and EOF checks.
Preserve genuine native aliases and absence distinctions. Signature
verification authenticates an offline historical closure. A distinct
preview admission receives that closure plus independently re-admitted
current root capabilities, checks the actual current native pair and
scope against the authenticated historical selection, and requires fresh
current-side observations before classification. It does not reuse the
historical scan as a live token. The offline result cannot enter the
classifier as current input.

## Integration and verification

Own the canonical root and endpoint codecs in Plan and reuse the Manifest
leaf. Use signed-byte and exact-claim parsing in the format owner and
perform strict Ed25519 and combined closure verification in the Linux
transfer composition, which already depends on Plan, Manifest and
ed25519-dalek. Use a result type with private construction at the closure
boundary. Parsing alone yields no trusted history. Supply independent
profile/key and native selection through the application. A read-only
history result has no signer, file descriptor, publication permit, live
copy grant or baseline-pointer capability. This division needs no new
lockfile dependency. Keep ordinary Plan and Manifest wire bytes unchanged.

Before implementation, review the workflow registry allocations and freeze
deterministic independent vectors. A separate Python canonical-CBOR
generator should use the pinned portable C BLAKE3 oracle and OpenSSL
Ed25519 with fixed synthetic fixture keys. Publish exact member bytes,
signing-input digests, reference lengths, selected root digest, all
derived digests and expected decoded selection. Keep valid vectors for
raw non-UTF-8, 255-byte basename and endpoint components, empty matched
stream, both completion orders, and wide timestamps and length fields.

Include independently re-signed refusal vectors for a swapped endpoint
order, missing/repeated/extra member, foreign owner/profile/key, wrong
root or endpoint kind/domain, wrong envelope length or count, a digest
for the same payload under another kind/domain, stale/wrong boot or
namespace, substituted locator or physical alias, stale scan, incompatible
policy/filter, non-null predecessors, nonempty receipts/tombstones,
incomplete coverage, a false exact-subject match and a leaf inconsistent
with the projected native roots or final evidence. Include each leaf
file ID aliased to either root or the common parent, and two matching
wrong digests for an empty stream. Mutate Path's parent locator while
keeping the child locator and raw name fixed. Test a noncanonical
Evidence map and a scope digest computed with bstr-wrapped locations.
A counted resolver must observe zero calls for a wrong pinned signer
with a valid signature and selected digest, bad signature, wrong root
digest, scope, exact subject or other root-local refusal. Also test malformed
and oversized fields, canonical width/trailing bytes, weak and invalid
keys/signatures, required feature/version changes, and cap enforcement
before parsing or reading external bytes. Keep the distinction between
a signature validated against synthetic historical observations and
actual native pair, publication, crash or power-loss qualification.
