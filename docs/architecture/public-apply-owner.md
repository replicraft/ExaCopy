# Authenticated public-apply owner binding

`PublicApplyOwnerRecord` is a distinct local owner declaration for a future
Linux public-Plan executor. It authenticates the private owner claims and
public execution expectations together. The public Plan digest and private
copy Plan digest retain their separate domains.

The envelope retains numeric fields for canonical body, selected public
key, Ed25519 signature and domain. Domain code 3 signs
`ExaCopy/owner/linux-public-apply/v1` plus NUL followed by the body. Its v1.0
header requires feature bit 1. The body wraps the canonical unsigned Linux
owner body and an eleven-field binding: public Plan digest, public entry,
private entry, private epoch, source and destination root aliases, approved
stream length and ordinary BLAKE3 digest, metadata-policy digest, optional
exclusive expiry and requested process-crash durability. The inner owner's
creation timestamp is the immutable admission timestamp.

The old Linux and managed APFS owner decoders refuse domain 3. This record
contains no separately signed legacy owner envelope and no removable
unsigned sidecar. The complete signed envelope digest can bind the job's
initial journal context. Decoding requires an independently selected
profile and verifying key; a key carried by the record cannot establish its
own trust. Canonical encoding, nonzero IDs/epoch, file extent bounds and
expiry after admission are checked. Expired records remain inspectable;
a future effect must separately obtain fresh time and check expiry.

Signing authenticates a local profile's declaration. It does not verify a
portable Approval, authorize roots, measure actual source or staged bytes,
establish metadata fidelity or qualify requested durability. The experimental [public staging coordinator](public-apply-staging.md)
persists this record before preparing a job and stops before publication.
Public recovery is still separate; legacy resume/retry continues to reject it. The [execution bridge](public-plan-bridge.md) still
requires non-bypassable expected-content verification and bound recovery
before product apply can be exposed.

The independent Python CBOR encoder and OpenSSL Ed25519 signer reproduce
the committed 541-byte fixture. Seven new Rust tests cover the external
trust boundary, signature prefix, every authenticated field, canonical
shape, scalar limits, expiry and legacy-reader refusal; existing Linux and
Darwin vectors remain unchanged. The [recipe](../../crates/storage/journal/verification/public_apply_owner/README.md)
and P-040 identify this scoped admission result. It is not a mathematical
proof of Ed25519 or native filesystem qualification. Private raw logs and
negative controls remain in `/private/tmp/exacopy-public-apply-owner.Jye0jFGp`.
