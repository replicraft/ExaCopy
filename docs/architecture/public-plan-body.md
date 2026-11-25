# Canonical public Plan body

Decision PLN-002, 2026-11-25. `exacopy-codec` implements the registered
18-field Plan v1 canonical body and public Plan digest. This is a scoped
part of R-155/A-155 under INV-013, INV-018 and INV-019. P-038 exercises
digest binding; it does not establish approval or filesystem authority.

The binary projection follows the local pack's public record registry:
keys 0–16 and 127, version `[1,0]`, RFC-variant UUIDv7 Plan ID, all seven
operation codes, registered safety-policy enums, source views, document
references, resource limits, counts and extensions. Time is an i64 Unix
seconds/u32 nanoseconds pair, with nanoseconds below one billion.
UUIDs other than the Plan ID are opaque non-nil identifiers. No clock,
filesystem lookup or root authorization occurs in the codec.

The admitted canonical body is at most 1 MiB. Roots, source views and
grant labels are limited to 128 each; root page references to 4,096;
provider and grant strings to 128 Unicode scalars. Referenced root counts
must sum to the declared entry count without overflow. Actual descendants,
cycles, contradictory entries, source-view membership and capabilities
require bundle/runtime validation. A caller's `complete` boolean is a
claim carried by the record, not proof of complete enumeration.

Extensions preserve exact accepted canonical bytes. The profile allows
null, booleans, base-range CBOR integers, UTF-8 text, definite arrays and
text-keyed maps. Top-level keys must be namespaced; limits are 16 extension
fields, 64 fields per nested map, 4,096 array items and 32 container levels
including the body. Duplicate or out-of-order keys, non-preferred encodings,
floats, byte strings, tags and indefinite containers are refused.
Extensions never override policy or grant authority.

Admission checks input size before hashing, requires the caller's expected
digest, decodes bounded fields, and checks exact canonical re-encoding.
The digest is ordinary BLAKE3 over `ExaCopy/plan/v1` plus NUL and those
body bytes. A new constructor validates bounded fields before encoding,
then enforces the encoded-size cap. Its transient encoding allocation can
exceed 1 MiB within the fixed field limits; 1 MiB is not a peak-memory claim.
Errors and Debug output do not echo extension or grant contents.

The [independent vectors and recipe](../../crates/core/codec/verification/plan_body/README.md)
include complete and incomplete bodies. The complete fixture references
two distinct entries with matching root and source-view IDs, counts and
working-byte estimates. All prior page/reference vectors are unchanged.
An independent Python encoder and portable official C BLAKE3 implementation
establish exact bytes and digest values.

The final private candidate passed 36 native codec tests and nine focused
source mutations. Whole-codec coverage measured 1,381/1,421 lines and
215/222 branch outcomes; the new body/shared-identity scope measured
652/660 lines and 91/92 branch outcomes. A refreshed ASan campaign
completed 250,000 inputs without failure artifacts. Exact hashes, bounds,
raw results and the corrected fixture history are retained at
`/private/tmp/exacopy-plan-envelope.GOZW69/evidence/fixture-revision`.

[Unsigned JSON/RFC3339 parsing](public-plan-json.md) is implemented separately.
Cryptographic approvals, actual page-tree validation, CLI export and apply
remain separate work. Private Linux plans
and their persisted journal contexts keep their existing representation.
