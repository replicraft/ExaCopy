# Public plan-entry pages

Decision PLN-001, 2026-11-25. The codec implements a bounded part of
R-182/A-182 and R-193/A-193: a public `DocumentRef` and one complete
`PlanEntries` v1 leaf containing one regular-file `create_new` entry.
Its owning Rust admission gate is P-037, under the P-010 parser boundary.
INV-013, INV-018 and INV-019 require bounded parsing and fail-closed
domain admission. This codec provides no filesystem authority.

The numeric field allocations and digest framing follow the local pack's
public record registry. The plan leaf's object-kind field uses the public
manifest object-kind allocation: regular is code 0. The pack names that
field without a separate plan-specific enumeration; this decision makes
the shared allocation explicit. Unknown kinds and actions are refused.

The leaf contains two non-nil root IDs and raw Unix basenames, a non-nil
entry and source-view ID, one unnamed BLAKE3 stream, a metadata-policy
digest, expected destination absence, no explicit conflict, and a u64
working-byte estimate. Logical length is at most `2^63-1`; each basename
is 1–255 bytes with no NUL, slash, `.` or `..`. Optional source identities
are namespaced opaque bytes, with each atom limited to 256 bytes.
They neither manufacture a live handle nor establish reuse protection.

References carry kind, exact encoded byte length, descendant count and a
BLAKE3 digest over `ExaCopy/document-page/v1` plus NUL, kind u16 LE,
encoded length u64 LE, and canonical page bytes. They are independent of
repository keys. Reference parsing does not establish that a page exists.
Page admission checks the 256 KiB byte bound, kind, length and digest
before fixed-shape decoding, then requires count one and exact canonical
re-encoding. Indefinite containers, trailing bytes, unknown fields and
unsupported profiles fail. Parsing borrows input bytes and has no
input-dependent recursion or child-page retrieval.

The [independent vectors and recipe](../../crates/formats/exacopy-plan/verification/plan_entries/README.md)
cover an empty file with a real entry and an opaque Linux identity.
An independent Python encoder and the portable official C BLAKE3
implementation establish exact CBOR and digest bytes. Tests additionally
exercise truncations with fresh valid digests, wrong domains, counts and
lengths, noncanonical encodings and unsupported actions. Whole-codec
coverage measured 779/816 lines and 130/138 branch outcomes; the new
modules alone measured 409/440 lines and 57/64 branch outcomes. These
denominators differ and the latter remain below the crate targets.

The [crate-local ASan runner](../../crates/formats/exacopy-plan/verification/plan_entries/check-fuzz.sh)
completed 250,000 inputs on ARM64 macOS with nightly-2026-11-04 and
cargo-fuzz 0.13.2. It used seed 441037, a 262,145-byte input cap,
90-second campaign cap, two-second input timeout and 768 MiB RSS cap.
There were no failure artifacts. Raw references are decoded independently;
arbitrary page bytes receive a freshly calculated matching reference so
fuzzing reaches the CBOR parser beyond the digest check. Exact source and
lockfile digests, budget, sanitizer evidence and raw logs are retained at
`/private/tmp/exacopy-public-plan.Bp3u9v/evidence/plan-fuzz`.
Mutation coverage remains unmeasured. Hosted Linux fuzz execution remains
pending; adding its nightly lane is configuration, not a passing result.

The complete public Plan envelope, multi-level page-tree traversal,
approval, bundle lookup, root/source-view binding and public apply remain
unimplemented. Expected absence is planning evidence; a future executor
must revalidate it and use exclusive publication. This record does not
reinterpret the private Linux copy-plan journal or change its bytes.
