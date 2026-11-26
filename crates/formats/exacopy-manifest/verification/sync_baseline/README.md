# Generation-one paired baseline leaf

Workflow page kind `0x0100` uses the workflow-page v1 BLAKE3 domain.
The bounded decoder expects the exact externally selected digest,
encoded length, kind and item count of one. Version 1.0 admits one
level-zero leaf with two ordered measured and rechecked sides. Root
IDs, exact raw name, scope, policy and scan must match the independent
selection. Scope covers owner/profile and the native session. Each
side's final identity and stability must match its measured facts and
follow both distinct completed-read positions.

The Linux owner-and-mode v1 projection admits ordinary permission bits,
numeric UID and GID. The metadata digest hashes the exact UTF-8 bytes
`ExaCopy/sync-baseline/linux-owner-mode/v1`, one NUL and the canonical
three-item CBOR array of those values. Modified and changed times can
contribute to native stability stamps. Time values, ACLs, xattrs, forks,
named streams and other filesystem properties are outside this comparison
domain. The surrounding policy must explicitly expose its omissions.
A different native profile needs its own registered projection.

The signature and full closure belong to the enclosing workflow root.
The leaf compares a supplied commitment and expectation. This check
neither verifies a signer nor establishes native identity, live read
facts or filesystem authority. The codec has no artifact writer or CLI.

## Native projection preconditions

An EndpointBinding's 16-byte root locator names a selection. The leaf's
32-byte root observation represents an independently verified native
identity. Treat both according to their distinct contracts. Scope must
bind the full observed native boot and mount session and both ordered,
authenticated endpoint references. The 32-byte file identity projection
must be root-independent so aliases do not acquire different IDs from
the selected path. The native adapter still checks physical file and root
aliases explicitly before any writer can use the observation. This codec
treats these identities and scope digests as supplied values. Their
native construction and qualification remain separate work.

## Reproduce the vectors

Use `reference.py` with the existing portable C BLAKE3 oracle from
[manifest verification](../manifest/README.md). Build the oracle with the
checked workspace BLAKE3 source. Reproduce into a temporary directory.

```sh
python3 -B crates/formats/exacopy-manifest/verification/sync_baseline/reference.py \
  /absolute/path/to/manifest-hash \
  /absolute/path/to/private/reproduced-vectors.tsv
cmp crates/formats/exacopy-manifest/verification/sync_baseline/vectors.tsv \
  /absolute/path/to/private/reproduced-vectors.tsv
cargo nextest run --locked -p exacopy-manifest --no-tests fail -- \
  --exact independent_workflow_baseline_vectors_bind_scope_evidence_and_canonical_bytes
```

Four synthetic valid vectors exercise raw non-UTF-8 bytes, maximum
basename, an empty stream with reversed read order, and the signed
length ceiling. Forty-six independently digest-bound refusal vectors
cover references, native projections, timing and canonical CBOR shape.
Right-side cases include wrong final root/file identity, changed stability
and a final check after the right read but before the later left read.
Other Rust checks exercise every truncation and separately selected wrong
references. Ordinary single-file Manifest vectors remain unchanged.
