# Single-file public manifest vectors

The checked-in envelopes and CBOR bodies come from an independent Python
projection and byte encoder. The recipe computes both standard stream
digests and envelope digests with the portable C implementation in the
locked BLAKE3 1.8.7 package. The maximum-length vector uses a synthetic
digest to test the wire type without requiring an actual large file.

The JSON view uses portable RFC 4648 padded base64, lowercase digests and
canonical UUID text. The CBOR projection uses definite containers, shortest
arguments and RFC 8949 core deterministic encoded-key order. Each map in
this profile uses either numeric keys or text keys. The entry's text keys are
ordered as `path`, `streams`, `file_type`, `metadata_ref`. Display hints
are omitted from the canonical projection. The envelope digest covers the
NUL-terminated `ExaCopy/manifest/v1` domain followed by the canonical bytes.

To regenerate without writing into the workspace, copy this directory to a
temporary location, run `bash build-hash.sh PATH_TO_BLAKE3_1_8_7_C_SOURCES`,
and then run `python3 reference.py` there. Use the `c` directory of the
checksum-verified crate archive. The Rust manifest integration tests compare
the independent fixture CBOR byte for byte and verify its envelope digest.
The fixture byte checks do not exercise filesystem identity or publication.

## Parser fuzzing

The [manifest JSON fuzz target](../../fuzz/README.md) exercises R-182 and
A-182 for this parser, including byte admission, bounded component
construction, and typed re-encoding. Run `bash check-fuzz.sh` from this
directory with the pinned tools. Its evidence covers exercised parser
paths under AddressSanitizer. Future formats and filesystem effects
require their own verification.
