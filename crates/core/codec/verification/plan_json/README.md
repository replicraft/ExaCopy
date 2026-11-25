# Unsigned public Plan JSON vectors

The fixtures pair the public Plan v1 JSON schema with its canonical CBOR
projection. The reference script uses independent Python field mappings and
the checked-in Plan body reference encoder. The BLAKE3-256 digest uses the
portable C implementation from the pinned BLAKE3 package. The complete
fixture includes two page references, opaque binary identities, offset
timestamps, and extension integers at both CBOR limits.

Build the portable hash tool using the recipe in
[manifest vectors](../manifest/README.md), then run
`python3 -B reference.py --hash /path/to/hash` in this directory. Use
`--write` to regenerate fixture bytes in a disposable checkout.

The unsigned profile requires each body field, rejects attached approval,
and canonicalizes RFC 3339 timestamps to UTC after checking the four-digit
year and nanosecond limits. Extension values support null, booleans,
UTF-8 text, integers in the CBOR base range, definite arrays, and
text-keyed maps with unique keys. The JSON document is limited to 8 MiB
and 33 nested containers. The canonical body retains its own 1 MiB and
32-container limits. The byte limits describe wire representations.

These checks cover R-155, R-182, R-187, and R-188 for this parser. They
exercise semantic digest binding, canonical field encoding, and exact
large integer representation. Page loading, approval verification,
execution, and platform effects belong to separate gates.
