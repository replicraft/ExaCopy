# Portable manifest parser fuzzing

The `manifest_json` target sends arbitrary bytes to
`SingleFileManifest::from_json`. It checks that the byte limit applies
before parsing, that rejected records receive the same error on repeated
decoding, and that accepted records meet the supported basename, identity
and stream-length invariants. Serializing and reparsing an accepted
manifest must preserve its typed fields, canonical CBOR body and digest.
The target also checks rejection of a trailing non-whitespace byte.
It compares no JSON text for canonical equality.

The seeds include independent valid envelopes, raw non-UTF-8 basenames,
a display annotation, truncated and invalid UTF-8 input, duplicate and
unknown fields, unsupported shapes, a wrong body digest, and inputs at
and above the byte limit.

Run from the repository root with the pinned Rust nightly and cargo-fuzz
0.13.2. The first argument is an optional new evidence directory.

```sh
bash crates/core/codec/verification/manifest/check-fuzz.sh
```

The runner uses AddressSanitizer, 250,000 inputs, seed 18723, at most
16,385 input bytes, a two-second input timeout, a 90-second campaign cap
and a 768 MiB RSS limit. It records toolchain versions, source and
lockfile hashes, the resolved fuzz graph, the fuzzer log and exit status.
The committed seed files stay read-only. Any added corpus entries and
failure artifacts go into the evidence directory. An incomplete campaign
does not count as completed evidence.
