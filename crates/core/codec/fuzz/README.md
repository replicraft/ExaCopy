# Codec parser fuzzing

## Portable manifest JSON

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

## Public PlanEntries pages and document references

The `plan_entries_page` target passes the original bytes to the standalone
`DocumentRef` reader. It also creates an expected address for those same
bytes using the registered page digest framing. This exercises the page CBOR
decoder beyond its length and digest gates, including well-addressed malformed
pages. Accepted pages and references must reproduce their exact canonical bytes.
The target checks accepted entry bounds and rejects a modified page digest.

The deterministic corpus includes independent page and reference fixtures,
unsupported kind and array forms, trailing data, truncation, and a non-preferred
integer. The runner generates an additional input one byte over the 256 KiB
page limit in the evidence directory.

```sh
bash crates/core/codec/verification/plan_entries/check-fuzz.sh
```

This run uses AddressSanitizer, 250,000 inputs, seed 441037, at most 262,145
input bytes, a two-second input timeout, a 90-second campaign cap and a
768 MiB RSS limit. It checks the budget actually completed and records
sanitizer symbols, exact input and lockfile hashes, the resolved dependency
graph, engine output, and any failure artifacts.

## Public Plan bodies and extensions

The `plan_body` target checks both the digest-bound Plan body and the standalone
extension reader. It derives an expected Plan digest over each arbitrary input
so malformed bodies reach the field decoders. Accepted input must reproduce
its canonical bytes and typed bounds. A changed expected digest must fail.

The corpus includes independent complete and incomplete bodies, canonical
extension maps, malformed maps, bounds violations, unsupported version and
values, and a generated input one byte over the 1 MiB profile.

```sh
bash crates/core/codec/verification/plan_body/check-fuzz.sh
```

The runner uses AddressSanitizer and 250,000 inputs with seed 441038, a
1,048,577-byte input limit, a two-second input timeout, a 90-second campaign
cap, and a 768 MiB RSS limit. It records the sanitizer symbols, source and
lockfile hashes, resolved graph, result and retained failure artifacts.
