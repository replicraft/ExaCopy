# Plan parser fuzzing

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
bash crates/formats/exacopy-plan/verification/plan_entries/check-fuzz.sh
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
bash crates/formats/exacopy-plan/verification/plan_body/check-fuzz.sh
```

The runner uses AddressSanitizer and 250,000 inputs with seed 441038, a
1,048,577-byte input limit, a two-second input timeout, a 90-second campaign
cap, and a 768 MiB RSS limit. It records the sanitizer symbols, source and
lockfile hashes, resolved graph, result and retained failure artifacts.


## Unsigned public Plan JSON

The `plan_json` target parses arbitrary unsigned envelopes, reserializes
accepted values and checks exact canonical-body and digest preservation.
The corpus includes complete and incomplete independent vectors, attached
approval, invalid timestamps, extension integer extremes, duplicates and
integer-valued versus fractional resource-count spellings. The runner adds
an input one byte over the JSON limit without changing committed seeds.

```sh
bash crates/formats/exacopy-plan/verification/plan_json/check-fuzz.sh
```

This AddressSanitizer campaign requires 250,000 inputs with seed 441039,
an 8,388,609-byte input limit, a two-second input timeout, a 90-second
campaign cap and a 768 MiB RSS limit. Exact input hashes, resolved graph,
sanitizer symbols, completion status and failure artifacts are retained.
The independent nightly lane uses the same locked runner.
