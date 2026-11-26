# Synchronization genesis admission

The model predicate checks one explicitly selected scan of one raw
subject at two ordered roots. It consumes two independently completed
present regular-file measurements and two later final observations.
The predicate compares the selected identities, scope and policy, rejects
reused measurement positions and aliased objects, and requires equal
length, stream digest and required metadata digest. Each final observation
must match its measured side and follow both completed reads.

The bounded oracle enumerates every subset of 16 invalid conditions
against a fixed healthy pair, in both read orders. This gives 131,072
cases, including 2 accepting cases. The faults cover equal root
identities, swapped roots, missing measurements on either side, scope,
policy and scan substitutions, file aliases, reused read positions,
each unequal evidence field, missing final observations on either side,
changed stability and a partially stale final pair check. Each defect
invalidates a required fact in the reference contract. A separate
regression exercises a final observation from a different scan.

P-053 registers this bounded Rust gate in the owning obligation ledger.

Run the implementation-linked oracle from the workspace root.

```sh
cargo nextest run --locked -p exacopy-model --no-tests fail -- \
  --exact genesis_matches_independent_bounded_observation_oracle
```

The fixture's IDs and positions are synthetic. The model trusts admitted
callers to supply truthful rooted identity projections, independent stream
and metadata measurements, and monotonic sequence positions for one live
scan. The fixture covers finite combinations of reported facts. Native
observations, dependency verification, artifact publication, persistence
and effects require separate evidence. The seed result carries only
observations. Existing P-041 classifier and successor evidence keep
their recorded scope.
