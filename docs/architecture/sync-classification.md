# Two-way synchronization classification

`exacopy-model::classify_two_way_path` previews one regular-file path from
complete paired inventories and a caller-validated common baseline. Verified
file evidence compares stream length, content digest and required metadata
digest under the same policy. Unknown observations block classification;
unsupported entries and intentionally asymmetric baselines require review.

Without common history, a one-sided file is an additive copy candidate;
different files conflict. With a common file, a one-sided edit can nominate
protected replacement. Deletion against an unchanged or edited peer requires
review; the classifier never authorizes deletion. Matching observations do
not publish a baseline or tombstone. Incomplete inventory blocks every path.

Inputs assume authenticated pair/generation/policy and valid observations.
There is no inventory scanner, persistent baseline, executor or mutation
capability here. Copy candidates still require approved Plans and qualified
protected/recovery operations. This is a partial R-269/R-270 slice.

P-041 independently enumerates 432 bounded classifier subjects and replays
all of them against the Rust API. Its TLA+ model also checks that abstract
baseline admission requires complete observations, matching receipts from
both endpoints and a current predecessor generation. The linked proof
notes give the bounds, negative controls and reproduction commands.
Baseline persistence, protected transfers and native recovery remain open.
[SyncBaseline proof notes](../../crates/foundation/exacopy-model/verification/tla/SYNC_BASELINE.md)

Six table-driven tests passed with the existing model suite and doctest.
Five independent source mutations were caught, covering omitted metadata,
incomplete/unknown observations, incumbent preservation and fabricated
common history. Private evidence remains in
`/private/tmp/exacopy-sync-classifier.FcNbHd3K`; older model coverage results
exclude this module.
