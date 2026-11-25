# Bounded sync classifier and baseline model

`SyncBaseline.tla` exercises the read-only two-way classifier for one logical
path and two fixed endpoints. It covers the classification and absence parts of
`R-269`, `R-270`, and `INV-025`. The modeled baseline-admission rule
checks a bounded portion of `INV-026`. The Rust classifier returns preview
decisions and holds no baseline publication capability.

## Search bounds and evidence

- Each endpoint has six observations: measured file A, B or C, observed
  absence, unknown and unsupported entry. A and B differ only in the content
  digest. A and C differ only in the required-metadata digest. Equal symbols
  represent equality of the measured tuple under the same policy. The model
  assumes the caller supplied truthful observations for the same raw path,
  pair and policy.
- Baselines are uninitialized, common absent, common present A/B/C, or
  asymmetric. One Boolean represents whether both endpoint inventories are
  complete. The full Cartesian product has 432 initial subjects.
- The model decides by combining endpoint-relative labels in a matrix after
  the completeness, observation and prior-baseline checks. TLC emits all 432
  input/decision rows. The runner validates the exact subjects and compares
  the emitted table to `SyncBaseline.classifier.tsv`. The Rust integration
  test replays every row against `classify_two_way_path` with synthetic
  evidence tuples. This finite replay covers the classifier. The subsequent abstract
  baseline steps have no Rust implementation in this package.
- One modeled scan is bound to generation 1. Another writer can advance to
  generation 2 before publication. Each endpoint can independently contribute
  one receipt. It may be missing, match the observation and scan generation,
  disagree with the observation, or bind the wrong generation. A common
  present match or a two-sided observed-absence candidate can advance the
  baseline only with matching paired receipts and while generation 1 is
  current. Accepted publication records that predecessor and moves to
  its successor. Other previews and receipt observations leave the accepted
  generation unchanged. Receipt loss is represented by a slot remaining
  missing. The model takes receipt authenticity and bound evidence as inputs.
- TLC checks all six invariants in every reachable state within these
  bounds. Stuttering permits terminal states and missing receipts. Deadlock
  detection is disabled, and the model makes no fairness or liveness claim.
  Multi-path inventory, fresh scans after stale observations, retained data,
  crash cuts, power loss, authenticated receipt production, concurrent
  filesystem changes and protected transfers remain separate work.

The three negative controls independently turn unknown evidence into observed
absence, allow publication without paired receipts, or allow a stale
predecessor. The runner requires the expected invariant violation for
each control. The stale trace must show another writer advancing before
`PublishBaseline`.

## Reproduce

Use Python 3.11 or newer, Temurin OpenJDK 21.0.8+9 on `PATH`, and the TLC
release JAR pinned in [toolchain.lock.json](toolchain.lock.json). From the
workspace root, run:

```sh
TLA2TOOLS_JAR=/absolute/path/to/tla2tools.jar TLC_LOG_DIR=/absolute/path/to/logs \
  crates/foundation/exacopy-model/verification/check.sh tlc
cargo nextest run --locked -p exacopy-model --no-tests fail -- \
  --exact sync_classifier_matches_all_tlc_subjects
```

The TLC entry point checks CopyRecovery and SyncBaseline. TLC uses a
local Java RMI socket during startup. The sync reports include SHA-256
bindings for the JAR, model, configurations, table, Rust classifier, replay
test and scripts. TLC uses one worker, seed 0 and fingerprint index 0.
Keep the positive report and each mutant log.

## Executed candidate result

TLC 2.19 at revision `5a47802` under Temurin `21.0.8+9-LTS` explored
1,824 states, including 1,329 distinct states through depth 4. The queue
was empty at completion and all 432 classifier rows matched the replay
fixture. The Rust replay passed with Rust 1.100.0 and nextest 0.9.151.

| Negative configuration | TLC exit | Invariant violated |
| --- | ---: | --- |
| `SyncBaselineTreatUnknownAsAbsent` | 12 | `UnknownPreventsInference` |
| `SyncBaselineSkipReceipts` | 12 | `PublicationRequiresPairedReceipts` |
| `SyncBaselineAllowStaleGeneration` | 12 | `PublicationRequiresCurrentPredecessor` |
