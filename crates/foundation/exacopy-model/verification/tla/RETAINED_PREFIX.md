# Retained private prefix continuation

This independent model covers an owned one-unit retained prefix and a
two-unit suffix or no suffix, one old writer and two source epochs. The original
publication model and sync baseline checks retain their own scope.

Admission requires an unambiguous pre-intent replay, old-writer drain,
fresh source, authenticated exact held stage and lease, and fresh
comparison of all retained bytes plus the recomputed matching historical
hashes. Incomplete coverage, old epochs, uncertain history and bytes
past the old writer's authorized extent cannot authorize a tail permit.
The model abstracts those observed predicates. It separately requires a
confirmed prefix barrier and a durable, independently reread successor
before any admitted write. Each successfully completed unit uses the
selected fresh epoch and affects only the next tail position. Context
changes, ambiguous completions and uncertainty stop new authority.
No later completion can reopen a blocked stage.

The Rust model uses the exact next run, strictly increasing source
epoch, checked extent, existing range guard and physically observed
local end. A fully verified retained stage can reach durable continuation
with no tail writes. Source EOF and finalization still have separate checks.
Before issuing a tail permit the model checks the next ordinal, canonical
checkpoint end and closing journal byte and sequence capacity. It checks
the protected receipt capacity supplied by the storage owner. The owner
must hold those reservations under the lease and compute genuine canonical
and closing record sizes. The model binds the checkpoint to the reserved
ordinal and end. Each next permit requires the preceding chunk's verified data barrier
and independently confirmed durable checkpoint. The head advances by
exactly one sequence, with strictly increasing bounded journal offset,
the same continuation lineage and exact current run, source, stage, and
lease. No checkpoint crosses an outstanding write. The next chunk binds
the advanced head. The caller authenticates the
record body, verifies the actual previous and next heads, and keeps
the same exclusive lease, current grant, original source and truthfully
observed completed effects. No native authority is created by an
abstract transition. Successor receipt and publication still need
existing independent read-back and their own qualified finalization.

## Reproduce

Use the verified owning TLA+ toolchain pin and set TLA2TOOLS_JAR to the
checksum-pinned release. Set TLC_LOG_DIR to an owned evidence directory.

```sh
python3 -B crates/foundation/exacopy-model/verification/tla/check-continuation.py
cargo nextest run --locked -p exacopy-model --no-tests fail --test-threads 2 \
  -- --exact retained_prefix_requires_ordered_evidence_and_exact_tail_completions
```

The positive TLC run requires reached compare, prefix barrier, synced
continuation with and without a suffix, two tail completions, a checkpoint
between them, ambiguous completion and explicit block. Eight controls omit
durable continuation, allow prefix overlap, accept stale source or head
completions, lose the context check, skip a durable checkpoint, ignore
completion ambiguity or omit the pre-write closing budget. Deadlocks are intentional for
unavailable or blocked histories. No fairness or eventual progress is
asserted. The Rust regressions additionally exercise checked range
overflow, exact basis binding, historical extent and live extent at
operation boundaries. The tests and finite model are separate evidence.
Neither establishes native filesystem, reconnect, crash or power-loss
qualification.
