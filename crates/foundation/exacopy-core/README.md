# ExaCopy Core

`exacopy-core` owns the validated raw Unix filename component and the shared
job, entry, run-epoch and private-stage identity types. The component keeps
the original bytes. The identity types take values supplied by the caller.
The library forbids unsafe code and uses UUID only for UUIDv7 job validation.

The safety model owns transaction bindings, authorization and recovery
decisions. Platform adapters own filesystem name equivalence and held
filesystem operations. Public format crates own their version and encoding
policies. See the [architecture guide](../../../docs/architecture.md) for
the dependency boundaries.

## Reproduce checks

Run commands from the workspace root with the pinned toolchain and dependencies
described in the [workspace README](../../../README.md).

```sh
cargo test --locked -p exacopy-core
crates/foundation/exacopy-core/verification/check.sh kani
cargo bench --locked -p exacopy-core --bench unix_component
```

The [obligation ledger](verification/obligations.toml) records the bounded
Kani component contract and links the production validator. The [fuzz
instructions](fuzz/README.md) cover the independent component oracle and
synthetic corpus.

## Component benchmark

The [harness](verification/benchmarks/unix_component.rs) measures three fixed
paths separately. It uses a short accepted name, an accepted name at the
byte limit, and a name at the limit with a terminal NUL. It checks the
expected outcomes before timing. Each case runs three untimed warm-up
batches, followed by nine batches of 100,000 validations. The reported
minimum, median and maximum describe batch-average nanoseconds per call.
They include the loop and optimizer barrier overhead. Compilation and
process startup are outside the timed batches.

Record the revision, compiler and target, build profile, CPU and host load
when keeping results. Compare only equivalent inputs and profiles. The
harness measures warm pure validation. Filesystem observations and cold
start costs require separate measurements.
