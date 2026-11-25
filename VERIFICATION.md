# Verification

[Engineering standards](docs/engineering/standards.md) binds EES-1 and
EVS-1 to reviewed revisions. EVS-1 is the assurance authority. Each
work package identifies its requirements, invariants, acceptance cases,
assumptions and owners before enabling new safety-relevant behavior.

| Implemented owner | Obligations and reproduction |
| --- | --- |
| Core model | [Manifest](crates/core/model/verification/obligations.toml), [dispatcher](crates/core/model/verification/check.sh), [foundation evidence](docs/foundation.md) |
| Endpoint | [Manifest](crates/endpoints/endpoint/verification/obligations.toml), [dispatcher](crates/endpoints/endpoint/verification/check.sh) |
| Diff | [Manifest](crates/operations/diff/verification/obligations.toml), [dispatcher](crates/operations/diff/verification/check.sh) |

Keep proofs, extraction, models, harnesses and obligation ownership in
`<crate>/verification/`. Root tooling [captures](tools/record_evidence.py)
and validates scoped results. Preserve the original log and minimized
counterexample when a check fails.

A theorem covers its pinned source, statement, assumptions and trusted
computing base. TLC and Kani results are bounded by the actual model and
harness. Record native adapter tests, process-crash runs and hardware
power-loss qualification as separate evidence. Record toolchain, source and
lockfile revision, command, platform and feature profile, inputs, oracle,
exit status and artifact digests. A required unavailable or failed gate
blocks the claim it supports.

Use the [local adapter](docs/local-adapter.md) and [verified
staging](docs/verified-staging.md) to trace platform results. The [CI
workflows](.github/workflows/) show the configured automation. Each run's
retained output establishes what actually executed.
