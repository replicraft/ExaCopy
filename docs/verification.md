# Verification

[Engineering standards](engineering/standards.md) binds EES-1 and
EVS-1 to reviewed revisions. EVS-1 is the assurance authority. Each
work package identifies its requirements, invariants, acceptance cases,
assumptions and owners before enabling new safety-relevant behavior.

| Implemented owner | Obligations and reproduction |
| --- | --- |
| CLI command admission | [Obligations](../apps/exacopy-cli/verification/obligations.toml), [dispatcher](../apps/exacopy-cli/verification/check.sh), [separate native campaign](../apps/exacopy-cli/verification/remote/README.md) |
| Core model | [Manifest](../crates/foundation/exacopy-model/verification/obligations.toml), [dispatcher](../crates/foundation/exacopy-model/verification/check.sh), [foundation evidence](foundation.md) |
| Core | [Manifest](../crates/foundation/exacopy-core/verification/obligations.toml), [dispatcher](../crates/foundation/exacopy-core/verification/check.sh) |
| Diff | [Manifest](../crates/engines/exacopy-diff/verification/obligations.toml), [dispatcher](../crates/engines/exacopy-diff/verification/check.sh) |
| Manifest | [Obligations](../crates/formats/exacopy-manifest/verification/obligations.toml), [dispatcher](../crates/formats/exacopy-manifest/verification/check.sh) |
| Plan | [Obligations](../crates/formats/exacopy-plan/verification/obligations.toml), [dispatcher](../crates/formats/exacopy-plan/verification/check.sh) |
| Journal | [Obligations](../crates/storage/exacopy-journal/verification/obligations.toml), [dispatcher](../crates/storage/exacopy-journal/verification/check.sh) |
| Transfer | [Obligations](../crates/engines/exacopy-transfer/verification/obligations.toml), [dispatcher](../crates/engines/exacopy-transfer/verification/check.sh) |
| WireGuard | [Obligations](../crates/net/exacopy-wireguard/verification/obligations.toml), [dispatcher](../crates/net/exacopy-wireguard/verification/check.sh) |

The [verification owner inventory](../specs/verification/owners.toml) declares
each owner and its minimum gate kinds. Add an owner there when its first
crate-local ledger and dispatcher land. The workspace policy check requires
the registered packages, ledgers, dispatchers and declared gate kinds.
The crate-local ledgers own individual obligations and their linked inputs.

The same inventory registers native fixtures separately. A native fixture
manifest binds the owning package, target, profile, exact test selectors,
runner, controls, workflow and result filename. The protected-slot manifest
is under `crates/platform/exacopy-platform/verification/protected_slot/`.
Workspace validation checks the declarations and their source paths.
Native results require the corresponding execution and retained evidence.

Keep proofs, extraction, models, harnesses and obligation ownership in
`<crate>/verification/`. Root tooling [captures](../tools/record_evidence.py)
and validates scoped results. Preserve the original log and minimized
counterexample when a check fails.

The [P-071 Linux reservation fixture](architecture/remote-witnessed-closeout.md#p-071-linux-native-reservation)
is an adapter test selected on a Linux filesystem that supplies the needed
native primitives. Its result belongs to that recorded fixture profile.

A theorem covers its pinned source, statement, assumptions and trusted
computing base. TLC and Kani results are bounded by the actual model and
harness. Record native adapter tests, process-crash runs and hardware
power-loss qualification as separate evidence. Record toolchain, source and
lockfile revision, command, platform and feature profile, inputs, oracle,
exit status and artifact digests. A required unavailable or failed gate
blocks the claim it supports.

Use the [local adapter](local-adapter.md) and [verified
staging](verified-staging.md) to trace platform results. The [CI
workflows](../.github/workflows/) show the configured automation. Each run's
retained output establishes what actually executed.
