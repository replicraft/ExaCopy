# PR 1. Executable copy decisions and proof path

`exacopy-core` owns typed job, entry, epoch and stage identities. `exacopy-model` owns their transaction binding, the preserve-mode decision state machine, and the checked write-range guard. `xtask` owns engineering policy and evidence validation. The work package uses ADR-005, ADR-006, ADR-012, ADR-067, ADR-068, ADR-075, and ADR-107 through ADR-116 from the local architecture pack.

| Scope | Requirements and acceptance | Invariants and obligations |
| --- | --- | --- |
| Preserve-mode effects and identity | R-007, R-008, R-013, R-015, R-017 and corresponding A-IDs | INV-001–004, INV-019, P-001–003 |
| Checked half-open write-range admission | R-018, R-176–179, R-181, R-319, R-321 and corresponding A-IDs | INV-013 and the single-range portion of P-004 |
| Independent reference histories, TLC and a counterexample replay | R-181, R-320, R-323–324, R-326–327 and corresponding A-IDs | INV-003, INV-032 |
| Reproducible workspace and evidence gates | R-190, R-317–318, R-325, R-329–330, R-332–339 and corresponding A-IDs | INV-020, INV-032 |

The [obligation manifest](../crates/foundation/exacopy-model/verification/obligations.toml) maps exactly which contracted properties are exercised by the initial gates. A gate pass applies to the specified test, theorem, harness, or finite model.

## Model contract

A session accepts events bound to the same job, entry, run epoch, and stage. After stage preparation it may request a read-only source operation. It authorizes one exclusive publication after the reported writer join, data barrier, read-back verification, metadata, seal, and journaled intent. It rejects mismatched identities, skipped prerequisites, and replayed publication intent. An ambiguous publication or later effect leads to `RecoveryRequired`. Cancellation before intent ends the attempt. An executor still needs to stop writer activity and preserve evidence when it reports that boundary.

The session uses fixed-size state and returns at most one effect per event. The range guard admits only positive-length half-open ranges whose exclusive end fits within the file. Both model surfaces are pure. A coordinator must supply unique bindings and truthful observations. Adapters must enforce read-only source access, matching physical identities, and atomic no-clobber publication under their declared filesystem contracts. The current interfaces have no disk format, wire compatibility commitment, or release profile. There is no durable authority to roll back or resume at this stage.

The independent CopyRecovery model has one entry and target, two epochs, and one crash. It explores an external incumbent, stale completion, lost reply, and namespace observations after restart. TLC must reject the deliberate early-publication mutant through `PriorPublicationEvidence`. The Rust regression replays the decision prefix. Physical namespace effects and recovery replay require a real executor and journal in later packages.

## Evidence and reproduction

The [verification dispatcher](../crates/foundation/exacopy-model/verification/check.sh) runs the crate-local Lean, Kani, TLC and Miri gates. The [CI workflow](../.github/workflows/ci.yml) supplies the pinned tools and keeps raw results. TLC checks its jar checksum and exact Temurin runtime. Miri runs the deterministic model tests with isolation enabled. Native nextest runs the generated properties and reads their persisted regressions.

With the formal tools installed, capture and validate model evidence from a clean checkout.

```sh
evidence_dir="target/foundation-evidence/$(git rev-parse HEAD)"
python3 tools/record_evidence.py "$evidence_dir"
cargo run --locked -p xtask -- check-evidence "$evidence_dir"
crates/foundation/exacopy-model/verification/check.sh miri
```

The recorder takes `--gate rust|lean|kani|tlc` for a single lane. It retains the command output and the TLC counterexample with their SHA-256 digests. These records carry execution results. Independent assurance review and filesystem qualification are separate gates. Supply-chain review remains subject to [cargo-vet's import policy](../supply-chain/config.toml).

The initial macOS ARM64 coverage run measured 100 of 100 model source lines and 94 of 94 regions. Nightly instrumentation measured 16 of 16 branches. The production-only mutation run caught 25 viable mutants. Six other edits failed to compile. Separate Kani checks exercise the symbolic harness. The initial coverage and mutation denominators covered `identity.rs`, `range.rs`, and `transaction.rs`. Current mutation sampling spans core identities, the model binding, the range guard, and the copy state machine. The line and branch coverage gate also includes the model sync classifier. The component validator has a separate line coverage gate.

The initial locked dependency scans passed cargo-deny and cargo-audit. Cargo-vet imported existing peer audits covering 12 of 69 third-party versions. The other 57 require evidence under the configured review criteria. This keeps the dependency gate open.

The local architecture pack passed its structural validation and executable design scenarios before implementation. Its supplied `START_HERE.md` differed from the SHA-256 inventory. The pack stayed outside Git, and its results are design evidence.
