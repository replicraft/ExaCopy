# ExaCopy contributor instructions

Read the safety and acceptance scope in [the foundation work package](docs/foundation.md) before changing the model or an executor. When the local architecture pack is present, read its `START_HERE.md`, `SAFETY.md`, and EES-1 and EVS-1 standards before selecting a work package. Keep the local pack in `docs/temp/`.

Apply the [consolidated architecture reconciliation](docs/engineering/architecture-reconciliation.md), including its foundational `exacopy-core` amendment, over conflicting earlier supplemental organization instructions. Product executable packages belong under `apps/`; reusable libraries use fully prefixed package directories under `crates/<responsibility>/`. Engines consume capabilities; applications compose concrete adapters. Do not create empty packages to match a proposed tree.

Preserve source and incumbent destination content. Use typed, bounded decisions and check identity, quiescence, read-back verification, required metadata, and durable publication intent before authorizing exclusive publication. Unknown or uncertain outcomes require reconciliation. Separate abstract model results from adapter, process-crash, and power-loss qualification.

Use the one Cargo workspace, its root lockfile, and Rust 1.100.0, edition 2024, resolver 3. Inherit workspace dependencies and lints. Use hard tabs with four-column stops and split authored Rust files before 500 physical lines. Keep `lib.rs` and `mod.rs` declarative and `main.rs` limited to wiring and dispatch. Place proof inputs and harnesses under the owning crate's `verification/` directory.

Make focused Conventional Commits with tests. Give parallel contributors disjoint paths and serialize shared contracts and the lockfile. Run the workspace checks in the README and affected proof gates. Preserve failed and blocked evidence and keep their status visible. Verify the final integrated commit. Require explicit authorization to push.

Clean up task-owned temporary directories and files as part of the work, including subagent scratch checkouts, build caches, fixtures and stopped test infrastructure. Track their ownership, remove them promptly when no longer needed, and verify cleanup before finishing. Preserve required failure and verification evidence in a documented retained location before removing its scratch directory. Remove only artifacts created by the task; do not delete unrelated temporary files or shared caches. Subagents must report their cleanup or explicitly identify any retained artifacts and why they remain necessary.
