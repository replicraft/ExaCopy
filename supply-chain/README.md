# Rust dependency checks

Run these checks from the workspace root using the pinned CI tools.

```sh
cargo deny --locked check
cargo audit --deny warnings
cargo vet --locked
```

Cargo-deny checks source, licensing and RustSec policy across all workspace features and target-specific dependencies, including test dependencies. Cargo-audit reads the workspace lockfile and checks the RustSec advisory database. Cargo-vet uses its built-in criteria of `safe-to-deploy` for regular dependencies and `safe-to-run` for dev-only dependencies.

The cargo-vet configuration pins audit sources from the Bytecode Alliance, ISRG, Mozilla and Zcash. `imports.lock` records the audit paths cargo-vet found for the current lockfile. Audit entries preserve reviewer attribution and version scope from upstream. `audits.toml` stores ExaCopy's own audit records.

For a dependency update, review the workspace lockfile diff and run `cargo vet regenerate imports` to refresh the selected records from the pinned audit sources. Inspect the resulting diff and rerun the locked checks. Missing audit coverage blocks the vet gate until peer audits or reviewed local audit records satisfy the required criteria.
