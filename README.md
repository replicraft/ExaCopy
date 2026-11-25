# ExaCopy

ExaCopy is a Rust project for file transfers, comparison, and backup. The current foundation models one preserve-mode copy attempt and verifies its decisions. Filesystem operations and the command-line application are future work.

Use Rust 1.100.0 and cargo-nextest 0.9.151 for the developer checks.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked --workspace --profile ci
cargo test --locked --workspace --doc
cargo run --locked -p xtask -- check
```

The [foundation work package](docs/foundation.md) describes the current safety contract and evidence. The original code is available under [Apache-2.0](LICENSE).
