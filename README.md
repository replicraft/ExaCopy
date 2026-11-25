# ExaCopy

ExaCopy is a Rust project for file transfers, comparison, and backup. The foundation models one preserve-mode copy attempt and verifies its decisions. The Linux adapter implements the underlying read, stage and exclusive publication operations. The command-line application is future work.

Use Rust 1.100.0 and cargo-nextest 0.9.151 for the developer checks.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked --workspace --profile ci
cargo test --locked --workspace --doc
cargo run --locked -p xtask -- check
```

The [foundation](docs/foundation.md) and [Linux adapter](docs/local-adapter.md) work packages describe the current safety contracts and evidence. The original code is available under [Apache-2.0](LICENSE).
