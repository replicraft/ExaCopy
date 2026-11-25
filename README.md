# ExaCopy

ExaCopy is a Rust project for file transfers, comparison, and backup. The Linux code can prepare a private job with signed ownership and a synchronized journal, then copy data into a private stage and verify it by independent BLAKE3 read-back. The command-line application and recovery are future work.

Use Rust 1.100.0 and cargo-nextest 0.9.151 for the developer checks.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked --workspace --profile ci
cargo test --locked --workspace --doc
cargo run --locked -p xtask -- check
```

The [foundation](docs/foundation.md), [Linux adapter](docs/local-adapter.md) and [verified staging](docs/verified-staging.md) work packages describe the current safety contracts and evidence. The original code is available under [Apache-2.0](LICENSE).
