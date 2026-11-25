# ExaCopy

ExaCopy is a Rust project for file transfers, comparison, and backup. The Linux CLI compares regular files byte for byte and copies one regular file into an absent name. It verifies the private stage by independent BLAKE3 read-back, synchronizes publication intent before an exclusive rename, and commits a receipt. Recovery can inspect a retained job and complete the journal and receipt for an already-published copy.

```sh
cargo run --locked -p exacopy-cli -- diff LEFT RIGHT --format json
cargo run --locked -p exacopy-cli -- profile init PRIVATE_PROFILE
cargo run --locked -p exacopy-cli -- copy SOURCE TARGET --profile PRIVATE_PROFILE --format json
cargo run --locked -p exacopy-cli -- recover inspect JOB_DIRECTORY --profile PRIVATE_PROFILE --format json
cargo run --locked -p exacopy-cli -- recover finish JOB_DIRECTORY --profile PRIVATE_PROFILE --format json
```

The copy report identifies the job directory inside the target's parent. See the [CLI guide](crates/clients/cli/README.md) for supported inputs, recovery outcomes, and exit codes.

Use Rust 1.100.0 and cargo-nextest 0.9.151 for the developer checks.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked --workspace --profile ci
cargo test --locked --workspace --doc
cargo run --locked -p xtask -- check
```

The [foundation](docs/foundation.md), [Linux adapter](docs/local-adapter.md) and [verified staging](docs/verified-staging.md) work packages describe the current safety contracts and evidence. The original code is available under [Apache-2.0](LICENSE).
