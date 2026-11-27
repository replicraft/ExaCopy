# ExaCopy

ExaCopy is a Rust project for file transfers, comparison, and backup. The Linux CLI compares regular files byte for byte, creates single-file content manifests, verifies against a selected baseline, and copies one regular file into an absent name. It verifies the private stage by independent BLAKE3 read-back, synchronizes publication intent before an exclusive rename, and commits a receipt. Recovery can inspect a retained job, resume an interrupted copy, retry publication of a verified stage, or complete the journal and receipt for an already-published copy.

## Installation

Cargo is the recommended way to build and install the CLI. From a checkout
with the pinned dependencies prepared as described below, run:

```sh
cargo install --locked --path apps/exacopy-cli
exacopy --help
```

Cargo installs `exacopy` into its executable directory, normally
`$HOME/.cargo/bin` (`%USERPROFILE%\.cargo\bin` on Windows). Add that directory
to `PATH` if your Rust installation has not already done so. The crates.io
command `cargo install --locked exacopy` is the intended registry entrypoint;
registry publication is still pending.

Unsigned archives for Linux, Apple Silicon macOS and Windows are available
in the [v0.1.0 testing prerelease](https://github.com/replicraft/ExaCopy/releases/tag/v0.1.0).
Verify the archive checksum, extract it into a fresh test directory, and
run the extracted executable directly. The [testing guide](docs/releases/v0.1.0.md)
identifies the separate experimental Linux SSH/WireGuard archive and its
known embedded trust parser issue.

For a prebuilt installation without installing Rust, use
[`install.sh`](docs/architecture/posix-offline-install.md) on macOS/Linux or
[`install.ps1`](docs/installation/windows.md) on Windows. These installers
select the platform archive, verify its checksum and publisher identity,
and install an owned launcher. Use a signed stable release or a signed
offline bundle with these scripts. Official signed release provisioning
remains pending.

## Usage

```sh
cargo run --locked -p exacopy-cli -- diff LEFT RIGHT --format json
cargo run --locked -p exacopy-cli -- manifest create SOURCE > baseline.json
cargo run --locked -p exacopy-cli -- verify SOURCE --manifest baseline.json --format json
cargo run --locked -p exacopy-cli -- profile init PRIVATE_PROFILE
cargo run --locked -p exacopy-cli -- copy SOURCE TARGET --profile PRIVATE_PROFILE --format json
cargo run --locked -p exacopy-cli -- recover inspect JOB_DIRECTORY --profile PRIVATE_PROFILE --format json
cargo run --locked -p exacopy-cli -- recover finish JOB_DIRECTORY --profile PRIVATE_PROFILE --format json
cargo run --locked -p exacopy-cli -- recover resume JOB_DIRECTORY --source-root SOURCE_DIRECTORY --profile PRIVATE_PROFILE --format json
cargo run --locked -p exacopy-cli -- recover retry JOB_DIRECTORY --source-root SOURCE_DIRECTORY --profile PRIVATE_PROFILE --format json
```

The copy report identifies the job directory inside the target's parent. See the [CLI guide](apps/exacopy-cli/README.md) for supported inputs, recovery outcomes, and exit codes.

On macOS, `diff LEFT RIGHT --managed-macos` enables exact comparison of regular files in explicitly provisioned owner-managed APFS directories. The flag attests that both input parents satisfy the [managed directory contract](apps/exacopy-cli/README.md#managed-apfs-comparison-on-macos).

Use Rust 1.100.0 and cargo-nextest 0.9.151 for the developer checks. Supply the
[pinned Pomologie sibling checkout](specs/dependencies/README.md) before
running Cargo on any target; verify it with `python3 -B tools/apfs_source.py`.
Cargo also needs the two pinned repaired transport sibling sources. Run
`python3 -B tools/transport_source.py --fetch` to reconstruct and verify
them before Cargo resolves the workspace. An existing crate cache can be
selected with `--crate-cache`. The source pins, reconstruction inputs and
review scope are documented in
[local transport source provenance](docs/supply-chain/local-transport-sources.md).


```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked --workspace --all-features --profile ci
cargo test --locked --workspace --all-features --doc
cargo run --locked -p xtask -- check
```

Start with the [architecture](docs/architecture.md) and
[roadmap](docs/roadmap.md). The [testing guide](docs/testing.md) covers local
checks and the feature matrix. The [verification guide](docs/verification.md)
identifies the current formal gates and their evidence. The original code is
available under [Apache-2.0](LICENSE).
