# Unix filename component fuzzing

`unix_component` compares `UnixComponent::new` against the standard Unix path iterator. A valid input must consist of one ordinary path component whose bytes match the whole input. The oracle also applies the 255-byte limit and rejects embedded NUL. The target checks that accepted bytes round-trip exactly, including names that contain backslashes or invalid UTF-8.

Use `cargo-fuzz` 0.13.2, the dependencies pinned in `Cargo.lock`, and Rust `nightly-2026-11-04` on a Unix target with AddressSanitizer support. Run the following commands from the repository root.

```sh
fuzz_dir="$PWD/crates/foundation/exacopy-core/fuzz"
run_dir="$(mktemp -d)"
nightly_rustc="$(rustup which --toolchain nightly-2026-11-04 rustc)"
export PATH="$(dirname "$nightly_rustc"):$PATH"
export RUSTC="$nightly_rustc"
mkdir -p "$run_dir/corpus" "$run_dir/crashes"

cargo metadata --locked --manifest-path "$fuzz_dir/Cargo.toml" \
  --format-version 1 >/dev/null
cargo fuzz run --fuzz-dir "$fuzz_dir" --target-dir "$run_dir/target" \
  --sanitizer address unix_component "$run_dir/corpus" "$fuzz_dir/corpus/unix_component" \
  -- -seed=18723 -runs=250000 -max_len=512 -max_total_time=15 -timeout=2 \
  -artifact_prefix="$run_dir/crashes/"
```

Check the reported iteration count to confirm that the run completed its 250,000-input budget. New entries and failures go into the scratch directory. The nonempty synthetic seeds cover dot and parent names, absolute and nested paths, trailing separators, NUL, backslash, invalid UTF-8, and both sides of the length limit. LibFuzzer exercises empty input during initialization.
