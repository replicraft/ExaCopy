# Journal envelope fuzzing

`journal_frame` checks that the decoder limits each input buffer and returned payload to 1 MiB, advances only by exact frame sizes, and stops after the first error. It re-encodes every accepted frame and compares the complete bytes with the original input. The input-size budget caps this campaign at 512 bytes per input. The frame integration tests separately exercise a payload at the full 1 MiB format limit.

The seed corpus contains independently generated, valid checksummed frames from the framing tests, including a valid sequence gap. It also covers an oversized length, an unsupported kind, interrupted integrity trailers, and a broken chain followed by later magic bytes. Raw canonical recovery-decision seeds exercise both kind-20 payload variants. The target verifies exact re-encoding and disjoint admission for those variants, including when a decoded frame carries a kind-20 payload. The independently emitted kind-3 payload and immutable range-page vectors exercise both bounded range codecs. The range seeds carry an input derived from the canonical EntryPrepared vector used in the journal integration tests. Replay, ownership, and effect authority have separate checks.

From the repository root, use cargo-fuzz 0.13.2, the isolated tool lockfile, and Rust nightly-2026-11-04 on a target with AddressSanitizer support.

```sh
fuzz_dir="$PWD/crates/storage/journal/fuzz"
run_dir="$(mktemp -d)"
nightly_rustc="$(rustup which --toolchain nightly-2026-11-04 rustc)"
export PATH="$(dirname "$nightly_rustc"):$PATH"
export RUSTC="$nightly_rustc"
mkdir -p "$run_dir/corpus" "$run_dir/crashes"

cargo metadata --locked --manifest-path "$fuzz_dir/Cargo.toml" \
  --format-version 1 >/dev/null
cargo fuzz run --fuzz-dir "$fuzz_dir" --target-dir "$run_dir/target" \
  --sanitizer address journal_frame "$run_dir/corpus" "$fuzz_dir/corpus/journal_frame" \
  -- -seed=18723 -runs=250000 -max_len=512 -max_total_time=45 -timeout=2 \
  -rss_limit_mb=768 -artifact_prefix="$run_dir/crashes/"
```

Check the reported iteration count against the 250,000-input budget. The writable corpus and crash artifacts stay in the scratch directory.
