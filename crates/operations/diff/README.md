# Exact file comparison

`exacopy_diff::linux::compare` takes two already opened Linux `SourceFile` capabilities and caller-owned scratch. It compares the recorded logical extents of the held descriptors. It uses no pathname lookups, creates no files, and holds no mutation capability. Ordinary reads may update access times.

The comparator checks the logical end and recorded metadata of each file before and after each decision. It compares nonempty extents of equal lengths in successive positional windows, reading sparse holes as logical zero bytes. A successful result describes the live observations. An observation change, failed exact read, or invalid input makes the comparison inconclusive. The caller must supply storage files on filesystems where the captured length describes the logical byte stream. Linux virtual files can report synthetic lengths and fall outside this scope.

Equality covers every byte in both recorded extents. A difference reports the two unequal recorded lengths or the offset of the first unequal byte. The offset is a witness of inequality. Complete range reporting, patch construction, and tree traversal require further work.

The total buffer cap is 8 MiB. The two inputs share caller scratch equally, with the remainder unused if the supplied byte count is odd. The comparison allocates no intermediate storage, even for an extent near the common signed file-length limit.

This slice covers the local single-file portions of R-007, R-093, R-097 and R-100 under ADR-017 and invariants INV-001, INV-013, INV-016 and INV-017. Injected reader tests cover first, interior and final mismatches, short final windows, both observation boundaries and partial read failures. Native tests cover regular and sparse files, stale observations and preservation of both inputs. The full A-093, A-097 and A-100 cases have further remote, tree or syscall-audit scope. The diff crate's P-009 reconstruction and P-029 merge obligations apply to later work. Filesystem qualification and stable snapshots remain separate.

```sh
cargo nextest run --locked -p exacopy-diff
cargo test --locked -p exacopy-diff --doc
```

## Bounded parallel comparison

The opt-in `exacopy_diff::linux::compare_parallel` entry point uses the same held read-only views, observation checks, and byte comparison. The caller chooses a worker ceiling from 1 through 16. The active count also depends on the stream extent and scratch available. The same 8 MiB cap applies to the entire comparison, split among disjoint worker buffers. Each worker reads a contiguous logical range in order. The comparison has no work queue and uses at most two held file capabilities.

The coordinator joins the workers and reduces their outcomes in byte order. A mismatch can only be returned if every earlier window read successfully and compared equal. An outstanding speculative read in a later range joins before any result is returned. Thread start and worker panic failures are inconclusive. The final observation check follows the joins. Files remain live-observed, and results use only the bytes actually read.

The portable tests and the [three-range scheduling model](verification/tla/ParallelCompare.tla) exercise P-036. Linux adapter tests exercise the public API with sparse files, ordered mismatches, stale observations and content preservation. These checks cover a per-call worker and scratch budget, contributing to R-082 and A-097. Applications that run simultaneous comparisons account for their aggregate budgets. The CLI uses serial comparison by default and accepts an explicit [worker ceiling](../../clients/cli/README.md). The tested budget applies to each comparison.

Run the local gate using the TLC and Temurin versions pinned in the [TLC toolchain lock](verification/tla/toolchain.lock.json). Set `TLC_LOG_DIR` to retain the model and negative-control logs.

```sh
crates/operations/diff/verification/check.sh
```

## Managed APFS on macOS

`exacopy_diff::macos::compare` and `compare_parallel` take two managed APFS read handles from `exacopy_platform::macos`. The platform adapter admits and revalidates both files under the trusted owner's managed-root grant. The same byte comparator, scratch and worker bounds, result types, and error phases apply. Adapter failures propagate with their side and operation. Results describe live observations of the held views. See the [CLI instructions](../../clients/cli/README.md#managed-apfs-comparison-on-macos) for the grant and native fixture test. The fixture exercises the adapter on its host filesystem.
