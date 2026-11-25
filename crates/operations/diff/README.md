# Linux exact file comparison

`exacopy_diff::linux::compare` takes two already opened Linux `SourceFile` capabilities and caller-owned scratch. It compares the recorded logical extents of the held descriptors. It uses no pathname lookups, creates no files, and holds no mutation capability. Ordinary reads may update access times.

The comparator checks the logical end and recorded metadata of each file before and after each decision. It compares nonempty extents of equal lengths in successive positional windows, reading sparse holes as logical zero bytes. A successful result describes the live observations. An observation change, failed exact read, or invalid input makes the comparison inconclusive. The caller must supply storage files on filesystems where the captured length describes the logical byte stream. Linux virtual files can report synthetic lengths and fall outside this scope.

Equality covers every byte in both recorded extents. A difference reports the two unequal recorded lengths or the offset of the first unequal byte. The offset is a witness of inequality. Complete range reporting, patch construction, and tree traversal require further work.

The total buffer cap is 8 MiB. The two inputs share caller scratch equally, with the remainder unused if the supplied byte count is odd. The comparison allocates no intermediate storage, even for an extent near the common signed file-length limit.

This slice covers the local single-file portions of R-007, R-093, R-097 and R-100 under ADR-017 and invariants INV-001, INV-013, INV-016 and INV-017. Injected reader tests cover first, interior and final mismatches, short final windows, both observation boundaries and partial read failures. Native tests cover regular and sparse files, stale observations and preservation of both inputs. The full A-093, A-097 and A-100 cases have further remote, tree or syscall-audit scope. The diff crate's P-009 reconstruction and P-029 merge obligations apply to later work. Filesystem qualification and stable snapshots remain separate.

```sh
cargo nextest run --locked -p exacopy-diff
cargo test --locked -p exacopy-diff --doc
```
