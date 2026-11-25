# Linux retained-job compatibility evidence

This check exercises unchanged private Linux formats between two pinned development revisions. It covers explicit format admission and preserve-mode recovery under INV-001, INV-002, INV-009 and INV-019. The negative cases supply evidence for R-186 and A-186 at the CLI boundary.

## Inputs and reproduction

Run the [two-binary compatibility harness](../../apps/exacopy-cli/tests/contract_compatibility.py) with Python 3.11 or newer on Linux. Build each revision from a clean source archive and use separate Cargo target directories. Pass a scratch directory on the filesystem under test. Each direction creates its own private fixture with a sparse synthetic source, an unrelated incumbent, a profile created by the writer, and a real copy that produces a journal, checkpoint pages and a receipt.

```sh
# In each pinned revision's extracted workspace
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo +1.100.0 build --offline --locked -p exacopy-cli

# On Linux, with the two resulting executables
python3 -u apps/exacopy-cli/tests/contract_compatibility.py \
  /path/to/older/exacopy /path/to/newer/exacopy /path/to/ext4/scratch
```

| Build | Source revision | Cargo.lock SHA-256 | Executable SHA-256 |
| --- | --- | --- | --- |
| Older | `3080f2796c9fcd063e70dca033f41a6f9b4ff7e2` | `faa5866165f670ef58ebbe9804dd543190d117018ad89ed446e38339edc6c126` | `cc1b932360419857e18967af6212eb5b0a3c3f28c8c0869bb25d4a6d714dd06f` |
| Newer | `7cf7e9d72170db9576160edb57a3ff32c2381b58` | `ebbe7a23da819caea738b58429928338b86ee486ba8bd1becca67cf6814b9109` | `1f757df2640dbb895c9fd176818a4b83e7766a15eb271d24ef15cb5ba6502ca7` |

The run used Rust `1.100.0 (0ef1bc386059596dada8fb65b50425aab2ea637a)` and Python 3.12.3 on an AArch64 Lima guest with Linux `6.8.0-147-generic`. The guest workspace and fixture used `/dev/vda1` ext4 mounted `rw,relatime,discard,errors=remount-ro,commit=30`. The binaries are unoptimized development builds using default CLI features. Harness SHA-256 is `d64aa760da54da5618d330480b3248c82e70cfb015476dbf74d2f4f1374e87a9`.

## Observed results

The two-binary harness started at 08:54:32 UTC on 2026-11-25. It exited 0 after 35.914 seconds.

| Case | Observed outcome |
| --- | --- |
| Older writer, newer reader | Completed-job inspection and repeated finish preserved all fixture members. The newer reader also finished from the older journal's retained publication intent. The older reader reopened the recovered job and a repeated finish left it unchanged. |
| Newer writer, older reader | Completed-job inspection and repeated finish preserved all fixture members. The older reader also finished from the newer journal's retained publication intent. The newer reader reopened the recovered job and a repeated finish left it unchanged. |
| Unknown journal, plan, receipt and range-page versions, plus an unknown required receipt feature | Both revisions returned `E_INTEGRITY` with exit 5 at all four recovery entry points and preserved the input artifacts. |
| Foreign profile and oversized profile seed | Both revisions returned `E_PROFILE_AUTHORIZATION` with exit 8 at all four recovery entry points and preserved the input artifacts. |

The clean build and compatibility transcript has SHA-256 `d8074b36f1cff68c593584e390330380585298a7029d91036cc656eadcbb4934`.

## Oracles and scope

The other revision must reopen the original owner profile and report the same clean, complete journal state. The harness requires byte equality of source and target. It checks SHA-256, modes, inodes and device IDs of all fixture members before and after read-only inspection, repeated finish and refused recovery. During completion from a retained publish intent, the journal may extend its original bytes and the process may create a receipt. The target inode and all other fixture members must match their prior state.

For the refusal checks the harness changes one supported marker or feature field in a disposable artifact. It requires an integrity failure with the corresponding decoder diagnostic at each of `inspect`, `finish`, `resume` and `retry`. A foreign profile or oversized fixed-length seed must give a profile authorization error. The harness checks that every refused command preserves the bytes and identities it received. It restores each edited artifact and reopens the genuine job as a positive control.

The interrupted state is reconstructed from the original authenticated journal prefix and the already-published inode, with the later receipt removed. A real recovery process then reads and completes that state. Process-kill timing, injected barriers, power-loss behavior, schema conversion and release migration need separate evidence. The current Linux job persists journal-referenced range checkpoint pages. A separate repository index remains planned.

The first newer build attempt ended with guest `ENOSPC` (transcript SHA-256 `a9145bf4e670bdbe9616bdd5fa232a0a845e5ddf14d84d1304a67ee216b9ef49`). Reusing the older workspace's target directory produced stale dependency metadata and an unresolved `ReadView` import (transcript SHA-256 `e4480a0ea9025072c43900403d29f188a608bf496f2c8f448b15118c764f1902`). The subsequent build preserved the older executable and used a fresh target directory for the newer workspace.
