# Verified local performance baseline

The [workload specification](../../specs/performance/workloads.v1.json) defines the measurement boundary, budgets and future matrix. The first measurements use the locked optimized CLI at `d82ce08b78f770e500de9b2c7965f24d625b757a`. Each subject ran one excluded warm-up and nine measured trials with generated fixtures. Both measured cache profiles are warm. The evidence records each sample, host configuration, compiler, dependency lock, and benchmark runner digest.

| Workload | ExaCopy median wall time | Independent comparison median |
| --- | ---: | ---: |
| 4 KiB exact equality, APFS | 3.73 ms (1 worker) | 2.07 ms (`cmp -s`) |
| 64 MiB exact equality, APFS | 42.13 ms (1 worker), 15.24 ms (up to 4) | 101.38 ms (`cmp -s`) |
| 64 MiB first-byte difference, APFS | 5.06 ms (1 worker), 5.40 ms (up to 4) | 2.70 ms (`cmp -s`) |
| 64 MiB final-byte difference, APFS | 41.86 ms (1 worker), 15.34 ms (up to 4) | 103.51 ms (`cmp -s`) |
| 4 KiB verified copy, ext4 guest | 17.51 ms | — |
| 64 MiB verified copy, ext4 guest | 372.02 ms (172.03 MiB/s) | — |

Comparison measurements cover process launch, the full relation decision and its report. The macOS exact-comparison process peaked at 9.59 MiB RSS across the measured profiles. The large ext4 copy’s median was 236.88 ms process CPU, with 20.75 MiB peak RSS and a 259.02–482.15 ms wall-time range. Small copy was 3.39 ms process CPU and 18.88 MiB peak RSS. See [managed APFS data](../../specs/performance/evidence/macos-apfs-comparison.json) and [ext4 guest data](../../specs/performance/evidence/linux-ext4-copy.json).

The timed copy includes the CLI’s source read, staged write, readback, required metadata and persistence barriers, exclusive publication, receipt commitment and report. Profile creation and fixture generation are outside the clock. The validation pass independently compares bytes, checks the source identity and contents, checks the target mode and mtime, and inspects the authenticated committed job. The timing excludes the validation pass. The copy report marks durability `unconfirmed`. Do not sum multiworker CPU as wall time. Early mismatches have a useful latency but cannot be assigned full-extent throughput. Rsync runs in the guest as a compatibility control with different assurance, so the copy table has no relative rsync figure.

The APFS measurements describe an Apple M1 Pro host reading warm files. The ext4 measurements describe a 4-vCPU aarch64 VM and a virtio-backed guest volume. Physical-media bandwidth, cold-cache comparisons and power-loss qualification remain outside the run. Verification phase timing, random I/O, million-entry trees, physical HDD/SATA/NVMe and network drives, lossy SFTP and embedded WireGuard, Android USB/wireless, broader recovery scenarios, GUI latency and repository growth have explicit workloads in the [future matrix](../../specs/performance/workloads.v1.json).

## Linux checkpoint recovery

The optimized CLI at `7cf7e9d72170db9576160edb57a3ff32c2381b58` completed five measured warm trials per operation after one excluded warm-up each. The source was one generated, fully allocated 128 MiB file on the same ext4 guest volume as the destination. The guest had four vCPUs, 4.79 GiB of RAM, and about 544 MiB of available filesystem space at the start. [Recovery measurements and configuration](../../specs/performance/evidence/linux-ext4-checkpoint-resume.json)

| Verified 128 MiB operation | Median wall time | Wall-time range | Median process CPU | Peak process RSS |
| --- | ---: | ---: | ---: | ---: |
| Fresh copy | 624 ms | 489–742 ms | 471 ms | 21.38 MiB |
| Resume with a valid 64 MiB checkpoint | 601 ms | 566–965 ms | 546 ms | 21.38 MiB |

The runner reconstructs a pre-publication fixture from an authenticated copy, keeping the first checkpoint and the matching private inode. Setup runs outside the clock. The timed resume includes revalidating the retained bytes against the source, writing the suffix, reading back the whole stage, applying metadata, publishing, committing the receipt, and reporting the result. GNU `cmp`, SHA-256, metadata and inode checks, journal and receipt inspection, and a repeat invocation validate the completed result outside the clock. A separate syscall trace found 16 successful stage writes totaling exactly 64 MiB from offset 64 MiB through EOF. The observed writes skipped the retained prefix. The wall-time ranges overlap, and resume used more median process CPU in this run. [Recovery samples and syscall trace summary](../../specs/performance/evidence/linux-ext4-checkpoint-resume.json)

The fixture models a retained pre-publication job. Process-kill recovery and power-loss behavior have separate evidence requirements. An earlier run stopped when fresh copy returned exit 4 with empty stdout and stderr under concurrent guest activity. The cause remains unconfirmed. Its samples are excluded from the five-trial results. [Incomplete execution record](../../specs/performance/evidence/linux-ext4-checkpoint-resume-incomplete.json)

## Reproduce

Build from a clean production tree with the pinned Rust toolchain. Set `SCRATCH` to a trusted native volume. This is `/private/tmp` on a qualifying managed APFS host, or a private ext4 parent for the copy lane. Never use a real source or destination tree. Allow at least 800 MiB for the default trial count, or 2 GiB for 30 trials, in addition to build space. Use Python 3.11+, `cmp`, and rsync for the copy lane. The macOS runner uses the system C compiler to provision explicit empty ACLs. Use a new output file on each run.

```sh
cargo build --locked --release -p exacopy-cli
mkdir -p target/reference
PYTHONDONTWRITEBYTECODE=1 python3 tools/reference/run.py compare \
  --binary target/release/exacopy --scratch-parent "$SCRATCH" \
  --hardware 'CPU, RAM, local device and filesystem topology' \
  --output target/reference/comparison.json
PYTHONDONTWRITEBYTECODE=1 python3 tools/reference/run.py copy \
  --binary target/release/exacopy --scratch-parent "$SCRATCH" \
  --hardware 'CPU, RAM, virtualization and filesystem topology' \
  --output target/reference/copy.json
```

Run `copy` on Linux. The comparison runner supports Linux and managed macOS. For an exact re-run of an archived source revision, follow the [archive procedure](../compatibility/local-references.md#reproduce-the-managed-apfs-differential). The runner refuses to count mismatches and produces a structured failed result. Preserve it with the captured diagnostics and any passing results from the same work package.

The checkpoint runner requires Linux ext4, Python 3.11+, GNU `cmp`, `strace`, and at least 320 MiB of additional fixture space. For an archived production tree, place the checkpoint runner under its `tools/benchmarks/` directory, and pass the archived commit through `--source-revision`. Set `--repeats 5` to use the five-trial schedule. The example captures process output on tmpfs and keeps the file data and journal under `$SCRATCH`.

```sh
cargo build --locked --release -p exacopy-cli
mkdir -p target/reference
TMPDIR=/dev/shm PYTHONDONTWRITEBYTECODE=1 python3 tools/benchmarks/linux_resume.py \
  --binary target/release/exacopy --scratch-parent "$SCRATCH" \
  --hardware 'CPU, RAM, virtualization and filesystem topology' \
  --output target/reference/checkpoint-resume.json
```
