# Verified local performance baseline

The [workload specification](../../specs/performance/workloads.v1.json) defines the measurement boundary, budgets and future matrix. The first measurements use the locked optimized CLI at `a61ab02127a4bf9c3086ce47ceb310047888f831`. Each subject ran one excluded warm-up and nine measured trials with generated fixtures. Both measured cache profiles are warm. The evidence records each sample, host configuration, compiler, dependency lock, and benchmark runner digest.

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

The APFS measurements describe an Apple M1 Pro host reading warm files. The ext4 measurements describe a 4-vCPU aarch64 VM and a virtio-backed guest volume. Physical-media bandwidth, cold-cache comparisons and power-loss qualification remain outside the run. Verification phase timing, random I/O, million-entry trees, physical HDD/SATA/NVMe and network drives, lossy SFTP and embedded WireGuard, Android USB/wireless, recovery costs, GUI latency and repository growth have explicit workloads in the [future matrix](../../specs/performance/workloads.v1.json).

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
