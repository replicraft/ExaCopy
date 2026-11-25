# Independent compatibility checks

The [compatibility inventory](../specs/compatibility/inventory.v1.json) defines each reference profile, its acceptance cases, and its evidence status. An executed profile applies to the exact versions, platform, fixture and operation in its evidence. Acceptance IDs carry the architecture pack’s meanings. The local experiments exercise portions of A-008, A-009, A-093, A-100, A-185 and A-194. The incumbent experiment is a pre-existing-name case. The [native adapter tests](../local-adapter.md) cover concurrent incumbent creation and other platform behaviors.

ExaCopy 0.1.0 at `d82ce08b78f770e500de9b2c7965f24d625b757a` matched Apple `cmp` (`patch_cmds-61`) and rsync 3.5.2 checksum dry runs for seven regular-file pairs on managed APFS. One, four and sixteen worker ceilings all returned the expected byte or length witness. `cmp` followed a final symlink and reported equality. ExaCopy returned `E_OPEN_INPUT` without establishing a relation, as required by its capability-scoped path admission. `cmp` and the generated witness supply the exact oracle. Rsync supplies an independent content-update decision which uses a checksum shortlist. [Managed APFS differential evidence](../specs/compatibility/evidence/macos-apfs-differential.json).

On an aarch64 Ubuntu 24.04.5 LTS Lima guest with an ext4 volume, ExaCopy 0.1.0 at `7cf7e9d72170db9576160edb57a3ff32c2381b58` matched GNU diffutils `cmp` 3.10 and rsync 3.2.7 for the same seven pairs and three worker ceilings. GNU `cmp` followed the final symlink and reported equality. ExaCopy refused it with `E_OPEN_INPUT` and an inconclusive result. Each regular-file pair passed pre- and post-run checks for name, identity, contents, mode, link count and mtime. [Linux ext4 differential evidence](../specs/compatibility/evidence/linux-ext4-differential.json), [GNU cmp manual](https://www.gnu.org/software/diffutils/manual/html_node/Invoking-cmp.html), [rsync manual](https://rsync.samba.org/ftp/rsync/rsync.1).

With the same Linux build, rsync copied a 4 KiB fixture to a new name using `--ignore-existing`, and GNU `cmp` confirmed byte equality. Across both tools the source and the different pre-existing target retained their identities, bytes and checked metadata. Rsync signalled a successful skip. ExaCopy reported `E_CONFLICT` and no publication. The runner also verified six ExaCopy publications per size for 4 KiB and 64 MiB fixtures. Each passed independent `cmp`, target mode and mtime checks, source preservation, and committed-job inspection. The test exercised a pre-existing incumbent. Durability stayed `unconfirmed`. [Linux ext4 copy evidence](../specs/compatibility/evidence/linux-ext4-copy.json), [earlier performance baseline](../performance/baseline.md).

During the first Linux copy attempt the CLI exited 4 with empty captured output. The guest returned `ENOSPC` when the runner tried to write the failure record. The successful retry used the same binary with fresh fixtures after its build cache was cleared. [Blocked copy attempt](../specs/compatibility/evidence/linux-ext4-copy-enospc.json).

Inventory profiles marked `not_executed` describe future paired runs. Version discovery for OpenSSH and ADB records tool identity. It supplies no protocol execution evidence. Restic and Kopia are reference workflows for creating and restoring snapshots. Their on-disk repositories are outside the planned workflow comparison. When a discrepancy occurs, use the applicable protocol specification, an independent oracle and ExaCopy’s safety contracts to decide the expected outcome.

## Reproduce the managed APFS differential

Use Python 3.11+, `cmp`, rsync, the pinned Rust toolchain and a C compiler on macOS. Use a scratch parent satisfying the [managed APFS prerequisites](../../crates/clients/cli/README.md#managed-apfs-comparison-on-macos). `/private/tmp` was used on the test host and should only be used where the required mount, ownership and ancestor conditions hold. The runner creates per-side directories with private modes and explicitly empty ACLs. It opens no pre-existing data fixture. Output paths must be new.

```sh
cargo build --locked --release -p exacopy-cli
mkdir -p target/reference
PYTHONDONTWRITEBYTECODE=1 python3 tools/reference/run.py differential \
  --binary target/release/exacopy --scratch-parent /private/tmp \
  --hardware 'CPU, RAM, local device and filesystem topology' \
  --output target/reference/macos-apfs-differential.json
```

The recorded revision predates the Apache-only history rewrite. To repeat the experiment with the same production code and dependency lock, archive replacement commit `47ccfcf1322af40fa4b2edbf1d578bc412dfbccf` into a fresh directory. Copy the current `tools/reference/common.py`, `tools/reference/run.py` and `fixtures/macos/empty_acl.c` to the same relative paths in the archive. Rebuild there and pass the replacement commit to `--source-revision`.

## Reproduce the Linux ext4 checks

Build the locked release CLI at `7cf7e9d72170db9576160edb57a3ff32c2381b58` on Linux. Use Python 3.11+, GNU `cmp`, rsync and a private scratch parent on native ext4, such as a guest volume on virtio. With an archived source tree, pass the archive commit to `--source-revision` in both invocations. Use fresh output paths.

```sh
cargo build --locked --release -p exacopy-cli
mkdir -p target/reference
PYTHONDONTWRITEBYTECODE=1 python3 tools/reference/run.py differential \
  --binary target/release/exacopy --scratch-parent "$SCRATCH" \
  --hardware 'CPU, RAM, virtualization and filesystem topology' \
  --output target/reference/linux-ext4-differential.json
PYTHONDONTWRITEBYTECODE=1 python3 tools/reference/run.py copy \
  --binary target/release/exacopy --scratch-parent "$SCRATCH" \
  --hardware 'CPU, RAM, virtualization and filesystem topology' \
  --output target/reference/linux-ext4-copy.json --repeats 5
```

## FreeFileSync startup probe

FreeFileSync 14.13 aborted with `SIGABRT` before emitting a comparison result on local journaled APFS. Both the bundle launcher and the bundled main executable aborted with a synthetic equal-pair fixture and an alternate scratch settings path. The command session had no available CoreGraphics display or GUI session. Bundle signature verification independently failed for arm64. The cause of the abort remains unverified. [Probe output and exact batch configuration](../specs/compatibility/evidence/macos-apfs-freefilesync-startup.json).

For a paired run on a functioning macOS desktop, recreate the probe’s isolated fixture and run the reference in its file-content comparison mode. Generate a second fixture by flipping one byte while preserving both length and mtime. Compare the two reference decisions to ExaCopy’s managed-APFS byte comparison and the generated bytes. [FreeFileSync command-line guide](https://freefilesync.org/manual.php?topic=command-line), [comparison settings](https://freefilesync.org/manual.php?topic=comparison-settings).

## Fixture provenance

Fixtures are original synthetic data distributed via their project-licensed generator. Each 1 MiB block uses SHAKE-256 of `exacopy-reference-v1:<case name>:<zero-based block index>`. A changed-byte fixture flips bit zero at its known offset. Sparse fixtures have zero-filled holes plus a single written byte on one side. Regular inputs share the same fixed timestamps and modes. The expected relation and witness come from generation parameters, independently of both applications. The preservation checks compare input names, identity, contents, mode, link count and mtime. Ordinary reads may update atime.
