# Independent compatibility checks

The [compatibility inventory](../specs/compatibility/inventory.v1.json) defines each reference profile, its acceptance cases, and its evidence status. An executed profile applies to the exact versions, platform, fixture and operation in its evidence. Acceptance IDs carry the architecture pack’s meanings. The local experiments exercise portions of A-008, A-009, A-093, A-100, A-185 and A-194. The incumbent experiment is a pre-existing-name case. The [native adapter tests](../local-adapter.md) cover concurrent incumbent creation and other platform behaviors.

ExaCopy 0.1.0 at `d82ce08b78f770e500de9b2c7965f24d625b757a` matched Apple `cmp` (`patch_cmds-61`) and rsync 3.5.2 checksum dry runs for seven regular-file pairs on managed APFS. One, four and sixteen worker ceilings all returned the expected byte or length witness. `cmp` followed a final symlink and reported equality. ExaCopy returned `E_OPEN_INPUT` without establishing a relation, as required by its capability-scoped path admission. `cmp` and the generated witness supply the exact oracle. Rsync supplies an independent content-update decision which uses a checksum shortlist. [Managed APFS differential evidence](../specs/compatibility/evidence/macos-apfs-differential.json).

On the Ubuntu ext4 guest, rsync 3.2.7 copied a 4 KiB test file to a new name with `--ignore-existing`. `cmp` confirmed the result byte for byte. The tools preserved a different incumbent’s identity and bytes. Rsync signalled a successful skip, while ExaCopy reported `E_CONFLICT` and no publication. ExaCopy’s complete-copy benchmark independently checked published bytes and committed state before a trial could count. [Linux ext4 copy evidence](../specs/performance/evidence/linux-ext4-copy.json).

The other inventory profiles document future reference runs. Version discovery for OpenSSH and ADB records tool identity. It supplies no protocol execution evidence. Restic and Kopia are reference workflows for creating and restoring snapshots. Their on-disk repositories are outside the planned workflow comparison. When a discrepancy occurs, use the applicable protocol specification, an independent oracle and ExaCopy’s safety contracts to decide the expected outcome.

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

The recorded revision predates the Apache-only history rewrite. To repeat the experiment with the same production code and dependency lock, archive replacement commit `47ccfcf1322af40fa4b2edbf1d578bc412dfbccf` into a fresh directory. Copy the current `tools/reference/common.py`, `tools/reference/run.py` and `fixtures/macos/empty_acl.c` to the same relative paths in the archive. Rebuild there and pass the replacement commit to `--source-revision`. On Linux, run the [copy lane](../performance/baseline.md#reproduce) for the rsync copy and incumbent controls.

Fixtures are original synthetic data distributed via their project-licensed generator. Each 1 MiB block uses SHAKE-256 of `exacopy-reference-v1:<case name>:<zero-based block index>`. A changed-byte fixture flips bit zero at its known offset. Sparse fixtures have zero-filled holes plus a single written byte on one side. Regular inputs share the same fixed timestamps and modes. The expected relation and witness come from generation parameters, independently of both applications. The preservation checks compare input names, identity, contents, mode, link count and mtime. Ordinary reads may update atime.
