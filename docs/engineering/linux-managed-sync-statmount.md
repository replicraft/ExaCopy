# Bounded Linux mount attributes for managed synchronization

**Status** Accepted; implementation is experimental. Native evidence is scoped below.

**Source basis** ExaCopy `802247da38aa59d4a5f24b64e5e2d1972e0c3fe2`

**Owner** `exacopy-platform` Linux sync-preview adapter

This adapter contributes to R-269–272 and R-276–277 under INV-013, INV-016,
INV-019, INV-025 and INV-026. It establishes a mount observation, without
granting synchronization or publication authority.

## Context

The experimental managed one-subject sync preview needs positive evidence that the exact selected whole ext4 mount does not apply an ID map. The current held-root and history-location checks identify the parent, ordered roots and mounts. They cannot establish this attribute from projected file ownership, process identity, filesystem type, or a missing mountinfo annotation. The thread's user and group maps remain separate inputs. The check supplies one native fact to later independent owner, cooperation and history admission. [Current sync root contract](../architecture/sync-baseline-root-contract.md)

## Decision

Place one bounded `repr(C)` syscall module at the private platform crate root, `src/managed_sync_statmount.rs`, behind default-off `experimental-linux-managed-sync`. The safe `linux/sync_preview/managed_mount.rs` adapter exposes the information-only `SyncPreviewRoots::require_unmapped_history_mount` method on the existing held sync roots. The Linux namespace retains `forbid(unsafe_code)`. Use the version-zero 24-byte `mnt_id_req` with zero spare, the already observed nonzero unique mount ID, request `STATMOUNT_MNT_BASIC`, and syscall flags zero. This selects the calling thread's current mount namespace. Compare that held namespace and both ordinary and unique mount IDs before and after the query. Linux v6.8 already exposes both IDs and the IDMAP attribute in the BASIC result. Linux v7.0 retains the ID-based query and adds a separate by-FD option, which this ABI does not need. [Linux v6.8 BASIC and IDMAP implementation](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c#L4466-L4532) · [Linux v6.8 request processing](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c#L4703-L4725) · [Linux v7.0 implementation](https://github.com/torvalds/linux/blob/v7.0/fs/namespace.c#L4977) · [Linux v7.0 UAPI](https://github.com/torvalds/linux/blob/v7.0/include/uapi/linux/mount.h#L179)

The syscall receives an initialized fixed-width C-layout request and a bounded initialized, suitably aligned output allocation. Check compile-time request size, alignment and the field offsets of the output prefix consumed by Rust against the reviewed UAPI. The one synchronous unsafe call must state pointer validity, allocation extent, initialization, native argument widths and the output validity preconditions. Inspect only the proven initialized prefix within the returned size and allocated extent. Require success, BASIC in the returned mask, both exact IDs, and clear `MOUNT_ATTR_IDMAP` in the returned attributes. The fixed query neither requests nor parses variable-length strings. Other Linux builds preserve the existing unsafe prohibition where possible. On the specific feature-and-target combination where the adapter is built, use crate-wide `deny(unsafe_code)` with a reasoned exception only on the private syscall function in that module. Keep `unsafe_op_in_unsafe_fn` denied. Existing platform-specific exceptions retain their own scope. [Current platform lint placement](../../crates/platform/exacopy-platform/src/lib.rs) · [Engineering standards](standards.md)

## Dependency and compatibility

Use the already pinned workspace `libc = 0.2.191` for `libc::syscall`, through an optional target-specific direct dependency on native Linux x86-64 or AArch64 with 64-bit pointers. The existing macOS platform edge already places the exact package in the workspace lock. The Linux edge changes resolved dependency selection under the feature, and the feature inventory and target graph record that exact edge. The architecture policy already lists `libc` as a platform external and an engine-closure boundary. Check whether its validator requires a separate optional allowance for this explicit edge. Preserve the pin and verify the lockfile instead of assuming its serialized entries will change. The pinned libc sources do not define the syscall symbol for these two targets. Use a reviewed local UAPI number, 457 on both selected ABIs, under the same exact target gate and corroborated by the pinned `linux-raw-sys 0.12.1` output. This decision adds no separate direct dependency for that constant. Reassess if a qualified safe wrapper later supplies the exact capability. [Workspace pin](../../Cargo.toml) · [Existing platform edge](../../crates/platform/exacopy-platform/Cargo.toml) · [Architecture policy](../../specs/architecture/dependencies.toml) · [Generated dependency inventory](../../specs/dependencies/README.md) · [Linux x86-64 syscall table](https://github.com/torvalds/linux/blob/v7.0/arch/x86/entry/syscalls/syscall_64.tbl) · [Linux generic syscall table](https://github.com/torvalds/linux/blob/v7.0/scripts/syscall.tbl)

Linux 6.8 is the upstream minimum for the selected positive ID-based ABI. A release string, backport assumption, architecture match or successful unrelated syscall gives no admission. The query itself and the selected kernel profile must furnish the checked result. Upstream checks current-root reachability and the filesystem security hook. Run as the already admitted ordinary actor, without acquiring capabilities, elevation, namespace changes or a privileged fallback. Refuse absent ABI support, missing BASIC, truncated or malformed results, zero or mismatched IDs, an ID-mapped mount, denied access, or any held substrate or namespace mismatch. Preserve the original failure class and avoid projecting failure as absence. Explicitly require existing whole ext4 and held identity checks on both roots. [Linux v6.8 scope and security checks](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c#L4636-L4656) · [Linux v6.8 result-size handling](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c#L4619)

## Evidence before activation

The implementation lane owns ABI layout and typed refusal controls, including absent returned mask, short extent, wrong IDs, IDMAP present, unsupported syscall or architecture, permission error and a changed held namespace. The crate-owned native fixture must independently select real whole ext4 and capture source, kernel, architecture, boot, mount and namespace identities for an exact unprivileged run with no live capabilities. It must observe a valid positive BASIC and clear IDMAP result on that actual held mount. Any separate ID-mapped negative that needs setup privilege requires its own authorized fixture and cannot supply the ordinary observer's positive qualification. The prior whole-ext4 location/member run remains historical. The FFI uses no public CLI path or phase-one application policy wiring. Independent owner selection, cooperative lease, authentication and classification require their own integration evidence before any managed command is enabled. No mutation, recovery or durability guarantee follows from this check.

ABI, refusal and ownership checks accompany the implementation. Cross-compilation and portable controls do not qualify a native mount. The separate unprivileged hosted fixture must pass before its observations can support managed admission. Owner selection and the cooperative lease remain separate requirements.

## Native observation

At `f12908a`, the exact feature-bound integration case passed on Linux x64,
kernel `7.0.0-1020-azure`, whole ext4, as UID 1001. It observed clear ID mapping
and matched the held ordinary and unique mount IDs, boot and namespaces before
and after the query. The runner checked the selected Cargo target, singleton
feature, manifest and held executable digest. One case executed, none were
ignored, and the fixture and private build cleanup were confirmed.
[Native run](https://github.com/replicraft/ExaCopy/actions/runs/45910373914)

This is a positive read-only mount observation. A real ID-mapped negative,
other kernel profiles, cooperative writer admission and authenticated live
preview remain separate gates. The observed mount used `nobarrier` and
`data=writeback`; this result establishes no publication or durability claim.
