# Roadmap

Current priorities, set on 2026-11-25: SSH/SFTP and WireGuard, recovery,
cross-platform support, protected operations, synchronization, and installation
and uninstallation. GUI work is last. Backup/repository and deduplication work
are deferred beyond this scope.

The order below expresses safety dependencies, not a requirement to finish
all platforms before starting remote or synchronization work. Independent
slices can proceed together. The [CLI guide](../apps/exacopy-cli/README.md)
and platform work packages describe implemented behavior and evidence.

| Order | Milestone | Acceptance dependency |
| --- | --- | --- |
| 1 | Recovery and public execution boundary | Connect canonical public Plans to exact approved content, durable authenticated job ownership and reconciliation. Preserve the existing Linux recovery behavior; bind resume/retry to the same approved data and policy. Qualify actual process-crash boundaries separately from model checks and power-loss claims. |
| 2 | Cross-platform local operations | Finish managed APFS copy and recovery through the local Pomologie mounted API; qualify the Windows NTFS slice. Extend required metadata, traversal and directory workflows with explicit operation capabilities. Native execution remains necessary before advertising a supported profile. |
| 3 | SSH/SFTP and WireGuard | Establish explicit credentials, verified server identity, bounded SFTP capabilities and reconnect/resume. Bind embedded WireGuard connections and DNS to an approved route/profile revision; refuse route fallback. Qualify transport, remote filesystem and route behavior independently. |
| 4 | Protected operations | Require explicit scoped approval, quiescence, retained incumbent content, durable publication intent, verified replacement and uncertain-outcome reconciliation before replacement or retirement. Reclamation remains a separately authorized action. |
| 5 | Synchronization | Implement the baseline and change classifier, explicit conflict handling and reviewed plans before mutation. Preserve both sides on uncertainty; bind restart and baseline updates to verified outcomes. |
| 6 | Install, update and uninstall | Deliver root POSIX and PowerShell entrypoints, starting with verified offline CLI artifacts. Require signed release metadata, independently trusted publisher identity, owned transactional version switching and safe rollback. Preserve profiles, credentials, journals, recovery material and user data by default. Online channels, system scope and platform packages need their own qualification. |
| Later | GUI | Present established engine operations after the current CLI, recovery, remote and synchronization scope. |
| Deferred | Backup, repositories and deduplication | Revisit immutable repository publication, restore, migration, retention and reachability-safe reclamation after the current scope. |

Engineering, compatibility and verification run with each slice. Distribution
work proceeds alongside the engine; it does not wait for the GUI. The
[verification policy](verification.md) governs promotion to a supported
profile. Foundation invariants and the architecture pack remain acceptance
requirements; this priority change does not confer new mutation authority.
