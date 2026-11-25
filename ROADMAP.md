# Roadmap

Milestones describe dependency order. The [CLI guide](crates/clients/cli/README.md)
and the platform work packages describe current behavior and evidence.

| Order | Milestone | Acceptance dependency |
| --- | --- | --- |
| 1 | Foundation and proof path | Typed preserve-mode decisions and bounded ranges. Keep production-linked checks, independent model and negative controls active. |
| 2 | Recoverable local regular-file copy and exact comparison | Retain Linux implementation and recovery; finish qualifying managed APFS copy and recovery by operation and add a Windows slice. Exercise identity, native publication, journal interruption and actual process-crash boundaries before broadening support. |
| 3 | Broader local endpoint profiles and clients | Qualify metadata, traversal, bounded parallelism and directory-level workflows. Present established engine operations through CLI and GUI with explicit capabilities. |
| 4 | Reliable remote endpoints | Establish SSH/SFTP, explicit credentials, stable endpoint identity and qualified verified resume before delta transfers. Qualify Android adapters and WireGuard route confinement independently before enabling embedded options. |
| 5 | Synchronization and protected operations | Build the classifier, baseline and conflict model before mutation. Require explicit authority and qualified recovery for protected replacement, retirement and reclamation. |
| 6 | Backup and restore | Qualify immutable repository publication, restore and migration before relying on deduplication and reclamation. Run independent reference and native compatibility checks for each advertised profile. |
| 7 | Distribution and performance qualification | Reproduce portable locked builds, signed release and install/update behavior, and complete verified-operation measurements on the declared profiles. Complete release evidence with each advertised capability. |

Engineering, compatibility and verification run with each slice. The
[verification policy](VERIFICATION.md) governs promotion to a supported
profile.
