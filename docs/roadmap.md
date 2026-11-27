# Roadmap

The current priorities are SSH/SFTP and WireGuard, recovery, cross-platform
support, protected operations, synchronization, and installation and
uninstallation. Independent work can proceed in parallel where the safety
dependencies allow it. GUI remains last, after these CLI operations.
Backup, repositories, and deduplication are deferred.

| Priority | Current scope and acceptance dependency |
| --- | --- |
| SSH/SFTP and WireGuard | The unsigned Linux x64 [preview.2 archive](releases/v0.1.0-preview.2.md) at `59c26be` passed seven direct OpenSSH cases and seven independent kernel WireGuard cases plus carrier-down with the same held ELF under synthetic fixture authority. The exact hosted Linux lanes at `204bdb0` and `33714f4` each passed 146 selected remote CLI cases and 57 SSH/SFTP package cases, including the three read-health/backoff controls. The later `6be7dc3` password path rechecks route and grant after broker acquisition. Both new regressions passed on Linux, macOS, and Windows in the [exact `6be7dc3` cohort](https://github.com/replicraft/ExaCopy/actions/runs/45979711519). At `5c374b0`, the application-owned SSH refactor passed 154 selected Linux remote CLI cases and 59 Linux, 59 macOS, and 58 Windows in-process SSH package cases. [Exact `5c374b0` native CI](https://github.com/replicraft/ExaCopy/actions/runs/45984371580). Require explicit credentials, verified server identity, and bounded SFTP capabilities. Bind the embedded route and any future private DNS to the approved profile revision and refuse direct fallback. Qualify transport, remote filesystem, and route behavior separately. Production deployment and native same-invocation embedded redial remain open. [Remote readiness](engineering/remote-transfer-readiness.md) |
| Recovery and public execution | Linux preserve-mode local recovery and read-only public-stage inspection are implemented within their declared profiles. Explicit remote resume uses a fresh stage and reads from byte zero while retaining the old attempt. Efficient range reuse remains in private application composition. Bind public Plans to exact approved content and durable authenticated job ownership. Keep the same approved content and policy on resume or retry. Qualify retained-prefix reuse and reconcile uncertain publication before any new effect. The witnessed kind-8 restart candidate still needs native and process-crash qualification. [Public-stage inspection](architecture/public-stage-inspection.md) · [Retained suffix](architecture/remote-retained-suffix-appender.md) · [Witnessed publication](engineering/witnessed-publication.md) |
| Cross-platform local operations | The Windows fixed-NTFS fixture passed 17 Read and five Diff cases. Its separate publication lane at `33714f4` ran zero publication cases after the signed Visual Studio locator exited successfully with empty output. At `5261c57`, the signed locator, developer shell and held MSVC linker succeeded and Cargo produced the test executable, but an owned descendant kept the build job active until its deadline. The fixture drained and deleted its private tree without running publication cases. At `cb47f4a`, read-only owned-job observations identified `vctip.exe`, started by `link.exe`, as the sole active descendant at the final sample. The build job timed out again, ran zero publication cases, then drained and verified fixture deletion. A workaround still needs qualification. [Exact build-job result](https://github.com/replicraft/ExaCopy/actions/runs/45983834494/job/140454239910). The APFS `8c13b1d` pin retains the 48 mounted paths and build inputs from the earlier pin. The ordinary-source fixture at `ea2b867` refused a private-stage birth-time adjustment before publication. A separate synthetic timestamp-eligible fixture at `9a3f6b8` passed copy through the complete receipt. Ordinary APFS success, restart, broader Windows CLI composition, metadata and traversal coverage, and power-loss qualification remain open. [NTFS qualification](testing.md#windows-held-directory-ntfs-qualification) · [Publication setup result](https://github.com/replicraft/ExaCopy/actions/runs/45978346346/job/140435679325) · [APFS custody](engineering/apfs-recovery-handoff.md) · [APFS fixture outcomes](engineering/proposed-apfs-metadata-and-birth-handoff.md#hosted-profile-observations-on-2026-11-27) |
| Protected operations | The pure replacement model and held-slot observer have scoped evidence. Live admission still needs explicit scoped approval, quiescence, exact incumbent custody, durable intent, verified effects, and reconciliation. Source retirement requires qualified durable destination publication and separate quarantine authority. Reclamation needs a distinct approval. [Protected-slot contract](architecture/protected-slot-replacement.md) |
| Synchronization | The managed Linux SDK produces a signed one-subject genesis. The `9a3f6b8` whole-ext4 fixture exercised fresh-facts P-053 admission. The `9957ddb` Linux tmpfs preview ran 27 platform cases, one transfer case, and 12 read-only CLI oracles with exact source fingerprints and verified cleanup. Require a reviewed sync plan and explicit conflict handling before mutation. Preserve both sides when uncertain and bind restart and baseline advancement to verified outcomes. Receipt-backed successor admission, a current baseline pointer, and CLI protected mutation remain open. [Genesis](engineering/linux-managed-sync-genesis-production.md) · [Managed preview](engineering/linux-managed-sync-production.md) · [Exact preview run](https://github.com/replicraft/ExaCopy/actions/runs/45992398472/job/140483250194) |
| Install, update and uninstall | The unsigned preview uses manual extraction. The [source install](../README.md#installation) is available from a selected checkout. Once the verified CLI package and its dependency closure are published, `cargo install --locked exacopy` is the primary registry path. POSIX and PowerShell installers are the alternative for signed prebuilt artifacts. Require independently trusted publisher identity and signed release metadata. Keep native lifecycle evidence, owned transactional version switching and rollback as separate gates. Windows accepts one exact release per root and reports acknowledged publication independently of launcher or later validation failures. Default removal preserves profiles, credentials, journals, recovery material, and user files. Online channels, system scope, and native packages have separate gates. [POSIX installer](architecture/posix-offline-install.md) · [Windows installer](installation/windows.md) · [Release workflow](engineering/release-ci.md) |

At `204bdb0`, hosted default suites passed 1,105 Linux, 840 macOS, and
707 Windows tests. All 56 declared formal evidence records passed, along
with Miri. The earlier local macOS workspace run at `ca635e9` passed
1,075 tests, with 32 skipped. These results apply to their recorded
revisions and profiles. [`204bdb0` hosted CI](https://github.com/replicraft/ExaCopy/actions/runs/45976299011) · [Verification policy](verification.md)

At `aea84c9`, model coverage passed with 941/956 lines and 409/434
branches against the existing 95% line and 90% branch minimums. Platform
line coverage failed with 4,937/8,590 against the existing 85% minimum.
[Exact coverage job](https://github.com/replicraft/ExaCopy/actions/runs/45990398793/job/140476447859)

At `9957ddb`, all 172 added regressions passed in hosted coverage. Model
coverage passed again with 941/956 lines and 409/434 branches. Platform
line coverage rose to 6,281/8,633 (72.7557%), with 1,344 more covered lines
and 43 more measured lines than the earlier failed record. It remains
below the unchanged 85% minimum. [Exact coverage run](https://github.com/replicraft/ExaCopy/actions/runs/45992398772)

Workspace Clippy failed on Linux, macOS, and Windows at `aea84c9`.
The protected-model type-alias follow-up passed Windows and macOS Clippy
at `04da507`; Linux still failed at that revision. The native metadata-table
alias in `41470a7` passed strict Clippy on all three operating systems.
[Exact integrated CI](https://github.com/replicraft/ExaCopy/actions/runs/45992934541).
Cargo Vet still reported 166 unvetted
dependency versions, with 165 `safe-to-deploy` and one `safe-to-run`.
[Exact `aea84c9` CI](https://github.com/replicraft/ExaCopy/actions/runs/45990399107) · [Supply-chain evidence](supply-chain/README.md)

The private cross-platform, protocol and recovery, native kind-8, Windows
composition, and BoringTun modernization candidates still require integrated
compilation and affected qualification. The cross-platform candidate has
scoped host formatting, endpoint Clippy and doctest evidence. The private
protocol and recovery candidate passed formatting before its compile attempt
was blocked by storage. Preserve earlier failed and blocked results and distinguish
fixture execution, process-crash qualification, and power-loss qualification.
The foundation invariants and architecture pack govern each new effect.
