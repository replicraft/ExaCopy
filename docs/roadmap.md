# Roadmap

The current priorities are SSH/SFTP and WireGuard, recovery, cross-platform
support, protected operations, synchronization, and installation and
uninstallation. Independent work can proceed in parallel where the safety
dependencies allow it. GUI remains last, after these CLI operations.
Backup, repositories, and deduplication are deferred.

The latest inspected native cohort at `c5e0e06` passed 1,437 Linux, 952
macOS, and 814 Windows default tests, all three strict Clippy jobs, and the
declared feature matrices. These results do not qualify public retained-range
reuse, restart recovery, or power-loss durability.
[Exact native cohort](https://github.com/replicraft/ExaCopy/actions/runs/46163107297)

The inspected pre-P-085 cohort at `7e97fd2` passed 64 formal evidence records
and 97 Miri checks. Independent Lean, TLC and Rust obligation checks passed.
P-020 and P-083 Kani composition gates failed: P-020 timed out after
omitted-argument diagnostics, and P-083's guard rejected the same diagnostics.
The first P-085 run at `11427d5` parsed but stopped with TLC exit 75 because
`Crash` left `uncertain` unspecified in one branch. The shared owner check
also failed seven earlier TLC records; no P-085 mutants ran. `e22e647`
groups the intended assignment. Its hosted replay passed: 322 distinct states,
an empty queue, all 23 action checks and all five exact negative controls.
The full corrected formal cohort recorded 65 passes and only the two existing
Kani failures, with 97 Miri checks passing. This is a bounded ordering proof
under the declared issuer and observation assumptions, not native execution.
[Failed model cohort](https://github.com/replicraft/ExaCopy/actions/runs/46155164324)
[Corrected model cohort](https://github.com/replicraft/ExaCopy/actions/runs/46157652331)

Platform coverage at `55932ea` is 8,679/10,051 lines (86.3496%), passing the
unchanged 85% requirement. Every platform per-file denominator is unchanged.
The joined native checkpoint and witness-prepublication components passed
their existing whole-ext4 selector, with verified fixture cleanup. The
earlier `b6f379b` component compilation failure is retained; `27ffc53`
corrected the two positional reads before any native component result.
The default platform inventory does not measure the opt-in managed-sync
profile store; its native fixture results are separate evidence.
[Exact coverage result](https://github.com/replicraft/ExaCopy/actions/runs/46159858369)

Cargo Vet reports 159 unaudited dependency versions after BoringTun's unused
device tables left the selected tunnel-only graph. The full `d286feb` Vet
graph has 278 nodes and contains none of the three removed versions. Surviving
audit gaps and criteria are unchanged, and the mandatory audit remains
failing. The earlier graph-capture command exited 2; the corrected command
and its full graph passed independently of that audit failure.
[Exact dependency evidence](https://github.com/replicraft/ExaCopy/actions/runs/46158938911)

Managed sync now exports a bounded signed create-new proposal with the exact
authenticated predecessor and child Plan. At `64ca8ce`, the real ext4 fixture
passed signed export and missing-seed refusal, independent bundle verification,
and preservation and cleanup controls. The test-only `d42cad5` follow-up adds
an empty-survivor regression. The export grants no execution authority;
parent approval, durable action associations, successor persistence and
baseline activation remain open.
[Signed proposal contract](architecture/signed-sync-recreate-export.md) ·
[Exact managed-sync result](https://github.com/replicraft/ExaCopy/actions/runs/46148802537)

The private managed activation claim now has a fixed 496-byte codec and
independent binding and refusal controls. At `564432e`, all five codec tests
and the contract marker test passed within the 952-test macOS default suite.
Strict Clippy failed because the new integration target lacked crate
documentation; `970e2d3` adds it. The same revision includes `c68da35`, which
binds preview, preparation and signed export history custody to the original
policy record. At `c5e0e06`, the whole-ext4 fixture passed the two-store
regression, and all three default suites and strict Clippy passed. The exact
`564432e` formal cohort also passed P-086's single golden-record Rust check:
66 evidence records passed, with only the two existing Kani failures;
97 Miri checks passed. P-086 establishes this byte specimen, not native spend.
These changes
provide neither a native activation issuer nor managed execution authority.
[Claim contract](architecture/managed-activation-claim.md) ·
[Recorded failure and test results](https://github.com/replicraft/ExaCopy/actions/runs/46161680845) ·
[Record custody fixture](https://github.com/replicraft/ExaCopy/actions/runs/46163107393)

At `3d2c588`, the owned ext4 fixture exercised the complete checked transfer
engine with real native adapters and synthetic component authority. One case
confirmed the returned receipt and kind-18 physical EOF. The second refused
receipt commit after publication and preserved exact receipt and journal
bytes, ending at kind 9. Both ran inside the existing single selector;
fixture cleanup passed. Positive independently enrolled SDK execution,
managed activation and process-crash qualification remain open.
[Checked component result](https://github.com/replicraft/ExaCopy/actions/runs/46164684842)

Local work remains source-only at the maintainer's request. Automatic CI
provides the runtime results above. The sections below retain earlier outcomes
and failures with their original revisions.

| Priority | Current scope and acceptance dependency |
| --- | --- |
| SSH/SFTP and WireGuard | The unsigned Linux x64 [preview.2 archive](releases/v0.1.0-preview.2.md) at `59c26be` passed seven direct OpenSSH cases and seven independent kernel WireGuard cases plus carrier-down with the same held ELF under synthetic fixture authority. The exact hosted Linux lanes at `204bdb0` and `33714f4` each passed 146 selected remote CLI cases and 57 SSH/SFTP package cases, including the three read-health/backoff controls. The later `6be7dc3` password path rechecks route and grant after broker acquisition. Both new regressions passed on Linux, macOS, and Windows in the [exact `6be7dc3` cohort](https://github.com/replicraft/ExaCopy/actions/runs/45979711519). At `5c374b0`, the application-owned SSH refactor passed 154 selected Linux remote CLI cases and 59 Linux, 59 macOS, and 58 Windows in-process SSH package cases. [Exact `5c374b0` native CI](https://github.com/replicraft/ExaCopy/actions/runs/45984371580). Require explicit credentials, verified server identity, and bounded SFTP capabilities. Bind the embedded route and any future private DNS to the approved profile revision and refuse direct fallback. Qualify transport, remote filesystem, and route behavior separately. Production deployment and native same-invocation embedded redial remain open. [Remote readiness](engineering/remote-transfer-readiness.md) |
| Recovery and public execution | Linux preserve-mode local recovery and read-only public-stage inspection are implemented within their declared profiles. Explicit remote resume uses a fresh stage and reads from byte zero while retaining the old attempt. Efficient range reuse remains in private application composition. Bind public Plans to exact approved content and durable authenticated job ownership. Keep the same approved content and policy on resume or retry. Qualify retained-prefix reuse and reconcile uncertain publication before any new effect. At `2f0e809`, five recovered kind-8 journal and coordinator tests passed on Linux, macOS and Windows. All three strict Clippy jobs passed. Linux passed eight exact P-071 cases and replayed all four mandatory remote selectors. The test-gated native SDK at `4bd63d3` adds a fresh OP2 check under live grant and approval guards. At `6af4f31`, its eight authority controls and five platform recovery controls passed on Linux. Its full restart path, process-crash qualification and CLI activation remain open. [Exact `2f0e809` CI](https://github.com/replicraft/ExaCopy/actions/runs/45994838922) · [Linux attendance](https://github.com/replicraft/ExaCopy/actions/runs/45994838922/job/140491545515). [Public-stage inspection](architecture/public-stage-inspection.md) · [Retained suffix](architecture/remote-retained-suffix-appender.md) · [Witnessed publication](engineering/witnessed-publication.md) |
| Cross-platform local operations | The Windows fixed-NTFS fixture passed 17 Read and five Diff cases. Its separate publication lane at `33714f4` ran zero publication cases after the signed Visual Studio locator exited successfully with empty output. At `5261c57`, the signed locator, developer shell and held MSVC linker succeeded and Cargo produced the test executable, but an owned descendant kept the build job active until its deadline. The fixture drained and deleted its private tree without running publication cases. At `cb47f4a`, read-only owned-job observations identified `vctip.exe`, started by `link.exe`, as the sole active descendant at the final sample. The build job timed out again, ran zero publication cases, then drained and verified fixture deletion. A workaround still needs qualification. At `0052c49`, the read-only NTFS reopen probe hit two `E0505` borrow errors, and Windows Clippy reported an unused import. Publication ran zero cases. The source fixes in `3ed9a48` and `6539450` cleared hosted Windows compilation and Clippy at `6af4f31`; private staging also passed its declared profile. Publication still stopped on the retained `vctip.exe` helper before any cases ran. The reopen probe passed its declared cases in the `b116813` v2 matrix; Windows recovery composition remains open. The opt-in owned compiler preparation in `e498592` is integrated as source. The strict v1 workflow is preserved. A separate push-only v2 workflow now selects owned build preparation after the scoped P-078 pass at `90b5d44`. The bundled prebuild controls passed at `8c1a311` and `b50ada3`, and the declared v2 native matrix passed at `b116813`. [Build preparation contract](../crates/platform/exacopy-platform/verification/windows_ntfs_publication/build_retirement/contract.md) · [Exact build-job result](https://github.com/replicraft/ExaCopy/actions/runs/45983834494/job/140454239910) · [Exact `0052c49` publication failure](https://github.com/replicraft/ExaCopy/actions/runs/45996547690/job/140497252556). The APFS `8c13b1d` pin retains the 48 mounted paths and build inputs from the earlier pin. The ordinary-source fixture at `ea2b867` refused a private-stage birth-time adjustment before publication. A separate synthetic timestamp-eligible fixture at `9a3f6b8` passed copy through the complete receipt. Ordinary APFS success, restart, broader Windows CLI composition, metadata and traversal coverage, and power-loss qualification remain open. [NTFS qualification](testing.md#windows-held-directory-ntfs-qualification) · [Publication setup result](https://github.com/replicraft/ExaCopy/actions/runs/45978346346/job/140435679325) · [APFS custody](engineering/apfs-recovery-handoff.md) · [APFS fixture outcomes](engineering/proposed-apfs-metadata-and-birth-handoff.md#hosted-profile-observations-on-2026-11-27) |
| Protected operations | The pure replacement model and held-slot observer have scoped evidence. At `f802e9c`, the transfer layer adds advisory admission under a retained lease. All six advisory controls passed in the `8c1a311` macOS opt-in suite with strict Clippy. The advisory guard exposes no protected effects. Live admission still needs explicit scoped approval, quiescence, exact incumbent custody, durable intent, verified effects, and reconciliation. Source retirement requires qualified durable destination publication and separate quarantine authority. Reclamation needs a distinct approval. [Protected-slot contract](architecture/protected-slot-replacement.md) |
| Synchronization | The managed Linux SDK produces a signed one-subject genesis. The `9a3f6b8` whole-ext4 fixture exercised fresh-facts P-053 admission. The `9957ddb` Linux tmpfs preview ran 27 platform cases, one transfer case, and 12 read-only CLI oracles with exact source fingerprints and verified cleanup. Require a reviewed sync plan and explicit conflict handling before mutation. Preserve both sides when uncertain and bind restart and baseline advancement to verified outcomes. At `8c1a311`, the pure model adds an advisory receipt-backed successor assessment for one approved create-new action. Its ten synthetic tests passed in hosted coverage at that revision. The corrected coverage inventory passed at `b50ada3`. Native successor admission, baseline persistence and current-pointer activation, restart reconciliation, and CLI protected mutation remain open. [Successor assessment](architecture/sync-successor-assessment.md) · [Genesis](engineering/linux-managed-sync-genesis-production.md) · [Managed preview](engineering/linux-managed-sync-production.md) · [Exact preview run](https://github.com/replicraft/ExaCopy/actions/runs/45992398472/job/140483250194) |
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

At `0052c49`, ordinary platform coverage rose to 6,317/8,669 lines
(72.8688%), below the 85% minimum. Model coverage again passed at
941/956 lines and 409/434 branches. Two Linux controls passed for the
read-only kind-42 receipt names and the existing kind-18 refusal order.
[Exact standard coverage job](https://github.com/replicraft/ExaCopy/actions/runs/45996547430/job/140497252203)

The separate `323f15f` advisory witnessed-ext4 run passed all seven
instrumented cases but refused linked-test source mappings. The `6af4f31`
fix passed export and cleanup, reporting 117 mapped source files and 46
excluded tracked test aliases. This inventory differs from the ordinary
gate; its counters are not pooled with that gate. The failed export remains
retained. [Earlier advisory failure](https://github.com/replicraft/ExaCopy/actions/runs/45997490135/job/140500444217)

At `6af4f31`, ordinary platform coverage reached 6,520/8,910 lines
(73.1762%) and still failed the 85% gate. All 377 platform coverage cases
passed, including five new recovery component cases; 23 remained skipped.
Model coverage stayed at 941/956 lines and 409/434 branches. The Linux SDK
also passed its eight authority controls. Its large typed error payload
failed strict Clippy at that revision.

At `824521c`, the exact-source Linux job passed strict workspace Clippy
and all standalone CLI profiles, including the previously failing SSH capture
profile. It passed 1,296 default and 163 remote cases, including all five
platform recovery controls and eight SDK authority controls. The four mandatory
remote selectors and all eight exact P-071 cases also passed. Full native
restart, process-crash and power-loss qualification remain open.
[Exact Linux job](https://github.com/replicraft/ExaCopy/actions/runs/46002008193/job/140515758917)

At `8c1a311`, all 97 model coverage tests passed, including the ten new
sync successor cases. The coverage validator then refused the new module
because its explicit source inventory had not been updated. `4c2272e`
registers that module and updates the inventory control's expected totals;
it preserves the 95% line and 90% branch thresholds. At `b50ada3`, all 97
model tests passed and the corrected inventory admitted 1,006/1,021 lines
(98.5309%) and 441/466 branches (94.6352%). The ordinary platform result remained
6,520/8,910 lines with 377 passed and 23 skipped cases.
[Exact coverage run](https://github.com/replicraft/ExaCopy/actions/runs/46003782747) · [Verified correction](https://github.com/replicraft/ExaCopy/actions/runs/46004576304)

The stronger protected admission model in `ce1b039` adds an explicit
authorization step before intent and five negative controls. At `b50ada3`,
SANY rejected its initial record's closing-bracket indentation before state
exploration. At `74dd691`, the corrected healthy search exhausted 262 states
and the controller reported all 14 expected negative outcomes. The early
snapshot contains the registered prior-history raw trace and summaries for
the other 13 controls; final Rust and Miri evidence remains separate.
The Windows short-write regressions in `576e1b0` passed both exact native
selectors at `b50ada3`, with verified fixture cleanup. At `824521c`,
P-078 failed before state exploration:
all twelve TLC invocations returned parser exit 150 for the model's record-update
closing indentation. The correction indents all four affected closing brackets;
the corrected P-078 model passed at `90b5d44`: 333 preparation and 21 strict states, empty queues, first-selector reachability and all ten expected counterexamples. Windows preparation v2 is enabled for automatic qualification; native results remain pending.
[Exact failed formal job](https://github.com/replicraft/ExaCopy/actions/runs/46002008193/job/140515758293)

At `49b5633`, all six ordinary LLVM input-capture controls passed. Two identical
pre-execution receipts recorded the exact 31-object export order, filter,
pinned LLVM tool and indexed profile. The platform result remained
6,520/8,910 lines. These receipts do not merge witnessed profiles or authorize
an executable. [Collector contract](engineering/ordinary-coverage-inputs.md) ·
[Exact coverage run](https://github.com/replicraft/ExaCopy/actions/runs/46006579812)

The `49b5633` Linux default suite passed the inherited-stage ACL regression
within 1,313 tests, with strict Clippy and standalone profiles clean. The
case verifies refusal after read-back, retained stage ACL and bytes, source
and incumbent preservation, and absence of the requested destination.
[Exact native CI](https://github.com/replicraft/ExaCopy/actions/runs/46006579648)

The separate [Windows v2 qualification workflow](../.github/workflows/windows-ntfs-publication-preparation.yml)
retains its own fixture, profile and artifact. Activation uses the passing
P-078 model inputs and previously passed prebuild controls. Its native
compiler preparation, image admission and five publication cases still
require a verified hosted result. The v1 workflow and manifest are unchanged.

The first v2 run at `9101b9f` refused duplicate target declarations in Cargo
metadata before compiler preparation, ran zero publication cases and deleted
its fixture. The target-aware correction requires the exact known declaration
tuples while retaining the eight-package Windows closure. Its native result
is pending. [First v2 attempt](https://github.com/replicraft/ExaCopy/actions/runs/46009182684)

At `0f6051e`, compiler preparation, quiescence, transcript verification and held
image admission succeeded. Two ABI/status controls and two native refusal cases
passed; the three positive publication cases returned Win32 error 87 before
observation. Cleanup remained unconfirmed after an unexpected entry. The native
rename-call candidate preserves held roots and no-replace semantics and awaits
hosted execution. [Second v2 attempt](https://github.com/replicraft/ExaCopy/actions/runs/46010876078)

The full `74dd691` formal artifact subsequently passed all 57 declared records,
Miri and final EVS validation. The earlier snapshot's model log and trace hashes
match the final artifact. [Full hosted CI](https://github.com/replicraft/ExaCopy/actions/runs/46007719725)

At `b116813`, Windows v2 passed both ABI/status controls and all five native
publication cases. Independent review verified the eight-package build graph,
compiler preparation and held-image binding, exact case outputs, process
drainage and fixture deletion. This qualifies the declared hosted NTFS component
matrix; Windows CLI composition, restart and power-loss evidence remain open.
The three earlier code-87 failures and unconfirmed cleanup remain retained.
[Passing native v2 run](https://github.com/replicraft/ExaCopy/actions/runs/46013234916)

The same revision passed the new ordinary Linux publication-observation
regression in standard coverage. Platform coverage reached 6,521/8,910 lines
(73.1874%), still below 85%; the measured cohort passed 380 cases with 23
skipped. Endpoint coverage remained 580/663 lines and model coverage remained
above both gates.

Workspace Clippy failed on Linux, macOS, and Windows at `aea84c9`.
The protected-model type-alias follow-up passed Windows and macOS Clippy
at `04da507`; Linux still failed at that revision. The native metadata-table
alias in `41470a7` passed strict Clippy on all three operating systems.
[Exact integrated CI](https://github.com/replicraft/ExaCopy/actions/runs/45992934541).
Cargo Vet still reported 166 unvetted
dependency versions, with 165 `safe-to-deploy` and one `safe-to-run`.
[Exact `aea84c9` CI](https://github.com/replicraft/ExaCopy/actions/runs/45990399107) · [Supply-chain evidence](supply-chain/README.md)

The remaining cross-platform, Windows composition, and BoringTun
modernization candidates still need integrated compilation and affected
qualification. The early cross-platform candidate has scoped host formatting,
endpoint Clippy and doctest evidence. An earlier private protocol build was
blocked by storage. Preserve earlier failed and blocked results and distinguish
fixture execution, process-crash qualification, and power-loss qualification.
The foundation invariants and architecture pack govern each new effect.
