# Windows publication compiler preparation with owned-job retirement

**Status.** Integrated source with an explicit, default-off `PrepareOwnedCompilerJob` switch. The hosted Windows workflow still selects strict v1. Portable controls and native preparation qualification remain pending; P-078 is registered separately with the formal dispatcher. The strict `windows-hosted-server2025-fixed-ntfs-publication-v1` result remains failed at `cb47f4a`. Its retained publication ZIP records a successful Cargo root and emitted executable, with `vctip.exe` as the sole sampled job member at 479862 ms. The job timed out, drained, and was deleted. No publication case ran.

## Scope and entry point

At `824521c`, all twelve P-078 invocations returned TLC parser exit 150 before
state exploration. SANY rejected the closing record-update bracket at model
line 64. The four analogous closing brackets are now indented inside their
conjunction items. The source correction awaits automatic formal verification;
neither the two healthy cases nor the ten mutants is qualified by the failed
run. [Failed formal job](https://github.com/replicraft/ExaCopy/actions/runs/46002008193/job/140515758293).

A separately named preparation entry point may retire a compiler job to establish that its admitted job members can no longer write its outputs. Only the canonical admitted Windows Server 2025 x64 fixed-NTFS publication harness can construct the preparation request. It supplies the exact source and lockfile revision, a newly acquired empty private target, the reviewed offline feature/package/target graph, and the held compiler toolchain. Plan, source capture, setup tools, ordinary process controls, inventory, and publication tests continue to use the strict existing supervisor. Give any future hosted run that enables the new preparation contract a distinct profile identifier and retain the v1 result.

Proposed narrow API boundaries:

- `PreparePublicationBuild(ApprovedCompilerPreparation)` owns one launch, its private job, both sinks and its build deadline. It returns an `OwnedBuildPreparationReceipt`. The request is constructed by the canonical harness from fixed inputs rather than generic command strings or a caller-controlled switch on `Run`.
- `AdmitPreparedTestImage(OwnedBuildPreparationReceipt, HeldCompilationInputs, HeldBuildDirectory)` returns a held `PreparedTestImage` only after the full admission checks below. The construction is private to the qualification harness. A receipt or path alone supplies no test-launch authority.
- Exact inventory and test invocations consume the live prepared-image authority and invoke the existing strict supervisor. Their outcomes retain the natural completion, timeout, output, and drain requirements of that supervisor.

The native receipt distinguishes `QuiescedAfterRootExit`, `PreparationFailed`, `PreparationTimedOut`, and `PreparationUncertain`. Quiescence records job disposition only. It is independent of whether Cargo's output is valid or contains an acceptable artifact. Image admission and publication case outcomes are later decisions. The existing supervisor's natural completion result is reserved for its existing path. Even an already empty job must acknowledge the preparation mode's explicit retirement call before image admission.

## Held launch authority and pre-retirement proof

1. Acquire the exact unnamed Job object at launch, configure its existing kill-on-close and creation-time association, and check suspended membership before resume. Keep the sole controlling job handle and the exact root process handle. Assign an invocation-local build identifier at creation and bind the job, Cargo input pin, holds, output sinks, and later receipts to it. A random build identifier is correlation evidence. Only the original held Windows Job object provides termination authority.
2. Hold and fingerprint the actual pinned Cargo image used as the root. The simplest composition is the physical `cargo.exe` from the same admitted official toolchain as the held Rust compiler, with a pinned identity/version preflight and the fixed Cargo arguments applied directly. An alternative retaining the rustup proxy needs independent proof of the exact Cargo image and its root-exit semantics before adoption. Keep the already qualified signed MSVC linker, held compiler, and qualified VC/SDK inputs. Recheck exact source, lock, build parameters, and private target identity. The proposal does not authorize new runtime tool discovery or a linker fallback.
3. Obtain a signaled observation and successful exit code zero from that same held root **before issuing retirement**. An unsignaled root, process-query failure, unknown status, or nonzero exit cannot authorize retirement for successful preparation.
4. This is owner cleanup of an admitted compiler job, including if its captured output is malformed. The native layer captures bounded bytes without parsing Cargo JSON or calling an application callback. If an output sink has failed, its extent is uncertain, a cap was exceeded, or supervision has recorded any other failure, process cleanup may still proceed under the existing cleanup rules. Such cleanup cannot produce `QuiescedAfterRootExit`.
5. Bind the held successful root observation to this invocation and require it before the existing build deadline. Check the deadline immediately before requesting retirement. A late root-zero observation cannot clear a timeout.

## Retirement, drain, and image custody

Issue one local `TerminateJobObject` call for planned retirement on the original held job. Record intent first, including invocation identity, exact held-root exit proof and time. Record the call's positive return or its failure as an independent observation. The existing cleanup behavior remains available on failure, but later cleanup, timeout kills, or kill-on-close cannot supply a successful retirement receipt. A lost, uncertain, or failed planned-retirement result can never authorize the artifact. Scope remains the whole owned compile job and its previously admitted exact handle. Process names, IDs, notifications, and snapshots carry diagnostic information only.

After a positive retirement return, independently confirm same held root signaled, authoritative job accounting active count zero, both retained pipes at EOF, confirmed sink extents, and valid output caps. Require those observations by both the existing absolute build deadline and the existing bounded cleanup budget measured from the planned stop. Receipt timeout and first failure are monotone. An observation received after the deadline can support cleanup evidence. It cannot restore readiness.

Only after `QuiescedAfterRootExit` does the owning PowerShell composition read the full immutable raw bytes of both captured sinks through their held identities and verify lengths/digests. Decode stdout with a strict UTF-8 byte decoder that refuses invalid encodings without replacement characters. It parses stdout as strict bounded UTF-8 JSON Lines, with complete newline-terminated records, checked record length/depth, duplicate-key rejection, and a closed Cargo event grammar for the exact graph. Require exactly one fresh selected artifact matching package, manifest, source, feature, target and test profile, followed by exactly one terminal `build-finished` whose `success` is Boolean `true`. Refuse missing, false, duplicate, conflicting, malformed or trailing partial records. Captured stderr stays diagnostic.

Authenticate the exact source, tools and offline build closure independently of stdout before accepting a transcript. Windows pipes do not authenticate each writer. The supported graph must be reviewed and closed over trusted Cargo/compiler/linker behavior, with no arbitrary build script, proc-macro, external wrapper, or other source-controlled executable writer in this admitted lane. Subprocess containment alone does not cover writers such as pre-existing external services, so the admitted graph and environment must exclude reliance on them for private build outputs. Establish and enforce that graph before launch. An archived observation of library artifacts and an ordinary build-finished record does not prove the source graph.

With the private target and ancestry still pinned, independently open the selected path no-follow. Require an ordinary regular file on the same volume, match its name and handle identity, verify AMD64 PE32+ with the executable-image flag set and the DLL flag clear, and hash a bounded complete held-file read-back. Immediately before the first inventory selector, verify the named and held image identity/digest, clean source checkout at the exact revision, unchanged lockfile digest, and invocation provenance again. Keep the file held through the exact existing cases and retain the existing post-case source checks. The hash measures the selected image and keeps it bound across use. It does not prove compiler integrity beyond the trusted tool and source assumptions. A short read, stale/cross-job path, source mismatch, changed tool, reparse point, unknown identity, rebind, or unexpected image role fails image admission with zero cases run.

## Required evidence and trust review

Record the distinct profile, repository/tree and lockfile identities, reviewed target closure and feature selection, tool identities/digests, invocation correlation, job association and held root proof, absolute deadline, stop request timestamp/returned status/native error, post-stop active count and clock, both EOF facts and output caps/extents, full transcript extent/digest and selector outcome, and held image identity/digest. Retain failures and stop/cleanup facts with their own dispositions. No raw Windows handle or unrelated process name is necessary. Evidence export remains governed by the existing custody rules.

| Threat or uncertainty | Required refusal or check |
| --- | --- |
| Old PID reused or unowned process attached by PID | No PID-based authority and no global process search. Root and Job use their original handles, held throughout the build. |
| Stale or crossed transcript, sink, job or build directory | One invocation identity spans the exact held handles and the owned filesystem roots. Refuse stale, duplicate or cross-run evidence. |
| Root exit 0 with missing, false, forged or incomplete build-finished | Owner cleanup may establish quiescence. The transcript and trusted output closure are independently required for image admission. |
| Bytes written by a descendant around the retirement boundary | Both pipes are drained to EOF before reading the immutable full transcript. Missing, partial, conflicting, duplicate or post-terminal bytes fail image admission. |
| Timeout races with root exit, stop acknowledgement or drain | The deadline wins at and after its boundary. Cleanup observations remain visible; no cleared timeout. |
| Successful stop with active jobs, escaped processes or unread streams | Preserve containment and creation-time membership. Require independent active-zero accounting and EOF from both pipes with confirmed sinks. |
| Compiling root/child interrupted before build completion | Retirement is admitted only from a proven successful held root. Full post-EOF Cargo output and post-drain image custody refuse incomplete or otherwise inadmissible outputs. |
| Signed compiler or artifact changes between observation and launch | Hold tools and ancestry, recheck source/provenance, and bind a verified image at launch. Keep image custodial handles through the cases. |
| Future toolchain launches an unfamiliar descendant | No identity-specific allowance. Whole-job stop, accounting, EOF, and image admission govern the decision. |
| Product publication success inferred from compilation | Preparation cannot emit a case result. Only pre-existing strict test invocations can do so after image admission. |

This work package is verification-only. It adds no product publication authority, no remote operation, and no crash/power-loss qualification claim. Its model treats ownership, root observation, transcript parsing, native return truth, and image custody as trusted facts supplied by separately reviewed adapters.

## Adopting the work package

Review the [platform-owned finite model](../../tla/PublicationBuildRetirement.tla) and [hand-derived counterexamples](counterexamples.md) before activating the preparation profile. The existing formal evidence dispatcher can execute the registered platform obligation independently of Windows runtime activation. A later change should verify the closed build graph and ensure identical strict execution behavior for v1 and all unrelated cases. Run source-level negative controls for stale binding, counterfeit/truncated JSONL, missed EOF, output sink failure, timeout, stop uncertainty, and rejected image provenance once execution is authorized. Native positive and failure controls must exercise the new named mode, while strict owner-death, nested drain, output cap, signed-linker custody and exact test selection remain independently qualified.

Primary boundaries: [Win32 whole-job termination](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject) and [Cargo JSON message contract](https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages).
