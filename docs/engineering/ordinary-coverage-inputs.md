# Ordinary LLVM export input capture

The endpoint coverage workflow can retain advisory pre-execution receipts for
the ordinary LLVM export. Its six Python controls run first. Failed controls
disable capture and fail the job, while the existing ordinary coverage command
still runs. The original test selection, source inventory, LLVM argument order
and per-crate 85% line minimum are unchanged. At `49b5633`, all six hosted
controls passed. The two pre-execution receipts were byte-identical and
recorded 31 distinct ordered objects, the pinned tool and indexed profile.
They survived the unchanged platform threshold failure at 6,520/8,910 lines.
[Exact hosted coverage](https://github.com/replicraft/ExaCopy/actions/runs/46006579812).

The delegate records the canonical campaign directory, exact export arguments
and filename filter, and bounded SHA-256 receipts for the pinned LLVM tool,
indexed profile and every explicit object, in original order. It accepts only
the observed pinned export grammar. An unsupported argument shape or expected
capture error produces no successful receipt and still forwards the original
LLVM invocation. Existing LLVM tool overrides or warning-denial settings,
including empty values, bypass the optional delegate.

Receipts use a held, no-follow, owner-private directory and exclusive relative
writes. Capture permits at most 128 objects, 512 arguments totaling 64 KiB,
256 MiB per input and 1 GiB across inputs. Four numbered success receipts and
four failure receipts bound output multiplicity. Unavailable custody or full
slots can prevent an additional receipt without suppressing LLVM.

These are observations before LLVM executes. They do not establish export
success, select or authorize a test executable, or admit additional profiles.
Correlate them with the ordinary command's retained exit status and report.
Separate witnessed coverage summaries remain separate.

Canonical main pushes from the Coverage workflow request three separately
admitted foreground groups in the same ordinary campaign: seven witnessed
recovery components, six selected-stream publication cases, and four protected
snapshot cases. Source, workflow, job and run identity are checked before the
ordinary build. The ordinary command must finish successfully before the native
contribution can proceed. The runner holds the original indexed profile, LLVM
tools, ordered objects and selected test executable, and retains the ordinary
report independently.

Only the 17 measured run profiles join the original index, after exact
attendance and verified cleanup of each group's private fixture. All 34 listing
profiles are discarded. The protected snapshot group additionally checks the
current ext4 root mount, protected ancestry and working POSIX access ACLs. The
held executable must have no file capabilities. The combined export preserves
the ordinary filename filter,
file inventory and every file's line denominator, with no decrease in covered
lines. The existing per-crate 85% gate then evaluates the combined report.

If native admission or measurement fails, the gate evaluates the ordinary
report and the requested witness lane still fails. Failed capture or witness
controls preserve the ordinary run and fail their own CI steps.

At `e95398a`, all four image controls, three campaign controls and seven
native cases passed. Fixture cleanup was verified. The merge used exactly
31 original objects and seven measured profiles, excluding all 14 listing
profiles. All 90 reported files retained their ordinary line denominators.
Platform coverage rose by 355 lines to 6,876/8,910 (77.1717%); the 85% gate
still failed. Endpoint coverage remained 580/663 and core remained 34/34.
[Exact coverage run](https://github.com/replicraft/ExaCopy/actions/runs/46029308664).
These component measurements supply no restart or power-loss qualification.
The expanded 17-case collection is source-reviewed; its first hosted result
remains pending. The original seven-case qualification is unchanged.
