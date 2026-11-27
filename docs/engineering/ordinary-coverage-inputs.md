# Ordinary LLVM export input capture

The endpoint coverage workflow can retain advisory pre-execution receipts for
the ordinary LLVM export. Its six Python controls run first. Failed controls
disable capture and fail the job, while the existing ordinary coverage command
still runs. The original test selection, source inventory, LLVM argument order
and per-crate 85% line minimum are unchanged. Hosted validation of this new
capture path is pending.

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
Separate witnessed coverage summaries remain separate. A future combined
campaign must use the same objects, source inventory and line denominators
and retain exact case attendance and cleanup evidence before admitting raw
profiles. No such combined campaign is activated here.
