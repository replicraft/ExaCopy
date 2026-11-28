# Grant clock evidence

P-083 covers one decision of the actual `check_grant_time` function on normalized
UTC timestamps. Seconds retain the full signed `i64` domain; nanoseconds are
below one billion. The Rust oracle uses signed wide nanosecond arithmetic.
Its representative cases and the three Linux clock-adapter controls passed
at `8404b71`. They do not establish every possible input or native clock behavior.

The first Kani encoding at that revision timed out with exit 124 under the
900-second recorder limit. The shared dispatcher started the clock harness
but completed no assertion or cover report before timeout. The range harness
did not start, so the separate P-004 record also failed through this coupling.
[Exact formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46122888565/artifacts/15257080510)
has SHA-256 `4aec02ae18ef334b0b3154da356d3976a48330e5125cd74e8778f6412b558da9`.
The P-083 raw member is `exacopy-evs/9dd02531-2be4-4084-8497-0d16eb9be198.log`,
with SHA-256 `1115ada46979405d891d9d06adc764231340d789b198341f1ab1438cfeb089e3`.
No assertion counterexample was observed; the timeout provides no passing proof.

The revised P-083 runner is `verification/kani/check-grant-time.sh kani`.
It requires the real `before` comparator contract and four covers, then the
actual decision with only that comparator verified-stubbed, both decision
assertions and all twelve original covers. The comparator's independent wide
delta oracle clamps a nonzero seconds difference to one second of the same
sign. A normalized subsecond difference has magnitude below one second, so
this preserves the exact order of the original wide nanosecond difference,
including signed extremes and rollover. The decision uses the intersection
of both half-open intervals and retains regression-before-expiry precedence.
Qualification must never widen acceptance.

The P-004 default runner separately selects the unchanged range harness and
six covers, refusing any stub. P-083 still requires its own passing record.
Both invocations preserve the pinned tools, enabled unwind checks and the
900-second per-record deadline. The redesigned proof remains unverified.

Clock sampling and monotonic classification, paired high-water updates,
retirement, mutex serialization, effects and native qualification remain
separate. Lean registration requires actual generated source and a theorem
that invokes that extracted function; candidate generation earns no proof credit.
