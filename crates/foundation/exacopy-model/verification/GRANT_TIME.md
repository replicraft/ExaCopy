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

At `fdf4ae1b09f545a9277e55ec36eae4f4bc4d81da`, both isolated Kani records
passed on `x86_64-unknown-linux-gnu`. The logs report Kani `0.68.0`, CBMC
`6.11.0` and Rust `1.100.0-nightly` at `8925ea358`. Both runners retain
unwind checks and the 900-second per-record deadline.

P-083 verified both harnesses in 6.429 seconds. The decision passed both
assertions and 12 of 12 covers with `exacopy_model::grant_time::before` as
its sole verified stub. The real comparator passed its assertion and 4 of 4
covers without a stub. The record binds `src/grant_time.rs` at SHA-256
`16105dbadd18ba2ebb3c6dc09ee597ed026ce444aa8f1aed1ad424e4a0ba4f2d`.
Its raw member is `exacopy-evs/7f2daaa9-7457-4c15-ba89-ac74a45a7bd3.log`,
with SHA-256 `8161378a43290fbfa2048dfbddfd48e4dd5e6eafc8594b2634870056e0ff089b`.

P-004's default `verification/check.sh kani` runner again verified the
unchanged range harness, with 6 of 6 covers and no stub, in 1.317 seconds.
Its source is `src/range.rs` at SHA-256
`6b80bd5a2126bb9b1cbb0456b9903c5bfd6b3bc6b6b525f878cdff8517fee7f6`.
Its raw member is `exacopy-evs/a745f201-212a-48af-a7ce-4ee913577dd4.log`,
with SHA-256 `44054c2d509621777e38a6933ca38fbabd62e4ed55f6e02a1fe93edba98cd996`.

Both records bind `Cargo.lock` at SHA-256
`02f508558e1b473658917de6362b914e4d74141c0af38b8d5f05b7973db6cfbe`.
[Exact hosted snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46130028396/artifacts/15258028844)
contains both logs and their same-named JSON records and has SHA-256
`960280c184dd1f046d3c1c41191b5a326f8934bc20898125255addbacf5e07c5`.

The same revision's advisory extraction completed with exit zero. Its
[generated-source artifact](https://github.com/replicraft/ExaCopy/actions/runs/46130028396/artifacts/15258920042)
has SHA-256 `6d59cadd778aa53c3940427c6682331091ad44cbfcaa1af29bca346fdda4816f`.
The receipt binds the actual Rust source, app caller, lockfile and pinned
extraction inputs. The three reviewed module payloads are retained verbatim
under `Generated/GrantTime`, with only the external template's filename changed.
That template contains no external declarations.

The P-083 Lean gate now freshly extracts those exact modules and checks
`ExaCopy.Proofs.check_grant_time_spec` against signed integer nanosecond
ordering, half-open window intersection and refusal precedence. The original
range regeneration and theorem remain mandatory. A drift refusal retains a
bounded raw byte diff in the EVS log before its scratch directory is removed.
The new theorem and combined regeneration still require hosted kernel validation;
the advisory capture itself earns no proof credit.

At `b595397`, fresh regeneration matched all three grant-time module payloads
and Lake built the generated modules and existing range theorem. The grant-time
ordering lemma failed: `omega` treated `Int.ofNat` and the normalization
hypotheses' Nat-to-Int coercions as different terms. The axiom guard then
correctly rejected the incomplete theorem's `sorryAx` dependency. Both Lean
records failed because their shared build includes this theorem.
[Exact failed snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46134360046/artifacts/15258808647)
has SHA-256 `a977720717c70bed14af44965246ebc48bdf951d251474c7ced602a97765f0e2`.
The P-083 raw member is `exacopy-evs/395f1bd3-6533-4722-8cef-f832ea6b08de.log`,
with SHA-256 `a9d8177dcbd0d022f1f0ed62778d785ce3a909d79c97436e078b3afef44ad56c`.
The correction uses the same coercion in the timestamp formula. Its mathematical
value, normalized domain, theorem statement and axiom allowlist are unchanged;
hosted kernel verification of the correction remains pending.

Clock sampling and monotonic classification, paired high-water updates,
retirement, mutex serialization, effects and native qualification remain
separate.
