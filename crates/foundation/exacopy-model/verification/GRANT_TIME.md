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

At `fdf4ae1b09f545a9277e55ec36eae4f4bc4d81da`, the recorder marked both
isolated Kani records passed on `x86_64-unknown-linux-gnu`. The logs report
Kani `0.68.0`, CBMC `6.11.0` and Rust `1.100.0-nightly` at `8925ea358`.
Both runners retain unwind checks and the 900-second per-record deadline.

P-083 exited zero in 6.429 seconds. The log reported both decision assertions
and 12 of 12 covers with `exacopy_model::grant_time::before` as its sole
verified stub. It reported the real comparator assertion and 4 of 4 covers
without a stub. The same real comparator log contains four omitted-argument
diagnostics. CBMC twice reported a nondeterministic replacement in
`enter_contract_clause` when calling `usize::saturating_add` and twice in
`exit_contract_clause` when calling `usize::saturating_sub`. The original
EVS pass remains recorded. Its Kani proof qualification is withdrawn because
the transformed calls do not establish the intended contract semantics.
The record binds `src/grant_time.rs` at SHA-256
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
The P-004 range log contains no omitted-argument diagnostic.

At `2f8d567`, P-083 again exited zero with the same four warnings in the
real comparator and an EVS pass. The raw member
`exacopy-evs/2b7a5b16-129a-48b9-bd11-951d946d1a9a.log` has SHA-256
`6974fc1a233c116a913a2202bba5a028e78a9db1d1ba8b48d3ea2c4ac86cce9c`.
The [exact snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46140123678/artifacts/15261804678)
has SHA-256 `83b3f84b887bfffdb4db412fe5c59027d48e08ffba92da4226fc9251084436b2`.
The common model Kani runner now rejects the diagnostic in either the range
or grant-time log before accepting a successful tool exit. This Kani tool
finding leaves the independently extracted and kernel-checked Lean evidence
below intact.

At `7ba5567`, the common runner rejected the same four diagnostics despite
Kani's apparent two-harness success. The command exited 1 and the recorder
retained a failed P-083 record. The [early Kani snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46143750803/artifacts/15263177925)
has SHA-256 `f3343162d380fae677f03b3cdb153c51f863d9d2682720f93bb9429023461a6c`.
Its raw member `exacopy-evs/b0f661b7-e26f-4ecd-898e-3eddaa81be7f.log`
has SHA-256 `1223346bff434c96bcd5050e686d26d65767023f6c4f39b4a84371e0f51fac2f`.
This verifies the refusal behavior; it supplies no new Kani proof credit.

The `fdf4ae1` advisory extraction completed with exit zero. Its
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
The advisory capture itself earns no proof credit.

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
the correction was then submitted to hosted kernel verification.

The corrected theorem passed at `72cc9bb5d9054f48f160feb113cd39047b155fa9`.
Both P-083 and P-004 passed the shared gate on `x86_64-unknown-linux-gnu`
with Lean `4.31.0` at `68218e876d2a38b1985b8590fff244a83c321783`. Each run
freshly regenerated and compared all six Range and GrantTime modules and
kernel-checked both theorem files. Both theorem reports list exactly
`propext`, `Classical.choice` and `Quot.sound`. Source correspondence assumes
the pinned Charon and Aeneas translation and Hax scalar models.

P-083's extracted scalar decision matches the independent signed integer
nanosecond rule for normalized UTC operands, the original and optional
qualification half-open windows, and regression-before-expiry precedence.
The theorem calls the generated decision in `Generated/GrantTime/Funs.lean`,
SHA-256 `ab048e0ace18a4ee575773dd39e477fef50de1313264b44075646d37d32f4d2b`.
The checked `Proofs/GrantTime.lean` has SHA-256
`bd90bd0c26ae147729f4ea3646e4b4abd1a5f1cbdcf972a87816a29661d8aaed`.
The raw P-083 member is `exacopy-evs/2caddfff-3b32-4f30-b378-9abe5fd8265d.log`,
with SHA-256 `2dad614c2be6c571b627a0c997a62228c715be4682470b767bbf65fd47ff289b`.
The raw P-004 member is `exacopy-evs/9901a88b-b94b-47c4-b94a-36dd5d1d6a0c.log`,
with SHA-256 `3243a1fbc98b5b423bde27902b5670810eada8791cbf7a44f6df663e24a8191f`.
[Exact hosted snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46135567347/artifacts/15260026137)
contains both logs and their EVS records and has SHA-256
`7af9848fa99673a98723d7178f484954d0895434f89dbc598ee08dfcd487f2fd`.

Clock sampling and monotonic classification, paired high-water updates,
retirement, mutex serialization, effects and native qualification remain
separate.
