# Endpoint retry verification

P-020 includes the bounded endpoint scheduler checks in this crate. The seven scheduler harnesses invoke the production `RetrySupervisor` with an injected monotonic clock, fixed grant expiry and typed attempt observations. They exercise no credentials, transport, or filesystem operations. Durable job identity and effect recovery belong to the managing application and journal. This packet supplies no extracted Lean or full P-020 evidence.

Run `verification/check.sh kani` from the endpoint crate or invoke its workspace-relative path. The dispatcher uses the shared pinned Kani, compiler and CBMC lock. It runs ten exact harness names and requires all twenty-two cover goals with unwinding checks enabled. The crate manifest links the principal history harness. The same gate requires a separate concrete cap witness, the five scheduler companions, the arithmetic equivalence lemma, the real jitter contract proof, and the real timing contract proof. The clean Kani invocation gives each selected harness up to 600 seconds. The standard evidence recorder keeps a 900-second limit for the entire clean gate, including setup, and treats a timeout as failure. The four mutation controls run separately with a 120-second limit each.

## Retained gate results

| Commit and evidence | Endpoint gate | Transient history | Arithmetic equivalence lemma |
| --- | --- | --- | --- |
| [`8c41289` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46096898324/artifacts/15243739377) | Exit 1 after 155.100 s. Five of six harnesses verified with fourteen covers. | CBMC reached its 120 s limit. | Outside this revision’s harness set. |
| [`31534dd` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46099119907/artifacts/15245338576) | Exit 1 after 634.016 s. Five of six harnesses verified with fourteen covers. | CBMC reached its 600 s limit. | Outside this revision’s harness set. |
| [`cca2551` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46101786882/artifacts/15247020306) | Exit 124 after 900.001 s at the recorder limit. Five of seven harnesses verified with fourteen covers. | CBMC reached its 600 s limit. No accepted cap cover. | Started; the recorder stopped it before a verdict or accepted interior cover. |
| [`cd52dae` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46105573911/artifacts/15247979716) | Exit 124 after 900.001 s at the recorder limit. Five of seven harnesses verified with fourteen covers. | MiniSAT 2.2.1 ran and CBMC reached its 600 s limit. No accepted cap cover. | MiniSAT 2.2.1 ran and the recorder stopped it before a verdict or accepted interior cover. |

The `cca2551` snapshot SHA-256 is `6acc51d76fb1bc78cb4c353e2e3b48f0881982a478bcbf192e247c4281e7ddb7`. Its raw member `exacopy-evs/3ea76766-4abb-4326-9727-5695a313a983.log` has SHA-256 `71a1fd900acb81c2c3b5afec13e2dc9f14ce896b2cbd5d3ef2fcf2b2948e6273`. The `cd52dae` snapshot SHA-256 is `8cf1f71e62de802e3c76c9520a56c002db4e0e768539642911f4818a910fa9b9`. Its raw member `exacopy-evs/266f1a2c-6c35-436a-9aeb-5dcf479a80bd.log` has SHA-256 `0a409c885e177c8dbc15baa6671d08f9e9527faebf90ddebd34b888050e3392d`. Neither revision reported a counterexample for the interrupted harnesses. The complete gate remains unresolved.

In the first composed run at `d3380af`, the history log confirmed the exact verified `equal_jitter` stub and MiniSAT 2.2.1. The history reached its 600-second limit, and the recorder cut off the subsequent arithmetic equivalence lemma at its 900-second limit. The real-function contract harness did not start. The gate exited 124 after 900.002 seconds. Five of eight harnesses verified with fourteen of seventeen covers. The raw log contains no reported counterexample from the interrupted harnesses.

The `d3380af` snapshot SHA-256 is `a083f22597cf68ff9628969bb565d674d3edac7a4c2109e48be4143f10eb20d5`. Its raw member `exacopy-evs/0940ee8e-71ad-4faf-8884-24eb3db9088c.log` has SHA-256 `b5a338b4e391282929c552711b86f03da21d94c28dae8874cb1393aac62096cb`. [Exact formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46109525196/artifacts/15250095462)

The exact nanosecond run at `10c23ea` again selected the verified jitter stub and MiniSAT 2.2.1. The history reached its 600-second limit, the arithmetic equivalence lemma was interrupted by the recorder, and the real-function contract harness did not start. The gate exited 124 after 900.001 seconds. Five of eight harnesses verified with fourteen of seventeen covers. The interrupted harnesses reported no counterexample. [Exact formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46112472744/artifacts/15251252206)

The `10c23ea` snapshot SHA-256 is `63c49e524deb421dcf7e196710a41e5a3c0491292ffb00f577e2aa2554cabaab`. Its raw member `exacopy-evs/f6c7ddb4-7716-4ca3-beea-0b0aa2a423e0.log` has SHA-256 `f91a8e72600dffc6d9385def846c7c4567048f8ab2e90e9df9ebfbafa598f8f8`.

The first selected-row run at `3b9ef5f` confirmed the verified jitter stub and MiniSAT 2.2.1. The history reached its 600-second limit, and the 900-second recorder interrupted the arithmetic equivalence lemma. The real-function contract harness did not start. The gate exited 124 after 900.002 seconds. Five of eight harnesses verified with fourteen of seventeen covers. The interrupted harnesses reported no counterexample. [Exact formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46118308336/artifacts/15253053872)

The `3b9ef5f` snapshot SHA-256 is `7c1f7275e54c5730a6aca9c18800947f0b570107c04fded972bf6a7f6ba0661d`. Its raw member `exacopy-evs/107edd91-49be-4e5b-9b55-b6ab82a5c925.log` has SHA-256 `745be1f52d4e71153152f131486625c7610f286f788117d0ac1202686df1485f`.

The transient history and arithmetic lemma select MiniSAT 2.2.1 from the existing pinned CBMC package. The five companion harnesses retain Kani’s default solver. Clean evidence must show the MiniSAT banner for both selected harnesses, and the inclusive-jitter mutation must show it for the transient history alongside the expected assertion failure. The solver selection leaves the proof inputs, assertions, covers, unwinding checks, and time limits intact. The retained `cd52dae` run confirms MiniSAT attendance for both harnesses. The two timeouts leave their verification unresolved. [Kani’s pinned solver selection](https://raw.githubusercontent.com/model-checking/kani/0d2328a93f0e0ff66132d6bfa1a7d884877cf862/kani-driver/src/call_cbmc.rs#L383) and [CBMC’s pinned release build](https://github.com/diffblue/cbmc/blob/cbmc-6.11.0/COMPILING.md#compiling-with-alternative-sat-solvers)

The history checks still use eight fresh full-width samples and the actual cumulative schedule through nine starts. Each exact delay now uses a `u64` product in the independent literal-window oracle. Its largest numerator is `(2^32 - 1) × 30,001 < 2^47`. A separate harness checks the same history helper against the original `u128` quotient for an arbitrary full-width `u32` sample and an independent three-bit selector spanning all eight literal rows. This quantifies the same sample-by-row domain as the earlier loop. Its interior-sample cover reaches the exact quotient on the second capped row. The earlier composition still called the real supervisor and substituted the pure jitter function. The separate real-function harness checks the exact returned duration for every full-width sample at all seven distinct literal ceilings. The timing composition checks the exact policy ceiling precondition at the actual calls. Clean evidence still requires the concrete jitter contract proof and the original wide-oracle equivalence together with the history and its companions.

The inclusive-jitter mutation gate runs the same row checks in a concrete, unannotated full history. The selected mutated production function runs directly. Ordinary harness calls also use their original functions. Kani’s `--no-assert-contracts` disables automatic contract wrappers on those ordinary calls, while the explicit contract proof and verified replacement remain active in their owning harnesses. The log gate rejects other substitutions and requires the exact verified-timing banner for the current composed history. The contract, composed history and concrete mutation remain unverified.

The prior nanosecond encoding compares the contract return and four history timing predicates through exact `Duration::as_nanos()` values. For valid normalized durations this is injective and preserves order. It removes expected `Duration::from_millis` normalization and repeated addition from the oracle while retaining all real supervisor operations, eight independent full-width samples, nine starts, exact early polling, cumulative feedback and the cap cover. Nanosecond sums fit `u128` without narrowing. The independent wide/narrow arithmetic lemma and real-callee proof are unchanged. The first hosted run of this encoding timed out as recorded above. The complete gate remains unverified under the same time limits.

The previous selected-row encoding draws an independent selector for one of its eight rows. It retains the selected row’s observed timing and sample, then checks its exact proportional mapping after the ninth start. The selector cannot alter any supervisor input or control flow. Kani must satisfy the exact mapping for every combination of the eight unrestricted samples and all eight row choices. The same run still checks every row’s generation, overlap refusal, timing bounds, endpoint cases, and early poll. A missing selected observation, unexpected supervisor result, or assertion failure rejects the proof. The concrete inclusive-jitter mutation continues checking the mapping inline at every row. Its first hosted run timed out as recorded above.

The health case samples elapsed whole seconds from zero to sixty and the instant one nanosecond before the threshold. The lease case independently evaluates the same jitter sample using an ample lease, checks the exact minimum, and requires a strict `unclipped > expiry` cover. The stale-admission case uses stale attempts from both the same and another owner.

## Mutation controls

Each patch in `verification/kani/mutations/` alters one scheduler guard. Apply one patch at a time from the workspace root of a disposable checkout of this integrated revision. The checker does not change tracked source and refuses a mutation run unless `src/connection_retry.rs` has the exact selected mutated SHA-256. Retain raw output and the exit status from each run. Remove the disposable checkout when the evidence is retained. Run the clean gate independently.

For each patch, use `git apply --unidiff-zero crates/interfaces/exacopy-endpoint/verification/kani/mutations/ID.patch` in the disposable workspace, then `crates/interfaces/exacopy-endpoint/verification/check.sh mutation ID`. The gate requires the log writer to exit successfully. The mutation gate also requires Kani exit 1, the one-harness failure summary and the named failed assertion. A successful mutant, a failed unwinding assertion, or a setup, compilation, timeout, tool or log-write failure invalidates the control.

| ID | Input that must expose the change | Target assertion |
| --- | --- | --- |
| `lease-clipping` | Lease 1 ms, initial jitter sample zero | `the lease clips the jittered wake exactly at expiry` |
| `source-fence` | Exact current route and SSH with only the source observation stale | `every independent observation must refer to the current attempt` |
| `health-activity` | `Healthy` without activity at 30 seconds | `reset requires both qualifying activity and the full healthy duration` |
| `inclusive-jitter` | Maximum u32 sample in the first 1,000 ms window | `every sample maps proportionally into the inclusive equal-jitter window` |

Mutation controls require their own retained assertion failures.

The initial inductive history checked the same per-row predicates at every loop step. An
immutable array represents all eight independent full-width samples. Each step
executes the real supervisor methods in order and supplies the observed wake to
the next step. The invariant checks the actual owner, fixed grant expiry,
generation, next backoff ceiling, phase and last clock observation. Independent
literal tables bound the row index and cumulative time. The inferred frame must
admit the three carried assignments, and the integer rank decreases from eight
to zero. The gate requires successful generated invariant entry and preservation,
rank, and write checks. A missing transform or missing write evidence fails the
gate. Explicit `loop_modifies` is omitted because the pinned tool does not support
it together with the scalar rank. [Kani loop-contract limitations](https://github.com/model-checking/kani/blob/kani-0.68.0/docs/src/reference/experimental/loop-contracts.md#limitations)

The cap predicate after the contracted loop describes an abstract exit. The
owning gate also requires a separate unannotated and unstubbed run from the real
constructor through the exact capped wakes at 61,500 and 91,500 ms and the ninth
start. The inclusive-jitter mutation still executes all eight concrete steps with
arbitrary full-width samples and every exact assertion inline. Budgets and solver
choices for the existing harnesses are unchanged. The first hosted result follows.

At `af75d35`, the first inductive run compiled and reached CBMC but reported
11 omitted call arguments filled with nondeterministic values. The transient
history produced no completed invariant, rank or write checks before timeout.
Six companions, including the concrete cap witness, passed with 15 of 18 covers.
The narrow/wide lemma started, the outer recorder interrupted it, and the real
jitter contract harness did not start. No assertion counterexample was observed.
[Exact snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46124250197/artifacts/15257094093)
has SHA-256 `d928070e4f9e2f5cb1b8e530719954624d0d7f94c71224cdf47e92046ff4389c`.
Its raw member `exacopy-evs/34c99af6-15b4-486d-8144-00681259dc34.log` has
SHA-256 `a8b22fbd5b4ddc24d94b4b68731affcb70853377ffaa1e35c858fbfe12eb76a6`.
The gate refuses the observed argument-substitution diagnostic in both clean
and mutation runs. That refusal does not repair the transformation or establish
the intended history. A countdown-only change remains unapplied because it
would not address the omitted-argument diagnostics in the invariant and real
step helpers. Proof scope, solvers and budgets remain unchanged.

The current history uses an ordinary unannotated loop. It still starts the
actual supervisor nine times, reports the same eight transient losses using
fresh independent full-width `u32` samples, and keeps every predicate inline.
It passes the real returned wake to the next iteration. Its sole verified
substitution is the private production `retry_timing` function consumed by
`RetrySupervisor::failure`. The real timing proof executes its real jitter
callee and compares the outcome with a wide nanosecond oracle across both
full normalized duration inputs and the complete jitter domain. Overflow must
refuse before lease clipping. A representable result must carry the exact wake
and next capped ceiling. Four covers distinguish overflow, clipping, exact
maximum time, and the capped high sample. All existing arithmetic, real jitter,
concrete cap, and mutation checks remain required. The tool-argument diagnostic
refusal also remains in force. The existing time limits and solver selections
remain in effect.

At `969549a` and `98c291b`, the consumed-timing encoding ran without the earlier
omitted-argument diagnostic and reported exactly one verified `retry_timing`
substitution. Six companion harnesses passed with fifteen of twenty-two covers,
including the real concrete capped trajectory. The arbitrary history reached
four MiniSAT banners before its CBMC timeout. The narrow/wide lemma reached
two banners before the outer recorder timed out with exit 124. Neither real
function contract harness began. No named assertion counterexample was observed;
these results leave the complete proof and contract composition unverified.

The [969549a snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46133037585/artifacts/15259567666)
has SHA-256 `421b1fa45e1251250449ccd614e91232a5cca81573e41a36a9a133f8a65db32e`.
Its raw member is `exacopy-evs/4c6f9a28-176c-4278-b1bc-25dea7ad12c2.log`,
with SHA-256 `b59efcb7a50018f8ac5fbe35a1796363ddc2ee1a9e9a22e4024d11352be48bb8`.
The independent [98c291b snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46133269159/artifacts/15259222436)
has SHA-256 `8717b360c77a7d2b67c368de150f43827da941b76821609e622013fa991a2c01`.
Its raw member is `exacopy-evs/141fd60f-26b9-462a-8f47-b0e13da1f37b.log`,
with SHA-256 `00ee723d79dc4142ec154b66371969e8b81dda4dc292ac4c7d3faacacba6087a`.

The current timing postcondition expresses the same wake through normalized
seconds and subseconds. For a delay of `1000q + r` milliseconds, it adds `q`
seconds and `r × 10^6` nanoseconds, carries at most once, and checks both
nonnegative seconds additions before clipping to the lease. The real timing
harness still requires the original wide-nanosecond assertion as well as this
postcondition over both complete normalized duration inputs. The clean history
compares native duration values through all eight losses and nine starts.
The concrete cap and mutation histories retain the original nanosecond
assertions and execute the real timing function without substitution. Solvers,
budgets, ten harnesses and twenty-two covers are unchanged. The new encoding's
proof and performance results remain pending hosted execution.
