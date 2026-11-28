# Endpoint retry verification

P-020 includes the bounded endpoint scheduler checks in this crate. The six scheduler harnesses invoke the production `RetrySupervisor` with an injected monotonic clock, fixed grant expiry and typed attempt observations. They exercise no credentials, transport, or filesystem operations. Durable job identity and effect recovery belong to the managing application and journal. This packet supplies no extracted Lean or full P-020 evidence.

Run `verification/check.sh kani` from the endpoint crate or invoke its workspace-relative path. The dispatcher uses the shared pinned Kani, compiler and CBMC lock. It runs seven exact harness names and requires all sixteen cover goals with unwinding checks enabled. The crate manifest links the principal history harness. The same gate requires the five scheduler companions and the arithmetic equivalence lemma. The clean Kani invocation gives each selected harness up to 600 seconds. The standard evidence recorder keeps a 900-second limit for the entire clean gate, including setup, and treats a timeout as failure. The four mutation controls run separately with a 120-second limit each.

## Retained gate results

| Commit and evidence | Endpoint gate | Transient history | Arithmetic equivalence lemma |
| --- | --- | --- | --- |
| [`8c41289` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46096898324/artifacts/15243739377) | Exit 1 after 155.100 s. Five of six harnesses verified with fourteen covers. | CBMC reached its 120 s limit. | Outside this revision’s harness set. |
| [`31534dd` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46099119907/artifacts/15245338576) | Exit 1 after 634.016 s. Five of six harnesses verified with fourteen covers. | CBMC reached its 600 s limit. | Outside this revision’s harness set. |
| [`cca2551` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46101786882/artifacts/15247020306) | Exit 124 after 900.001 s at the recorder limit. Five of seven harnesses verified with fourteen covers. | CBMC reached its 600 s limit. No accepted cap cover. | Started; the recorder stopped it before a verdict or accepted interior cover. |
| [`cd52dae` formal snapshot](https://github.com/replicraft/ExaCopy/actions/runs/46105573911/artifacts/15247979716) | Exit 124 after 900.001 s at the recorder limit. Five of seven harnesses verified with fourteen covers. | MiniSAT 2.2.1 ran and CBMC reached its 600 s limit. No accepted cap cover. | MiniSAT 2.2.1 ran and the recorder stopped it before a verdict or accepted interior cover. |

The `cca2551` snapshot SHA-256 is `6acc51d76fb1bc78cb4c353e2e3b48f0881982a478bcbf192e247c4281e7ddb7`. Its raw member `exacopy-evs/3ea76766-4abb-4326-9727-5695a313a983.log` has SHA-256 `71a1fd900acb81c2c3b5afec13e2dc9f14ce896b2cbd5d3ef2fcf2b2948e6273`. The `cd52dae` snapshot SHA-256 is `8cf1f71e62de802e3c76c9520a56c002db4e0e768539642911f4818a910fa9b9`. Its raw member `exacopy-evs/266f1a2c-6c35-436a-9aeb-5dcf479a80bd.log` has SHA-256 `0a409c885e177c8dbc15baa6671d08f9e9527faebf90ddebd34b888050e3392d`. Neither revision reported a counterexample for the interrupted harnesses. The complete seven-harness gate and its sixteen covers remain unresolved.

The transient history and arithmetic lemma select MiniSAT 2.2.1 from the existing pinned CBMC package. The five companion harnesses retain Kani’s default solver. Clean evidence must show the MiniSAT banner for both selected harnesses, and the inclusive-jitter mutation must show it for the transient history alongside the expected assertion failure. The solver selection leaves the proof inputs, assertions, covers, unwinding checks, and time limits intact. The retained `cd52dae` run confirms MiniSAT attendance for both harnesses. The two timeouts leave their verification unresolved. [Kani’s pinned solver selection](https://raw.githubusercontent.com/model-checking/kani/0d2328a93f0e0ff66132d6bfa1a7d884877cf862/kani-driver/src/call_cbmc.rs#L383) and [CBMC’s pinned release build](https://github.com/diffblue/cbmc/blob/cbmc-6.11.0/COMPILING.md#compiling-with-alternative-sat-solvers)

The history checks still use eight fresh full-width samples and the actual cumulative schedule through nine starts. Each exact delay now uses a `u64` product in the independent literal-window oracle. Its largest numerator is `(2^32 - 1) × 30,001 < 2^47`. A separate harness checks the same history helper against the original `u128` quotient for every literal window under an arbitrary `u32` sample, with one interior-sample cover after all comparisons. Neither proof stubs the supervisor or assumes the equality. The inclusive-jitter mutant still runs the original history harness against the changed production function.

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
