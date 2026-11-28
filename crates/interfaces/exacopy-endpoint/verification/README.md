# Endpoint retry verification

P-020 includes the bounded endpoint scheduler checks in this crate. The six scheduler harnesses invoke the production `RetrySupervisor` with an injected monotonic clock, fixed grant expiry and typed attempt observations. They exercise no credentials, transport, or filesystem operations. Durable job identity and effect recovery belong to the managing application and journal. This packet supplies no extracted Lean or full P-020 evidence.

Run `verification/check.sh kani` from the endpoint crate or invoke its workspace-relative path. The dispatcher uses the shared pinned Kani, compiler and CBMC lock. It runs seven exact harness names and requires all sixteen cover goals with unwinding checks enabled. The crate manifest links the principal history harness. The same gate requires the five scheduler companions and the arithmetic equivalence lemma. The clean Kani invocation gives each selected harness up to 600 seconds. The standard evidence recorder keeps a 900-second limit for the entire clean gate, including setup, and treats a timeout as failure. At `8c41289`, five harnesses finished in 28.874 seconds of recorded verification time and the transient-backoff harness reached its 120-second limit. The full gate took 155.100 seconds. At `31534dd`, the same harness reached its 600-second limit and the gate took 634.016 seconds. Both runs verified five companions with fourteen covers. The updated arithmetic oracle and lemma still require execution. The four mutation controls run separately with a 120-second limit each.

The history checks still use eight fresh full-width samples and the actual cumulative schedule through nine starts. Each exact delay now uses a `u64` product in the independent literal-window oracle. Its largest numerator is `(2^32 - 1) × 30,001 < 2^47`. A separate harness checks the same history helper against the original `u128` quotient for every literal window under an arbitrary `u32` sample, with one interior-sample cover after all comparisons. Neither proof stubs the supervisor or assumes the equality. The inclusive-jitter mutant still runs the original history harness against the changed production function.

The health case samples elapsed whole seconds from zero to sixty and the instant one nanosecond before the threshold. The lease case independently evaluates the same jitter sample using an ample lease, checks the exact minimum, and requires a strict `unclipped > expiry` cover. The stale-admission case uses stale attempts from both the same and another owner.

## Mutation controls

Each patch in `verification/kani/mutations/` alters one scheduler guard. Apply one patch at a time from the workspace root of a disposable checkout of this integrated revision. The checker does not change tracked source and refuses a mutation run unless `src/connection_retry.rs` has the exact selected mutated SHA-256. Retain raw output and the exit status from each run. Remove the disposable checkout when the evidence is retained. Run the clean gate independently.

For each patch, use `git apply --unidiff-zero crates/interfaces/exacopy-endpoint/verification/kani/mutations/ID.patch` in the disposable workspace, then `crates/interfaces/exacopy-endpoint/verification/check.sh mutation ID`. The mutation gate requires an actual failed assertion in the only selected harness. A successful mutant, a failed unwinding assertion, or a setup, compilation, timeout or tool failure invalidates the control.

| ID | Input that must expose the change | Target assertion |
| --- | --- | --- |
| `lease-clipping` | Lease 1 ms, initial jitter sample zero | `the lease clips the jittered wake exactly at expiry` |
| `source-fence` | Exact current route and SSH with only the source observation stale | `every independent observation must refer to the current attempt` |
| `health-activity` | `Healthy` without activity at 30 seconds | `reset requires both qualifying activity and the full healthy duration` |
| `inclusive-jitter` | Maximum u32 sample in the first 1,000 ms window | `every sample maps proportionally into the inclusive equal-jitter window` |

The updated history, lemma, cover and mutation controls require execution. Source presence alone supplies no verification result.
