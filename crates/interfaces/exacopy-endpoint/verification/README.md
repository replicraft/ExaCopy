# Endpoint retry verification

P-020 includes the bounded endpoint scheduler checks in this crate. The harnesses invoke the production `RetrySupervisor` with an injected monotonic clock, fixed grant expiry and typed attempt observations. They exercise no credentials, transport, or filesystem operations. Durable job identity and effect recovery belong to the managing application and journal. This packet supplies no extracted Lean or full P-020 evidence.

Run `verification/check.sh kani` from the endpoint crate or invoke its workspace-relative path. The dispatcher uses the shared pinned Kani, compiler and CBMC lock. It runs six exact harness names and requires all fifteen cover goals with unwinding checks enabled. The crate manifest links the principal harness and the same gate checks the companions. The six clean harnesses have individual 120-second solver limits, up to 720 seconds before setup. Each of the four separate mutation runs has a 120-second solver limit. Their full combined budget is 1,200 seconds before setup, and fitting them into one 900-second evidence-recorder run is unverified. The standard evidence recorder bounds the clean gate, including setup, at 900 seconds and treats a timeout as failure.

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

The new harnesses, covers, and mutation controls require execution. Source presence alone supplies no verification result.
