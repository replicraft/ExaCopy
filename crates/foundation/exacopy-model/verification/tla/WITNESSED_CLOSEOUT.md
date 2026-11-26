# Witnessed closeout composition

This model follows the [witnessed closeout grammar](../../../../../docs/architecture/remote-witnessed-closeout.md). It composes repeated retained continuation, pre-intent retirement, publication and private receipt closeout. The [retained prefix](RETAINED_PREFIX.md) and [witnessed namespace](WITNESSED_PUBLICATION.md) checks keep their own scopes.

The search covers two physical attempt identities, initial logical runs 1, 62 and 63, strictly newer source epochs and a maximum of 64 consumed runs. The retained prefix admits up to two suffix checkpoints. A continued run keeps its original physical attempt, uses the latest accepted head, and can be followed by retirement and a fresh V1 attempt. The new V1 attempt needs its own positive checkpoint before another continuation. Only pre-intent phases can retire. An earlier stage and its declared witness stay retained when the next one is prepared.

The file end is bounded at 64 MiB. Independently bounded byte intervals, a finite sequence-position ceiling of 27, and 6,144 anonymous receipt bytes exercise reservation refusal before effects. The model consumes maximum frame widths and checks distinct longest byte and sequence paths. A clean closeout requires 5,989 bytes and nine frames. A late retirement and fresh startup can require 6,022 bytes. Kind 41 freezes complete source coverage before seal, verification and metadata. A public kind-7 submission cannot be reissued after restart.

## Receipt convergence

The model abstracts one protected receipt inode that is initially anonymous and can become exact pending or exact final. The process consuming a promotion permit stops on an uncertain result. Restart clears every old permit and observation. A fresh process with independently qualified exact pending custody and final absence can acquire a new one-shot private promotion permit. Every promotion invalidates its earlier observation. Completion requires a separate exact final-custody observation, pending absence, independently rechecked public and witness facts, and required barriers. This confirmation is mandatory after a known successful rename and after restart. At most one physical private rename can take effect. The resulting historical declaration alone provides no native observation or effect authority.

A deliberate diagnostic applies the stronger proposition that no private submission can follow any earlier unknown reply. Its counterexample reaches an ambiguous no-effect submission, restart, fresh exact observation, newly authorized permit and second submission. The same durable kind 42 and namespace can result from interruption before the first call. The modeled rule keeps the old session stopped and preserves convergence under a new lease. A recorded terminal uncertainty remains terminal. The model adds no failure record or wire version.

The model assumes truthful owner, lease, route, authority and protected namespace evidence. Fresh inspection abstracts the simultaneous exact public target, witness and receipt observations and required barriers. The model does not execute filesystem or journal operations, prove refinement by a production scanner, or qualify native process-crash or power-loss behavior. Fairness and eventual completion are outside the bounded check.

## Reproduce

Run with the owning pinned Temurin and TLC jar. Set TLC_LOG_DIR outside the model source directory to preserve each raw run and the input hashes.

```sh
TLA2TOOLS_JAR=/path/to/tla2tools.jar TLC_LOG_DIR=/path/to/logs \
  python3 -B crates/foundation/exacopy-model/verification/tla/check-witnessed-closeout.py
```

TLC 2.19 and Temurin 21.0.8+9 executed the exact model with one worker, seed 0 and fingerprint 0. The healthy run exhausted 36,331 generated and 20,339 distinct states with none queued. Fourteen single-rule weakening configurations detect run limit, prior-head and source-epoch errors, reuse of a retired stage, dropped retained witness, post-intent retirement, independent insufficient byte/slot/receipt capacity, changed frozen coverage, digest-only receipt, resurrected permit and same-session retry of an uncertain submission, and commit immediately after a known native success without independent final observation and barriers. Three reachability configurations produce traces for repeat after two checkpoints, retirement after metadata and closeout at run 64. The stronger no-resubmission diagnostic preserves the real fresh-reconciliation trace.
