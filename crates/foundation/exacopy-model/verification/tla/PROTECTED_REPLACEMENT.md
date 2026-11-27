# Protected replacement safety model

The explicit admission transitions and five additional negative controls are
integrated source awaiting the automatic formal gate. Earlier results apply
to their recorded model revisions. This correspondence table identifies test
analogues under trusted observations; it does not establish refinement or
native qualification.

At `b50ada3`, SANY rejected the initial record's closing bracket at line 60
before state exploration. The closing bracket is now indented inside the
conjunction item. This correction changes no admission fact, transition,
invariant, bound or negative-control oracle and awaits automatic verification.
[Failed hosted CI](https://github.com/replicraft/ExaCopy/actions/runs/46004576369).

This independent finite model covers one already verified regular-file
replacement, one source kept outside the affected namespace, one public
slot and a private reserved slot. The model selects either retention alone
or a mandatory independent image. The replay classification starts fresh,
with an existing relevant intent, or indeterminate despite identical
initial namespace observations. A separate admission step checks fresh
history, agreement of the independently held replay and current head,
exact owner approval, affirmative disclosure of the public gap and opaque
capture, and both current grants. The model varies one defective admission
fact at a time, including prior or uncertain history. Only an admitted
attempt can record new intent.
The external actor can replace the
public incumbent once before capture, put an occupant into the private
slot, and place an arrival into the temporary public gap. A foreign
pre-capture occupant may be an ordinary file or an opaque entry.

The abstract capture moves the actual slot occupant without replacing a
private incumbent. The original approved object survives a modeled earlier
external rebind in an external location. Both capture-barrier orderings,
a conflicting after-barrier report, refusal of an image, lost replies
before and after each namespace effect, and cancellation are explored.
There is no restoration, destructive cleanup, recovery publication or
post-crash retry transition.

| Model evidence | Rust correspondence |
| --- | --- |
| Exact owner approval and disclosure before new intent | `requires_exact_owner_approval_and_disclosure` |
| Separate current capture and publication grants | `requires_both_current_grants_in_the_held_context` |
| Independently held replay and head must agree | `rejects_unavailable_or_inconsistent_pre_intent_replay` |
| Existing or ambiguous history refuses before a new attempt | `rejects_previously_issued_or_uncertain_history_at_fresh_admission` |
| Actual entry retained after slot rebind | `actual_foreign_and_unsupported_captures_are_preserved_without_publication` |
| Both barriers and post-barrier identity | `both_capture_barriers_and_the_exact_postbarrier_actual_are_required` |
| Separate independent image before publication | `independent_image_requires_special_authority_stable_view_and_distinct_durable_bytes` |
| One opaque relocation and one exclusive placement | `capture_intent_binds_exact_head_and_reserved_raw_name_and_is_one_shot` and `all_effect_outcomes_are_terminal_and_only_no_clobber_can_place` |
| An uncertain attempt cannot accept a late effect report | `interruption_after_a_permit_cannot_accept_late_completion` |

The first three rows refer to the [transfer admission tests](../../../../engines/exacopy-transfer/src/protected_admission/tests.rs).
The remaining rows refer to the [pure decision tests](../../tests/protected_replace.rs).
The replay mismatch is abstract. The Rust tests additionally distinguish
unavailable replay or current-head evidence, exact held-context mismatch,
and journal successor bounds.

The Rust tests also check exact context and grant identity, lease, stable
physical filesystem separation, expiry, typed name, extent, stage seal,
record head and role-specific read/create evidence. TLC abstracts these
preconditions and assumes a truthful, serialized coordinator. Platform
qualification must independently establish literal slot-at-effect behavior,
namespace isolation and alias exclusion, grant serialization, read-only
source, correct quiescence and durable operations. Neither implementation
uses native storage effects. These checks do not establish native
process-crash or power-loss durability.

Run `TLA2TOOLS_JAR=/path/to/tla2tools.jar ./check-protected-replacement.sh`
from this directory with the pinned Temurin runtime. `TLC_LOG_DIR` retains
raw reports. The checker requires the positive queue to empty, requires
coverage of each major transition, and expects an invariant counterexample
for every mutation. The controls substitute the prelookup for the actual
entry, skip the public or private barrier, accept a foreign capture or stale
post-barrier report, bypass the required image, overwrite a late arrival,
reauthorize after uncertainty, admit from existing or ambiguous history
or divergent replay evidence, or skip approval, disclosure, or either grant
check. An invariant violation at the admission transition is required for
each admission control. A loader failure does not count as a working negative
control.
