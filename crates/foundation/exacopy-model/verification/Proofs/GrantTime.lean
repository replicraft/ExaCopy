import Generated.GrantTime.Funs
import Lean.Util.CollectAxioms
import Lean.Elab.Command

open Aeneas Aeneas.Std

namespace ExaCopy.Proofs

/-- An extracted signed Unix second and its unsigned subsecond component. -/
abbrev UtcTimestamp := I64 × U32

/-- The mathematical timestamp before any clock window comparison. -/
def utcNanos (time : UtcTimestamp) : Int :=
  time.1.val * 1000000000 + (time.2.val : Int)

/-- A timestamp's subsecond component is less than one second. -/
def normalizedUtc (time : UtcTimestamp) : Prop :=
  time.2.val < 1000000000

/-- Both endpoints are normalized. Their order is unrestricted. -/
def normalizedWindow (window : grant_time.UtcWindow) : Prop :=
  normalizedUtc window.starts_at ∧ normalizedUtc window.expires_at

/-- An optional qualification contributes endpoints only when present. -/
def normalizedQualification (qualification : Option grant_time.UtcWindow) : Prop :=
  match qualification with
  | none => True
  | some window => normalizedWindow window

/-- Membership in a half-open UTC interval. -/
abbrev inUtcWindow (window : grant_time.UtcWindow) (now : Int) : Prop :=
  utcNanos window.starts_at ≤ now ∧ now < utcNanos window.expires_at

/-- Regression takes priority. A current monotonic sample requires membership
in the original interval and in the qualification interval when present. -/
def grantTimeDecision
    (monotonic : grant_time.MonotonicObservation) (now previous : Int)
    (original : grant_time.UtcWindow) (qualification : Option grant_time.UtcWindow) :
    CoreModels.core.result.Result Unit grant_time.GrantTimeRefusal :=
  if now < previous then .Err .Regressed
  else
    match monotonic with
    | .Regressed => .Err .Regressed
    | .Expired => .Err .Expired
    | .Current =>
      match qualification with
      | none => if inUtcWindow original now then .Ok () else .Err .Expired
      | some window =>
        if inUtcWindow original now ∧ inUtcWindow window now then .Ok ()
        else .Err .Expired

private theorem utcNanos_lt_iff (left right : UtcTimestamp)
    (hleft : normalizedUtc left) (hright : normalizedUtc right) :
    utcNanos left < utcNanos right ↔
      left.1.val < right.1.val ∨
        (left.1.val = right.1.val ∧ left.2.val < right.2.val) := by
  unfold normalizedUtc at hleft hright
  unfold utcNanos
  omega

private theorem grant_time_before_spec (left right : UtcTimestamp)
    (hleft : normalizedUtc left) (hright : normalizedUtc right) :
    grant_time.before left right = .ok (decide (utcNanos left < utcNanos right)) := by
  rcases left with ⟨ls, ln⟩
  rcases right with ⟨rs, rn⟩
  have order := utcNanos_lt_iff (ls, ln) (rs, rn) hleft hright
  change utcNanos (ls, ln) < utcNanos (rs, rn) ↔
    ls.val < rs.val ∨ (ls.val = rs.val ∧ ln.val < rn.val) at order
  by_cases less : ls.val < rs.val
  · simp [grant_time.before, *]
  · by_cases equal : ls.val = rs.val
    · by_cases subsecondLess : ln.val < rn.val <;>
        simp [grant_time.before, IScalar.eq_equiv, *]
    · simp [grant_time.before, IScalar.eq_equiv, *]

private theorem grant_time_contains_spec (window : grant_time.UtcWindow) (time : UtcTimestamp)
    (hwindow : normalizedWindow window) (htime : normalizedUtc time) :
    grant_time.contains window time = .ok (decide (inUtcWindow window (utcNanos time))) := by
  change normalizedUtc window.starts_at ∧ normalizedUtc window.expires_at at hwindow
  have start := grant_time_before_spec time window.starts_at htime hwindow.1
  have stop := grant_time_before_spec time window.expires_at htime hwindow.2
  by_cases early : utcNanos time < utcNanos window.starts_at
  · have outside : ¬ inUtcWindow window (utcNanos time) :=
      fun member => (not_lt_of_ge member.1) early
    simp [grant_time.contains, *]
  · have reached : utcNanos window.starts_at ≤ utcNanos time := le_of_not_gt early
    by_cases beforeEnd : utcNanos time < utcNanos window.expires_at <;>
      simp [grant_time.contains, inUtcWindow, *]

/-- The extracted grant decision terminates with the exact UTC and monotonic
admission result on every normalized input. -/
theorem check_grant_time_spec
    (monotonic : grant_time.MonotonicObservation) (current previous : UtcTimestamp)
    (original : grant_time.UtcWindow) (qualification : Option grant_time.UtcWindow)
    (hcurrent : normalizedUtc current) (hprevious : normalizedUtc previous)
    (horiginal : normalizedWindow original)
    (hqualification : normalizedQualification qualification) :
    grant_time.check_grant_time monotonic current previous original qualification =
      .ok (grantTimeDecision monotonic (utcNanos current) (utcNanos previous)
        original qualification) := by
  have order := grant_time_before_spec current previous hcurrent hprevious
  have originalResult := grant_time_contains_spec original current horiginal hcurrent
  cases monotonic with
  | Regressed =>
    by_cases rollback : utcNanos current < utcNanos previous <;>
      simp [grant_time.check_grant_time, grantTimeDecision, *]
  | Expired =>
    by_cases rollback : utcNanos current < utcNanos previous <;>
      simp [grant_time.check_grant_time, grantTimeDecision, *]
  | Current =>
    cases qualification with
    | none =>
      by_cases rollback : utcNanos current < utcNanos previous <;>
        by_cases originalAllows : inUtcWindow original (utcNanos current) <;>
        simp [grant_time.check_grant_time, grantTimeDecision, *]
    | some window =>
      have qualificationResult := grant_time_contains_spec window current hqualification hcurrent
      by_cases rollback : utcNanos current < utcNanos previous <;>
        by_cases originalAllows : inUtcWindow original (utcNanos current) <;>
        by_cases qualificationAllows : inUtcWindow window (utcNanos current) <;>
        simp [grant_time.check_grant_time, grantTimeDecision, *]

open Lean in
run_cmd do
  let dependencies ← Lean.collectAxioms ``check_grant_time_spec
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  for dependency in dependencies do
    unless allowed.contains dependency do
      throwError "Unexpected trust dependency for check_grant_time_spec: {dependency}"

#print axioms check_grant_time_spec

end ExaCopy.Proofs
