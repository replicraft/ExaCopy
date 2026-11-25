import Generated.Funs

open Aeneas Aeneas.Std

namespace ExaCopy.Proofs

/-- A file admits exactly the positive-length ranges whose mathematical end fits. -/
def rangeEnd (fileLen start len : Nat) : Option Nat :=
  if 0 < len ∧ start + len ≤ fileLen then some (start + len) else none

private def endToNat : CoreModels.core.option.Option U64 → Option Nat
  | .None => none
  | .Some stop => some stop.val

/-- The production predicate always returns successfully and agrees with unbounded arithmetic. -/
theorem checked_range_end_spec (fileLen start len : U64) :
    (do
      let result ← range.checked_range_end fileLen start len
      pure (endToNat result)) = .ok (rangeEnd fileLen.val start.val len.val) := by
  change Aeneas.Std.bind (range.checked_range_end fileLen start len)
    (fun outcome => RustM.ok (endToNat outcome)) = _
  by_cases zero : len = 0#u64
  · simp [range.checked_range_end, rangeEnd, zero, endToNat]
  · have positive : 0 < len.val := by scalar_tac
    have add := UScalar.overflowing_add_eq start len
    cases pair : UScalar.overflowing_add start len with
    | mk stop overflowed =>
      simp only [pair, UScalar.max_UScalarTy_U64_eq] at add
      by_cases overflow : U64.max < start.val + len.val
      · rw [if_pos overflow] at add
        obtain ⟨_, rfl⟩ := add
        have bound : fileLen.val ≤ U64.max := by scalar_tac
        have outside : ¬ (start.val + len.val ≤ fileLen.val) := by omega
        simp [range.checked_range_end, rangeEnd, zero, positive, outside,
          CoreModels.core.num.U64.checked_add, CoreModels.core.num.U64.overflowing_add,
          CoreModels.rust_primitives.arithmetic.overflowing_add_u64, pair,
          CoreModels.core.option.Option.Insts.CoreOpsTry_traitTry.branch,
          CoreModels.core.option.Option.Insts.CoreOpsTry_traitTryTOptionInfallible.branch,
          CoreModels.core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionInfallible.from_residual,
          endToNat]
      · rw [if_neg overflow] at add
        obtain ⟨exactAdd, rfl⟩ := add
        simp [range.checked_range_end, rangeEnd, zero, positive,
          CoreModels.core.num.U64.checked_add, CoreModels.core.num.U64.overflowing_add,
          CoreModels.rust_primitives.arithmetic.overflowing_add_u64, pair,
          CoreModels.core.option.Option.Insts.CoreOpsTry_traitTry.branch,
          CoreModels.core.option.Option.Insts.CoreOpsTry_traitTryTOptionInfallible.branch, exactAdd, endToNat]
        split <;> split <;> simp_all
        omega

/--
info: 'ExaCopy.Proofs.checked_range_end_spec' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in
#print axioms checked_range_end_spec

#print axioms checked_range_end_spec

end ExaCopy.Proofs
