import ObservationEngine.Observation
import ObservationEngine.Finite

namespace ObservationEngine

def HasValue {W O : Type} (worlds : List W) (V : W → O)
    (Q : W → Bool) (v : O) (b : Bool) : Prop :=
  ∃ w, w ∈ worlds ∧ V w = v ∧ Q w = b

theorem seen_iff {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) (b : Bool) :
    seen worlds V Q v b = true ↔ HasValue worlds V Q v b := by
  simp [seen, HasValue, List.any_eq_true]

theorem classify_yes_iff {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) :
    classify worlds V Q v = .yes ↔
      HasValue worlds V Q v true ∧ ¬ HasValue worlds V Q v false := by
  rw [← seen_iff, ← seen_iff]
  unfold classify
  cases seen worlds V Q v true <;> cases seen worlds V Q v false <;> decide

theorem classify_no_iff {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) :
    classify worlds V Q v = .no ↔
      HasValue worlds V Q v false ∧ ¬ HasValue worlds V Q v true := by
  rw [← seen_iff, ← seen_iff]
  unfold classify
  cases seen worlds V Q v true <;> cases seen worlds V Q v false <;> decide

theorem classify_unknown_iff {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) :
    classify worlds V Q v = .unknown ↔
      HasValue worlds V Q v true ∧ HasValue worlds V Q v false := by
  rw [← seen_iff, ← seen_iff]
  unfold classify
  cases seen worlds V Q v true <;> cases seen worlds V Q v false <;> decide

theorem classify_outside_iff {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) :
    classify worlds V Q v = .outOfDomain ↔
      ¬ HasValue worlds V Q v true ∧ ¬ HasValue worlds V Q v false := by
  rw [← seen_iff, ← seen_iff]
  unfold classify
  cases seen worlds V Q v true <;> cases seen worlds V Q v false <;> decide

/-- A definite result applies to each listed compatible completion of the query. -/
theorem classify_yes_sound {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O)
    (answer : classify worlds V Q v = .yes)
    (w : W) (listed : w ∈ worlds) (visible : V w = v) : Q w = true := by
  have hn := ((classify_yes_iff worlds V Q v).mp answer).2
  cases hq : Q w with
  | true => rfl
  | false => exact False.elim (hn ⟨w, listed, visible, hq⟩)

theorem classify_no_sound {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O)
    (answer : classify worlds V Q v = .no)
    (w : W) (listed : w ∈ worlds) (visible : V w = v) : Q w = false := by
  have hn := ((classify_no_iff worlds V Q v).mp answer).2
  cases hq : Q w with
  | false => rfl
  | true => exact False.elim (hn ⟨w, listed, visible, hq⟩)

/-- Lifting a list result to all worlds requires an explicit completeness premise. -/
theorem complete_yes_sound {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O)
    (complete : ∀ w, w ∈ worlds)
    (answer : classify worlds V Q v = .yes)
    (w : W) (visible : V w = v) : Q w = true :=
  classify_yes_sound worlds V Q v answer w (complete w) visible


/-- No declared completion has the requested observation. -/
theorem classify_outside_iff_no_world {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) :
    classify worlds V Q v = .outOfDomain ↔
      ¬ ∃ w, w ∈ worlds ∧ V w = v := by
  rw [classify_outside_iff]
  constructor
  · rintro ⟨ht, hf⟩ ⟨w, hw, hv⟩
    cases hq : Q w with
    | false => exact hf ⟨w, hw, hv, hq⟩
    | true => exact ht ⟨w, hw, hv, hq⟩
  · intro h
    constructor <;> rintro ⟨w, hw, hv, _⟩ <;> exact h ⟨w, hw, hv⟩

/-- Lossy erasure: unknown and outOfDomain both become none. The agreement
 theorem below excludes outOfDomain through its attained-value premise. -/
def toPartial : Verdict → Option Bool
  | .yes => some true
  | .no => some false
  | .unknown => none
  | .outOfDomain => none

/-- The executable classifier implements Proposition 3.4 on its declared world
subtype, not on an unproved larger universe. Attainment excludes outOfDomain. -/
theorem finite_agrees_qStar {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool)
    (v : VisibleImage (fun w : {w : W // w ∈ worlds} => V w.val)) :
    toPartial (classify worlds V Q v.val) =
      qStar (fun w : {w : W // w ∈ worlds} => V w.val)
        (fun w => Q w.val) v := by
  cases answer : classify worlds V Q v.val with
  | outOfDomain =>
    have absent := (classify_outside_iff_no_world worlds V Q v.val).mp answer
    obtain ⟨⟨w, hw⟩, hv⟩ := v.property
    exact False.elim (absent ⟨w, hw, hv⟩)
  | yes =>
    change some true = _
    symm
    apply (qStar_some_iff _ _ v true).mpr
    rintro ⟨w, hw⟩ hv
    exact classify_yes_sound worlds V Q v.val answer w hw hv
  | no =>
    change some false = _
    symm
    apply (qStar_some_iff _ _ v false).mpr
    rintro ⟨w, hw⟩ hv
    exact classify_no_sound worlds V Q v.val answer w hw hv
  | unknown =>
    change none = _
    obtain ⟨⟨a, hal, hav, haq⟩, ⟨b, hbl, hbv, hbq⟩⟩ :=
      (classify_unknown_iff worlds V Q v.val).mp answer
    symm
    apply mixed_forces_unknown _ _ _ (qStar_sound _ _) v
      (⟨a, hal⟩ : {w : W // w ∈ worlds}) (⟨b, hbl⟩ : {w : W // w ∈ worlds})
      hav hbv
    change Q a ≠ Q b
    simp [haq, hbq]

end ObservationEngine
