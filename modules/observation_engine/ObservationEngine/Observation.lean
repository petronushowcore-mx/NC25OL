import Std

/-! Observation-relative verification.
Double Fibre v1.1: Theorem 3.2 (1 <-> 2), Corollary 3.3, Proposition 3.4.
The set-theoretic results extend to arbitrary types. Selectors and compatibility
remain parameters; their application-specific semantics are not formalised.
No entropy, semantic extraction, or runtime authorisation is formalised here.
-/
namespace ObservationEngine

/-- Only compatible history-selector pairs inhabit the declared world space. -/
structure World (D : Type) (H A : D → Type)
    (C : (d : D) → H d → A d → Prop) where
  skeleton : D
  history : H skeleton
  selector : A skeleton
  compatible : C skeleton history selector

/-- The visible channel retains the skeleton as well as the observation. -/
def visible {D : Type} {H A Y : D → Type}
    {C : (d : D) → H d → A d → Prop}
    (observeHistory : (d : D) → H d → Y d) (w : World D H A C) : Sigma Y :=
  ⟨w.skeleton, observeHistory w.skeleton w.history⟩

def VisibleImage {W O : Type} (V : W → O) :=
  {v : O // ∃ w, V w = v}

def observe {W O : Type} (V : W → O) (w : W) : VisibleImage V :=
  ⟨V w, w, rfl⟩

def FibreConstant {W O T : Type} (V : W → O) (Q : W → T) : Prop :=
  ∀ a b, V a = V b → Q a = Q b

def FactorsThrough {W O T : Type} (V : W → O) (Q : W → T) : Prop :=
  ∃ q : VisibleImage V → T, ∀ w, q (observe V w) = Q w

/-- Theorem 3.2, the equivalence of statements 1 and 2 only.
This implication needs no finiteness or prior; the entropy equivalence is excluded.
-/
theorem factorization_iff {W O T : Type} (V : W → O) (Q : W → T) :
    FactorsThrough V Q ↔ FibreConstant V Q := by
  constructor
  · rintro ⟨q, hq⟩ a b hab
    have hi : observe V a = observe V b := Subtype.ext hab
    exact (hq a).symm.trans ((congrArg q hi).trans (hq b))
  · intro h
    classical
    refine ⟨fun v => Q (Classical.choose v.property), ?_⟩
    intro w
    apply h
    exact Classical.choose_spec (observe V w).property

/-- Corollary 3.3: a compatible collision refutes exact visible verification. -/
theorem collision_refutes_exact {W O T : Type} (V : W → O) (Q : W → T)
    (a b : W) (same : V a = V b) (different : Q a ≠ Q b) :
    ¬ FactorsThrough V Q := by
  intro exactVerifier
  exact different ((factorization_iff V Q).mp exactVerifier a b same)

/-- A binary verdict is justified only when the entire attained fibre agrees. -/
def Homogeneous {W O : Type} (V : W → O) (Q : W → Bool)
    (v : VisibleImage V) (b : Bool) : Prop :=
  ∀ w, V w = v.val → Q w = b

/-- A logical classifier; classical choice makes no runtime algorithm claim. -/
noncomputable def qStar {W O : Type} (V : W → O) (Q : W → Bool)
    (v : VisibleImage V) : Option Bool := by
  classical
  exact if Homogeneous V Q v true then some true
    else if Homogeneous V Q v false then some false else none

theorem homogeneous_unique {W O : Type} {V : W → O} {Q : W → Bool}
    {v : VisibleImage V} {b c : Bool}
    (hb : Homogeneous V Q v b) (hc : Homogeneous V Q v c) : b = c := by
  obtain ⟨w, hw⟩ := v.property
  exact (hb w hw).symm.trans (hc w hw)

/-- Proposition 3.4: both soundness and decisiveness on homogeneous fibres. -/
theorem qStar_some_iff {W O : Type} (V : W → O) (Q : W → Bool)
    (v : VisibleImage V) (b : Bool) :
    qStar V Q v = some b ↔ Homogeneous V Q v b := by
  classical
  unfold qStar
  split
  · rename_i ht
    constructor
    · intro he
      have hb : true = b := Option.some.inj he
      simpa [← hb] using ht
    · intro hb
      exact congrArg some (homogeneous_unique ht hb)
  · rename_i ht
    split
    · rename_i hf
      constructor
      · intro he
        have hb : false = b := Option.some.inj he
        simpa [← hb] using hf
      · intro hb
        exact congrArg some (homogeneous_unique hf hb)
    · rename_i hf
      constructor
      · intro he
        cases he
      · intro hb
        cases b
        · exact False.elim (hf hb)
        · exact False.elim (ht hb)

def Sound {W O : Type} (V : W → O) (Q : W → Bool)
    (classifier : VisibleImage V → Option Bool) : Prop :=
  ∀ v b, classifier v = some b → Homogeneous V Q v b

theorem qStar_sound {W O : Type} (V : W → O) (Q : W → Bool) :
    Sound V Q (qStar V Q) := by
  intro v b hb
  exact (qStar_some_iff V Q v b).mp hb

/-- Any decisive answer of any sound visible classifier is also made by qStar. -/
theorem qStar_maximal {W O : Type} (V : W → O) (Q : W → Bool)
    (classifier : VisibleImage V → Option Bool) (sound : Sound V Q classifier)
    (v : VisibleImage V) (b : Bool) (answer : classifier v = some b) :
    qStar V Q v = some b := by
  exact (qStar_some_iff V Q v b).mpr (sound v b answer)

/-- Mixed attained fibres force an unknown answer for every sound classifier. -/
theorem mixed_forces_unknown {W O : Type} (V : W → O) (Q : W → Bool)
    (classifier : VisibleImage V → Option Bool) (sound : Sound V Q classifier)
    (v : VisibleImage V) (a b : W)
    (ha : V a = v.val) (hb : V b = v.val) (different : Q a ≠ Q b) :
    classifier v = none := by
  cases he : classifier v with
  | none => rfl
  | some answer =>
    have h := sound v answer he
    exact False.elim (different ((h a ha).trans (h b hb).symm))

end ObservationEngine
