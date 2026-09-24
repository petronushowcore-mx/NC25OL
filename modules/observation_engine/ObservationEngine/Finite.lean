import Std

namespace ObservationEngine

/-- Outside the declared domain is distinct from an ambiguous attained fibre. -/
inductive Verdict where
  | outOfDomain
  | yes
  | no
  | unknown
  deriving DecidableEq, Repr, BEq

/-- Whether a declared world with this observation and target value exists. -/
def seen {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) (b : Bool) : Bool :=
  worlds.any (fun w => decide (V w = v) && decide (Q w = b))

def fromFlags : Bool → Bool → Verdict
  | false, false => .outOfDomain
  | true, false => .yes
  | false, true => .no
  | true, true => .unknown

/-- Computes over exactly the supplied list, not an inferred complete universe. -/
def classify {W O : Type} [DecidableEq O]
    (worlds : List W) (V : W → O) (Q : W → Bool) (v : O) : Verdict :=
  fromFlags (seen worlds V Q v true) (seen worlds V Q v false)

end ObservationEngine
