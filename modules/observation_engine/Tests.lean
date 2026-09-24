import ObservationEngine.Finite
import ObservationEngine.Observation

open ObservationEngine

def sampleWorld (d q : Bool) :
    World Bool (fun _ => Unit) (fun _ => Bool) (fun _ _ _ => True) :=
  ⟨d, (), q, True.intro⟩

def sampleView (w : World Bool (fun _ => Unit) (fun _ => Bool)
    (fun _ _ _ => True)) : Sigma (fun _ : Bool => Unit) :=
  visible (fun _ _ => ()) w

def check (name : String) (actual expected : Verdict) : IO Unit := do
  if actual != expected then
    throw (IO.userError s!"FAIL {name}: got {repr actual}, expected {repr expected}")
  IO.println s!"PASS {name}"

def main : IO Unit := do
  check "empty_domain" (classify ([] : List Bool) (fun _ => ()) id ()) .outOfDomain
  check "unattained_query" (classify [true] id id false) .outOfDomain
  check "homogeneous_true" (classify [true] (fun _ => ()) id ()) .yes
  check "homogeneous_false" (classify [false] (fun _ => ()) id ()) .no
  check "mixed_fibre" (classify [true, false] (fun _ => ()) id ()) .unknown
  check "visible_filter" (classify [true, false] id id true) .yes
  check "opposite_visible_filter" (classify [true, false] id id false) .no
  check "duplicate_world" (classify [true, true] (fun _ => ()) id ()) .yes
  check "permuted_mixed" (classify [false, true] (fun _ => ()) id ()) .unknown
  check "incomplete_positive" (classify [true] (fun _ => ()) id ()) .yes
  check "expanded_ambiguous" (classify [true, false] (fun _ => ()) id ()) .unknown
  check "skeleton_retained" (classify [sampleWorld true true, sampleWorld false false] sampleView (fun w => w.selector) (sampleView (sampleWorld true true))) .yes
  IO.println "ALL CASES PASSED"
