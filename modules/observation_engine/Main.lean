import Lean.Data.Json
import ObservationEngine.Finite

open Lean
open Std.Internal.Parsec
open Std.Internal.Parsec.String

namespace ObservationEngine.Cli


/-- Reject unpaired surrogate escapes instead of replacing their identity. -/
private def strictEscapedChar : Parser Char := do
  if (← peek!) != 'u' then
    return ← Json.Parser.escapedChar
  skip
  let u1 ← Json.Parser.hexChar
  let u2 ← Json.Parser.hexChar
  let u3 ← Json.Parser.hexChar
  let u4 ← Json.Parser.hexChar
  let val := (u1 <<< 12) ||| (u2 <<< 8) ||| (u3 <<< 4) ||| u4
  if val < 0xD800 then
    return Char.ofNat val.toNat
  else if val < 0xDC00 then
    match ← optional (attempt (Json.Parser.finishSurrogatePair val)) with
    | some c => return c
    | none => fail "unpaired Unicode surrogate"
  else if val < 0xE000 then
    fail "unpaired Unicode surrogate"
  else
    return Char.ofNat val.toNat

private partial def strictString (acc : String := "") : Parser String := do
  let c ← any
  if c == '"' then return acc
  if c == '\\' then return ← strictString (acc.push (← strictEscapedChar))
  if c.val < 0x20 then fail "unexpected control character in string"
  strictString (acc.push c)

/- Parse containers and strings strictly; Lean's scalar parser handles numbers
   and literals. Reject duplicate keys before insertion could discard a value. -/
mutual
  private partial def strictValue (depth : Nat) : Parser Json := do
    let c ← peek!
    if (c == '{' || c == '[') && depth == 0 then
      fail "JSON nesting exceeds 64 containers"
    if c == '{' then
      skip; ws
      if (← peek!) == '}' then
        skip; ws
        return Json.obj ∅
      return Json.obj (← strictObject (depth - 1) ∅)
    else if c == '[' then
      skip; ws
      if (← peek!) == ']' then
        skip; ws
        return Json.arr #[]
      return Json.arr (← strictArray (depth - 1) #[])
    else if c == '"' then
      skip
      let text ← strictString
      ws
      return Json.str text
    else
      Json.Parser.anyCore

  private partial def strictObject (depth : Nat) (fields : Std.TreeMap.Raw String Json compare) :
      Parser (Std.TreeMap.Raw String Json compare) := do
    if (← any) != '"' then fail "object key must be a string"
    let key ← strictString
    if (fields.get? key).isSome then fail s!"duplicate object key: {key}"
    ws
    if (← any) != ':' then fail "expected ':'"
    ws
    let value ← strictValue depth
    let fields := fields.insert key value
    let next ← any
    ws
    if next == '}' then return fields
    if next == ',' then return ← strictObject depth fields
    fail "expected ',' or '}'"

  private partial def strictArray (depth : Nat) (items : Array Json) : Parser (Array Json) := do
    let value ← strictValue depth
    let next ← any
    ws
    let items := items.push value
    if next == ']' then return items
    if next == ',' then return ← strictArray depth items
    fail "expected ',' or ']'"
end

private def parseJson (text : String) : Except String Json :=
  Parser.run (do
    ws
    let value ← strictValue 64
    eof
    return value) text

structure DeclaredWorld where
  id : String
  skeleton : String
  observation : String
  targetHolds : Bool

structure Request where
  target : String
  worlds : List DeclaredWorld
  query : String × String

/-- These are opaque caller-declared projection keys; no extraction is performed. -/
private def visible (world : DeclaredWorld) : String × String :=
  (world.skeleton, world.observation)

private def checkFields (context : String) (allowed : List String) (value : Json) :
    Except String Unit := do
  let fields ← value.getObj?.mapError (fun error => s!"{context}: {error}")
  for (key, _) in fields.toList do
    unless allowed.contains key do
      throw s!"{context}: unknown field '{key}'"

private def field (context : String) (value : Json) (key : String) : Except String Json :=
  value.getObjVal? key |>.mapError (fun error => s!"{context}.{key}: {error}")

private def nonemptyString (context : String) (value : Json) (key : String) :
    Except String String := do
  let value ← field context value key
  let result ← value.getStr?.mapError (fun error => s!"{context}.{key}: {error}")
  if result.trimAscii.toString.isEmpty then
    throw s!"{context}.{key}: nonempty string required"
  return result

private def readWorld (index : Nat) (value : Json) : Except String DeclaredWorld := do
  let context := s!"worlds[{index}]"
  checkFields context ["id", "skeleton", "observation", "target_holds"] value
  let id ← nonemptyString context value "id"
  let skeleton ← nonemptyString context value "skeleton"
  let observation ← nonemptyString context value "observation"
  let target ← field context value "target_holds"
  let targetHolds ← target.getBool?.mapError (fun error => s!"{context}.target_holds: {error}")
  return { id, skeleton, observation, targetHolds }

private def readRequest (value : Json) : Except String Request := do
  checkFields "input" ["schema", "target", "worlds", "query"] value
  let version ← field "input" value "schema"
  let version ← version.getNat?.mapError (fun error => s!"input.schema: {error}")
  unless version == 1 do throw "input.schema: expected 1"
  let target ← nonemptyString "input" value "target"
  let worldValues ← field "input" value "worlds"
  let worldValues ← worldValues.getArr?.mapError (fun error => s!"input.worlds: {error}")
  let mut worlds := []
  let mut ids : List String := []
  for index in [:worldValues.size] do
    let world ← readWorld index worldValues[index]!
    if ids.contains world.id then throw s!"worlds[{index}].id: duplicate id '{world.id}'"
    ids := world.id :: ids
    worlds := world :: worlds
  let query ← field "input" value "query"
  checkFields "query" ["skeleton", "observation"] query
  let skeleton ← nonemptyString "query" query "skeleton"
  let observation ← nonemptyString "query" query "observation"
  return { target, worlds := worlds.reverse, query := (skeleton, observation) }

private def verdictName : Verdict → String
  | .outOfDomain => "outside_declared_domain"
  | .yes => "target_true_in_declared_fibre"
  | .no => "target_false_in_declared_fibre"
  | .unknown => "insufficient_basis"

/-- The decision comes solely from classify; the remaining traversal extracts evidence. -/
private def report (request : Request) : Except String Json := do
  let verdict := classify request.worlds visible DeclaredWorld.targetHolds request.query
  let matching := request.worlds.filter (fun world => decide (visible world = request.query))
  let witness ←
    if verdict == .unknown then
      match matching.find? (fun world => world.targetHolds),
            matching.find? (fun world => !world.targetHolds) with
      | some positive, some negative =>
        pure [("witness", Json.mkObj [
          ("true_world_id", Json.str positive.id),
          ("false_world_id", Json.str negative.id)])]
      | _, _ => throw "internal error: mixed verdict has no opposing witnesses"
    else
      pure []
  return Json.mkObj ([
    ("schema", toJson (1 : Nat)),
    ("target", Json.str request.target),
    ("scope", Json.str "supplied_compatible_worlds"),
    ("query", Json.mkObj [
      ("skeleton", Json.str request.query.1),
      ("observation", Json.str request.query.2)]),
    ("verdict", Json.str (verdictName verdict)),
    ("matching_world_ids", toJson (matching.map DeclaredWorld.id))
  ] ++ witness)

private def emitError (message : String) : IO UInt32 := do
  let stderr ← IO.getStderr
  stderr.putStrLn (Json.mkObj [("error", Json.str message)]).compress
  return 2

/-- Reject inputs above 1 MiB, including when the file grows after its metadata was read. -/
private def readInput (path : System.FilePath) : IO String := do
  if (← path.metadata).byteSize > 1048576 then
    throw <| IO.userError "input exceeds 1048576 bytes"
  let handle ← IO.FS.Handle.mk path .read
  let mut bytes := ByteArray.empty
  repeat
    let chunk ← handle.read 4096
    if chunk.isEmpty then break
    if bytes.size + chunk.size > 1048576 then
      throw <| IO.userError "input exceeds 1048576 bytes"
    bytes := bytes ++ chunk
  match String.fromUTF8? bytes with
  | some text => return text
  | none => throw <| IO.userError "input is not valid UTF-8"

def run (args : List String) : IO UInt32 := do
  match args with
  | [path] =>
    try
      let text ← readInput path
      match parseJson text >>= readRequest >>= report with
      | .error error => emitError error
      | .ok result =>
        IO.println result.compress
        return 0
    catch error =>
      emitError s!"I/O error: {error}"
  | _ => emitError "usage: observation-engine INPUT.json"

end ObservationEngine.Cli

def main (args : List String) : IO UInt32 :=
  ObservationEngine.Cli.run args