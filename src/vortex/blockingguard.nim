## Compile-time guard for the values that cross into `req.blocking`.
##
## A `blocking:` body runs on a worker thread; only value data can safely cross
## the loop/worker boundary. A `ref`/`ptr`/`closure` (top-level or nested in a
## field) is *shared*, not copied, so mutating it there races the loop thread --
## a silent data race (see the cross-thread ORC rules). This module rejects such
## arguments at compile time, and provides the sanctioned escape: a value wrapped
## in `std/isolation`'s `isolate(...)` (a compiler-checked proof of unique
## ownership) may cross, and is `extract`ed back to the plain type inside the
## block.
##
## `isolation` is re-exported so `isolate`/`extract`/`Isolated` are in scope
## wherever `req.blocking` is.

import std/[macros, isolation]
export isolation

proc isIsolatedType(t: NimNode): bool =
  t.kind == nnkBracketExpr and t.len >= 1 and t[0].eqIdent("Isolated")

proc reachesManaged(t: NimNode, seen: var seq[string]): bool

proc recListReaches(rl: NimNode, seen: var seq[string]): bool =
  ## Walk an object/tuple field list, including variant (`case`) branches.
  for def in rl:
    case def.kind
    of nnkIdentDefs:
      if reachesManaged(def[^2], seen): return true
    of nnkRecCase:
      if reachesManaged(def[0][^2], seen): return true      # discriminator type
      for i in 1 ..< def.len:                                # of/else branches
        if def[i][^1].kind == nnkRecList and recListReaches(def[i][^1], seen):
          return true
    else: discard
  false

proc reachesManaged(t: NimNode, seen: var seq[string]): bool =
  ## Does type `t` transitively contain a ref / ptr / cstring / pointer / closure?
  ## Unknown shapes fail open (return false) so the guard never rejects a type it
  ## cannot analyse; `Isolated[T]` is treated as an allowed handle.
  var n = t
  if n.kind == nnkSym:
    if n.repr in seen: return false          # break recursive types
    seen.add n.repr
    n = n.getTypeImpl
  case n.kind
  of nnkRefTy, nnkPtrTy: return true
  of nnkProcTy:
    return n.len > 1 and n[1].kind == nnkPragma and
           n[1].findChild(it.eqIdent"closure") != nil
  of nnkBracketExpr:
    if isIsolatedType(n): return false       # Isolated[T]: allowed
    for i in 1 ..< n.len:                     # seq[T] / array[I,T] / Table[K,V] ...
      if n[i].kind != nnkIntLit and reachesManaged(n[i], seen): return true
    return false
  of nnkObjectTy:
    if n[1].kind == nnkOfInherit and reachesManaged(n[1][0], seen): return true
    if n[2].kind == nnkRecList: return recListReaches(n[2], seen)
    return false
  of nnkTupleTy: return recListReaches(n, seen)
  of nnkDistinctTy: return reachesManaged(n[0], seen)
  of nnkSym: return n.strVal in ["cstring", "pointer"]
  else: return false

macro assertBlockingType*(T: typedesc): untyped =
  ## Compile error if `T` reaches a ref/ptr/closure. Internal (used by prepArg).
  let ty = getTypeInst(T)[1]
  var seen: seq[string]
  if reachesManaged(ty, seen):
    error("req.blocking: a value of type '" & ty.repr & "' cannot cross to the " &
          "worker thread -- it (or a field) is a ref/ptr/closure, which would be " &
          "shared, not copied, and racing the loop thread. Pass value data, " &
          "return the result from the block, or move it in with isolate(...).")
  newEmptyNode()

template prepArg*(x: untyped): untyped =
  ## Per-argument preparation for the value tuple that crosses to the worker:
  ## a plain value passes through (after the static check); an `Isolated[T]`
  ## (which must be a `var`) is extracted back to `T`. Internal.
  when x is Isolated:
    extract(x)
  else:
    assertBlockingType(typeof(x))
    x
