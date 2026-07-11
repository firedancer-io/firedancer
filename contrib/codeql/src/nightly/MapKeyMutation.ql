/**
 * @name Do not mutate keys that are currently used in a map.
 * @description Mutating a key that is currently used in a map corrupts it.
 * @kind problem
 * @id asymmetric-research/map-key-mutation
 * @problem.severity warning
 * @precision medium
 * @tags correctness
 */

import cpp
import semmle.code.cpp.valuenumbering.HashCons
import filter

bindingset[a, b]
private predicate sameExpr(Expr a, Expr b) {
  hashCons(a.getFullyConverted()) = hashCons(b.getFullyConverted())
}

bindingset[mapName]
private string mapKey(string mapName) {
  exists(Macro name, Macro key |
    name.hasName("MAP_NAME") and
    key.hasName("MAP_KEY") and
    name.getFile() = key.getFile() and
    name.getLocation().getStartLine() <= key.getLocation().getStartLine() and
    result = key.getBody() and
    mapName = name.getBody() and
    not exists(Macro other |
      other.hasName("MAP_NAME") and
      other.getFile() = key.getFile() and
      name.getLocation().getStartLine() < other.getLocation().getStartLine() and
      other.getLocation().getStartLine() < key.getLocation().getStartLine()
    )
  )
}

bindingset[e]
private predicate denotesVariable(Expr e, Variable v) {
  e = v.getAnAccess() or
  exists(PointerDereferenceExpr deref |
    e = deref and
    deref.getOperand() = v.getAnAccess()
  ) or
  exists(Cast cast |
    e = cast and
    cast.getExpr() = v.getAnAccess()
  )
}

bindingset[access]
private predicate accessesKey(Variable ele, string key, FieldAccess access) {
  key = access.getTarget().getName() and
  denotesVariable(access.getQualifier(), ele)
  or
  exists(FieldAccess parent |
    parent = access.getQualifier() and
    key = parent.getTarget().getName() + "." + access.getTarget().getName() and
    denotesVariable(parent.getQualifier(), ele)
  )
}

private class MapQueryCall extends FunctionCall {
  MapQueryCall() { this.getTarget().getName().matches("%_ele_query") }

  string getMapName() { result = this.getTarget().getName().regexpCapture("(.*)_ele_query", 1) }

  Expr getMapArg() { result = this.getArgument(0) }

  Expr getKeyArg() { result = this.getArgument(1) }
}

private class MapRemoveCall extends FunctionCall {
  MapRemoveCall() {
    this.getTarget().getName().matches("%_ele_remove") or
    this.getTarget().getName().matches("%_idx_remove") or
    this.getTarget().getName().matches("%_ele_remove_fast")
  }

  string getMapName() {
    result = this.getTarget().getName().regexpCapture("(.*)_ele_remove", 1) or
    result = this.getTarget().getName().regexpCapture("(.*)_idx_remove", 1) or
    result = this.getTarget().getName().regexpCapture("(.*)_ele_remove_fast", 1)
  }

  predicate removes(MapQueryCall query, Variable ele) {
    this.getMapName() = query.getMapName() and
    this.getBasicBlock().getEnclosingFunction() = query.getBasicBlock().getEnclosingFunction() and
    sameExpr(this.getArgument(0), query.getMapArg()) and
    (
      (
        this.getTarget().getName().matches("%_ele_remove") or
        this.getTarget().getName().matches("%_idx_remove")
      ) and
      sameExpr(this.getArgument(1), query.getKeyArg())
      or
      this.getTarget().getName().matches("%_ele_remove_fast") and
      denotesVariable(this.getArgument(1), ele)
    )
  }
}

private predicate queryStoredIn(MapQueryCall query, Variable ele) {
  ele.getInitializer().getExpr() = query or
  exists(AssignExpr assign |
    assign.getRValue() = query and
    assign.getLValue().(VariableAccess).getTarget() = ele
  )
}

private predicate overwrittenBeforeUse(MapQueryCall query, Variable ele, ControlFlowNode use) {
  exists(AssignExpr assign |
    assign.getLValue().(VariableAccess).getTarget() = ele and
    assign.getRValue() != query and
    assign.getBasicBlock().getEnclosingFunction() = query.getBasicBlock().getEnclosingFunction() and
    dominates(query, assign) and
    dominates(assign, use)
  )
}

private predicate keyMutation(Variable ele, string key, FieldAccess access, ControlFlowNode mutation) {
  accessesKey(ele, key, access) and
  (
    exists(Assignment assign | assign.getLValue() = access and mutation = assign) or
    exists(CrementOperation crement | crement.getOperand() = access and mutation = crement)
  )
}

from MapQueryCall query, Variable ele, FieldAccess access, ControlFlowNode mutation, string key
where
  included(access.getLocation()) and
  included(query.getLocation()) and
  queryStoredIn(query, ele) and
  query.getBasicBlock().getEnclosingFunction() = mutation.getBasicBlock().getEnclosingFunction() and
  key = mapKey(query.getMapName()) and
  keyMutation(ele, key, access, mutation) and
  dominates(query, mutation) and
  not overwrittenBeforeUse(query, ele, mutation) and
  not exists(MapRemoveCall remove |
    remove.removes(query, ele) and
    dominates(remove, mutation)
  )
select access,
  "Map key '" + key + "' is mutated while the element may still be in " +
    query.getMapName() + "; remove it from the map first."
