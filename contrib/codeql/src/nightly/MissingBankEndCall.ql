/**
 * @name Missing Bank End Call
 * @description Finds paths that end a locking operation on one return
 * path but not on another.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/missing-bank-end-call
 */

import cpp
import filter

bindingset[base]
predicate end(FunctionCall u, string base) {
  u.getTarget().hasName("fd_bank_" + base + "_end_locking_modify") or
  u.getTarget().hasName("fd_bank_" + base + "_end_locking_query")
}

string capTarget(FunctionCall f) {
  result =
    f.getTarget().getName().regexpCapture("fd_bank_((?!.*(?:^|_)end(?:_|$)).+?)_locking_.*", 1)
}

/*
 * required for primitive infinite type string (base) to be bound in
 *   forward and backward execution
 */

string genAll() { exists(FunctionCall f | result = capTarget(f)) }

ControlFlowNode nextNoUnlock(ControlFlowNode n, string base) {
  base = genAll() and
  not exists(FunctionCall u | end(u, base) and n = u) and
  (
    result = n.getASuccessor() and result instanceof ReturnStmt
    or
    result = nextNoUnlock(n.getASuccessor(), base)
  )
}

from FunctionCall l, string base, string op, string lock_name, ControlFlowNode r
where
  base = capTarget(l) and
  exists(FunctionCall u | end(u, base) and l.getASuccessor*() = u) and
  r = nextNoUnlock(l.getASuccessor(), base) and
  exists(FunctionCall g | g.getTarget().hasName(lock_name) | dominates(g, r)) and
  op = l.getTarget().getName().regexpCapture(".*_locking_(.*)", 1) and
  lock_name = "fd_bank_" + base + "_locking_" + op and
  included(l.getLocation())
select l, "missing " + "fd_bank_" + base + "_end_locking_" + op + " call"
