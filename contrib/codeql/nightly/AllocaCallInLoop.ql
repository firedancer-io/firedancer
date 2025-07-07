/**
 * @name Alloca call in loop
 * @description We want to strictly forbid alloca in loops to avoid
 * stack overflows
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/alloca-in-loop
 */

import cpp

class AllocaCall extends FunctionCall {
  AllocaCall() {
    this.getTarget().hasName("fd_alloca") or
    this.getTarget().hasName("alloca") or
    this.getTarget().hasName("fd_alloca_check") or
    this.getTarget().hasName("__builtin_alloca")
  }
}

from Loop l, AllocaCall c
where c.getAPredecessor*() = l
select c, "Call to alloca in loop"
