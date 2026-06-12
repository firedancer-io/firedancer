/**
 * @name Suspicious/useless `memcpy(foo, foo, ...)` call.
 * @description `memcpy` is called with the same source and destination pointer.
 *                This is likely a bug or at best useless code.
 * @kind problem
 * @id asymmetric-research/useless-memcpy
 * @problem.severity warning
 * @precision high
 * @tags correctness
 */

import cpp
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import fd_memcpy

predicate isSamePointer(Expr e1, Expr e2) { globalValueNumber(e1) = globalValueNumber(e2) }

from MemcpyFunction memcpy, FunctionCall call
where
  call.getTarget() = memcpy and
  isSamePointer(call.getArgument(0), call.getArgument(1))
select call,
  "Call to " + memcpy.getName() +
    " has the same source and destination. This is likely a bug or useless code."
