/**
 * @name Self Assignment
 * @description Detects assignments of a value to itself
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/self-assign
 */

import cpp
import semmle.code.cpp.valuenumbering.HashCons
import filter

from AssignExpr assign
where hashCons(assign.getLValue()) = hashCons(assign.getRValue())
/* FD_TXN_ERR_FOR_LOG_INSTR is an example of how a self assignment can
be a valid result of a macro expansion */
and not assign.isInMacroExpansion()
and included(assign.getLocation())
select assign, "Self Assignment"

