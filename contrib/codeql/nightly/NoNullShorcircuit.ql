/**
 * @name Null no short-circuit
 * @description A potential null pointer is checked than accessed without short-circuiting.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/null-no-shortcircuit
 */

import cpp
import filter

from BinaryBitwiseOperation op, Expr lhs, PointerFieldAccess rhs
where
op.getLeftOperand() = lhs and
op.getRightOperand() = rhs and
rhs.getTarget().getDeclaringType() = lhs.getType() and
included(op.getLocation())
select lhs, "Potential null pointer is checked than accessed without short-circuiting."