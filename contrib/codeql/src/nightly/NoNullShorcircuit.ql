/**
 * @name Null no short-circuit
 * @description A potential null pointer is checked than accessed without short-circuiting.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/null-no-shortcircuit
 */

import cpp
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import filter

private predicate samePointer(Expr a, Expr b) {
  globalValueNumber(a.getFullyConverted()) = globalValueNumber(b.getFullyConverted())
}

private predicate isNullPointerConstant(Expr e) {
  e.getValue() = "0" and
  e.getFullyConverted().getUnspecifiedType() instanceof PointerType
}

private predicate checksPointerForNull(Expr check, Expr pointer) {
  exists(EqualityOperation cmp |
    check = cmp and
    (
      cmp.getLeftOperand() = pointer and isNullPointerConstant(cmp.getRightOperand())
      or
      cmp.getRightOperand() = pointer and isNullPointerConstant(cmp.getLeftOperand())
    )
  )
  or
  exists(NotExpr negation |
    check = negation and
    pointer = negation.getOperand() and
    pointer.getFullyConverted().getUnspecifiedType() instanceof PointerType
  )
}

private predicate unsafeNullCheck(
  BinaryBitwiseOperation op, Expr check, Expr accessOperand, PointerFieldAccess access
) {
  (
    op.getLeftOperand() = check and op.getRightOperand() = accessOperand
    or
    op.getRightOperand() = check and op.getLeftOperand() = accessOperand
  ) and
  accessOperand.getAChild*() = access and
  exists(Expr pointer |
    checksPointerForNull(check, pointer) and
    samePointer(pointer, access.getQualifier())
  )
}

from BinaryBitwiseOperation op, Expr check, Expr accessOperand, PointerFieldAccess access
where
  unsafeNullCheck(op, check, accessOperand, access) and
  included(op.getLocation())
select op, "A pointer is checked for null but dereferenced by a non-short-circuiting operation."
