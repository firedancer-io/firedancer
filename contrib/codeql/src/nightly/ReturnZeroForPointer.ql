/**
 * @name Return 0 instead of NULL for pointer type
 * @description Returning the integer literal 0 instead of NULL for a
 *              pointer-typed return value. Use NULL to make intent clear.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/return-zero-for-pointer
 * @tags readability
 *       correctness
 *       style
 */

import cpp
import filter

from ReturnStmt ret, Function f, Literal lit
where
  ret.getEnclosingFunction() = f and
  ret.getExpr() = lit and
  f.getType().getUnspecifiedType() instanceof PointerType and
  lit.getValue() = "0" and
  not lit.isInMacroExpansion() and
  included(ret.getLocation())
select ret, "Function $@ returns 0 instead of NULL for pointer return type.", f, f.getName()
