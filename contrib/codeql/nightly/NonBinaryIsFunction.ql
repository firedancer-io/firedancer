/**
 * @name Finds functions that suggest a boolean return type, but do not.
 * @description This query identifies functions that are named with the `is` prefix but return values outside
 *             the typical boolean range of 0 and 1.
 * @kind problem
 * @id asymmetric-research/non-binary-is-function
 * @precision medium
 * @severity warning
 * @tags correctness
 *       maintainability
 */

import cpp
import semmle.code.cpp.rangeanalysis.new.SimpleRangeAnalysis

/**
 * A function whose name suggests it returns a boolean value (0 or 1).
 */
class IsFunction extends Function {
  IsFunction() {
    this.getName().matches("%\\_is\\_%") and
    this.getType() instanceof IntegralType and
    not this.getName() = "fd_bn254_pairing_is_one_syscall"
    // returns values in [-1, 0]
  }
}

from IsFunction f, ReturnStmt rs, int lowerBound, int upperBound
where
  rs.getEnclosingFunction() = f and
  lowerBound = lowerBound(rs.getExpr().getFullyConverted()) and
  upperBound = upperBound(rs.getExpr().getFullyConverted()) and
  (
    lowerBound < 0 or
    upperBound > 1
  )
select rs,
  "The function $@ is named like an `is` function but returns a value with bounds [" + lowerBound +
    ", " + upperBound + "].", f, f.getName()
