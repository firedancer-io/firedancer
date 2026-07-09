/**
 * @name Call to a non const/pure function
 * @description Checks for known non-const/non-pure functions being
 * (transitively) called by a function that is marked as const or pure.
 * @id asymmetric-research/maybe-call-to-non-const-pure
 * @kind problem
 * @precision low
 * @problem.severity warning
 */

import cpp
import ConstPure

abstract class ShouldBeFunc extends Function { }

class ShouldBePure extends ShouldBeFunc {
  Function off;

  ShouldBePure() {
    (
      off instanceof ConstOrPureFunction or
      off instanceof ShouldBeFunc
    ) and
    not this instanceof ConstOrPureFunction and
    this.getACallToThisFunction().getEnclosingFunction() = off and
    this.getLocation().getFile().getRelativePath().matches("src/%")
  }

  Function getOff() { result = off }
}

string directOrNot(Function off) {
  /* alternatively we could make this query a path-query */
  result = "is" and off instanceof ConstOrPureFunction
  or
  result = "is called by a" and off instanceof ShouldBeFunc
}

from ShouldBePure f, Function off
where off = f.getOff()
select off, f + " is called via " + off + " which " + directOrNot(off) + " const/pure function"
