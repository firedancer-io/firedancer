/**
 * @name Call to a non const/pure function
 * @description Checks for known non-const/non-pure functions being
 * (transitively) called by a function that is marked as const or pure.
 * @id asymmetric-research/sure-call-to-non-const-pure
 * @kind problem
 * @precision very-high
 * @problem.severity warning
 */

import cpp
import filter

abstract class RFunc extends Function { }

class PureFunc extends RFunc {
  PureFunc() { this.getAnAttribute().getName() = "pure" }
}

class ConstFunc extends RFunc {
  ConstFunc() { this.getAnAttribute().getName() = "const" }
}

from RFunc r, Function f
where
  (
    /* for a nightly query, we only want known non-const/non-pure functions */
    f.hasName("fd_log_private_1") or
    f.hasName("fd_log_private_2") or
    f.hasName("fd_log_wallclock()")
  ) and r.calls*(f) and
  included(f.getLocation())
select r, f + " is called (transitively) by " + r + " which is marked as " + r.getAnAttribute().getName()
