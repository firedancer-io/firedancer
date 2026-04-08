/**
 * @name Const/Pure violation
 * @description A function is attributed with const or pure, but accesses a pointer in an illegal way.
 * @id asymmetric-research/const-pure-violation
 * @kind problem
 * @precision high
 * @problem.severity warning
 */

import cpp
import filter

predicate isDref(Parameter p) {
  exists(Expr e | e = p.getAnAccess().getQualifier())
  or
  // not 100% accurate but code has to be very weird to trigger an FP
  exists(PointerDereferenceExpr e | p.getAnAccess() = e.getAChild*())
  or
  exists(ArrayExpr a | a.getArrayBase() = p.getAnAccess())
}

abstract class RestrictedFunc extends Function {
  Parameter getAPointerParam() {
    result = this.getAParameter() and
    result.getType().getPointerIndirectionLevel() > 0
  }

  predicate isViolated() { none() }
}

class ConstFunc extends RestrictedFunc {
  ConstFunc() { this.getAnAttribute().getName() = "const" }

  override predicate isViolated() { isDref(this.getAPointerParam()) }
}

class PureFunc extends RestrictedFunc {
  PureFunc() { this.getAnAttribute().getName() = "pure" }

  override predicate isViolated() {
    exists(Parameter p, VariableAccess a | p = this.getAPointerParam() |
      a = p.getAnAccess() and
      a.mayBeImpure()
    )
  }
}

from RestrictedFunc f
where f.isViolated() and
included(f.getLocation())
select f, "Function is attributed with " + f.getAnAttribute().getName() + ", but accesses a pointer in an illegal way."
