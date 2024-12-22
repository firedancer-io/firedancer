/**
 * @name Const/Pure violation
 * @description A function is declared as const or pure, but access a pointer in a illegal way.
 * @id asymmetric-research/const-pure-violation
 * @kind problem
 * @precision medium
 * @problem.severity warning
 */

import cpp

predicate isDref(Parameter p) {
  exists(Expr e | e = p.getAnAccess().getQualifier())
  or
  // not 100% accurate but code has to be very weird to tigger an fp
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
where f.isViolated()
select f, "Function declared as " + f.getAnAttribute().getName() + " but access a pointer in a illegal way."
