/**
 * @name Checks for suspicious joins
 * @description This query checks for calls to `fd_*_join` where the argument does not match the expected type.
 * @precision high
 * @kind problem
 * @tags security, correctness
 * @id asymmetric-research/join-check
 * @problem.severity warning
 */

import cpp

class FdJoinCall extends Call {
  FdJoinCall() {
    this.getTarget().getName().matches("fd_%_join") and
    this.getTarget().getParameter(0).getType().(PointerType).getBaseType() instanceof VoidType and
    not this.getType() instanceof VoidType
  }
}

predicate isCompatible(DerivedType t, DerivedType expected) {
  t.getBaseType() = expected.getBaseType()
}

class RelevantType extends Type {
  RelevantType() {
    not this.(DerivedType).getBaseType() instanceof VoidType and
    not this.(DerivedType).getBaseType() instanceof CharType and
    not this instanceof IntegralType
  }
}

from FdJoinCall call, Expr arg, Type t, Type expectedType
where
  arg = call.getArgument(0) and
  t = arg.getType() and
  expectedType = call.getType() and
  not isCompatible(t, expectedType) and
  t.getUnspecifiedType() instanceof RelevantType
select call, "The $@ to $@ has type $@, but the parameter type is $@.", arg, "argument", call,
  call.toString(), t, t.toString(), expectedType, expectedType.toString()
