/**
 * @name Call to `memcpy` could be an assignment instead
 * @description Instead of using the `memcpy` function to copy a value
                between two pointers, an assignment statement could be
                used instead. `memcpy` is more susceptible to bugs due
                to weaker typing.
 * @kind problem
 * @id firedancer-io/trivial-memcpy
 * @problem.severity recommendation
 * @precision high
 * @tags maintainability
 *       readability
 */

import cpp
import filter

class MemcpyFunction extends Function {
  MemcpyFunction() {
    this.hasGlobalOrStdName("memcpy")
    or
    this.hasGlobalName(["fd_memcpy", "__builtin_memcpy"])
  }
}

predicate ignoredLocation(Location l) {
  // we don't want to change vendored code if not really necessary
  l.getFile().getBaseName() = "cJSON.c"
}

class InScopeType extends Type {
  InScopeType() {
    not this instanceof CharType and
    not this instanceof VoidType and
    not this.getUnspecifiedType().(DerivedType).getBaseType().getUnspecifiedType().hasName(["fd_txn_p", "fd_hash"])
  }
}

from FunctionCall call, MemcpyFunction memcpy, InScopeType t
where
  included(call.getLocation()) and
  not call.isInMacroExpansion() and
  not ignoredLocation(call.getLocation()) and
  call.getTarget() = memcpy and
  call.getArgument(2) instanceof SizeofTypeOperator and
  t = call.getArgument(0).getUnspecifiedType() and
  t = call.getArgument(1).getUnspecifiedType() and
  t.(DerivedType).getBaseType().getUnspecifiedType() = call.getArgument(2).(SizeofTypeOperator).getTypeOperand().getUnspecifiedType()
select call, "Call to " + memcpy.getName() + " could be rewritten as an assignment." + t.getUnderlyingType()
