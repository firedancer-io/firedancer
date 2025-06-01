/**
 * @name Call to `memcpy` could be an assignment instead
 * @description Instead of using the `memcpy` function to copy a value
                between two pointers, an assignment statement could be
                used instead. `memcpy` is more susceptible to bugs due
                to weaker typing.
 * @kind problem
 * @id firedancer-io/trivial-memcpy
 * @problem.severity none
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

from FunctionCall call, MemcpyFunction memcpy
where
  included(call.getLocation()) and
  not call.isInMacroExpansion() and
  call.getTarget() = memcpy and
  call.getArgument(2) instanceof SizeofTypeOperator and
  call.getArgument(0).getUnspecifiedType() = call.getArgument(1).getUnspecifiedType() and
  call.getArgument(0).getUnspecifiedType().(DerivedType).getBaseType().getUnspecifiedType() = call.getArgument(2).(SizeofTypeOperator).getTypeOperand().getUnspecifiedType()
select call, "Call to " + memcpy.getName() + " could be rewritten as an assignment."
