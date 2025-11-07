/**
 * @name Mismatched Memset Size
 * @description The call to memset might be of incorrect size. Detects
 * cases memset(x, c, sizeof(t)) where typeof(x) != t.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/memset-size-mismatch
 */

import cpp

class MemsetFunction extends Function {
  MemsetFunction() {
    this.hasGlobalName("fd_memset")
    or
    this.hasGlobalOrStdOrBslName("memset")
    or
    this.hasGlobalName(["bzero", "__builtin_memset"])
  }

  int sizeIdx() {
    result = 1 and this.hasGlobalName("bzero")
    or
    result = 2 and not this.hasGlobalOrStdOrBslName("memset")
  }
}

from FunctionCall call, MemsetFunction memset, Type t
where
  not call.isInMacroExpansion() and
  call.getTarget() = memset and
  call.getArgument(memset.sizeIdx()) instanceof SizeofTypeOperator and
  t = call.getArgument(0).getUnspecifiedType().(DerivedType).getBaseType().getUnspecifiedType() and
  t != call.getArgument(memset.sizeIdx()).(SizeofTypeOperator).getTypeOperand().getUnspecifiedType() and
  not (t.hasName("char") or t.hasName("unsigned char") or t.hasName("void"))
select call, "The call to " + memset.getName() + " might be of incorrect size. The first argument is of type " + t.getName() + " but the size is taken from sizeof(" + call.getArgument(memset.sizeIdx()).(SizeofTypeOperator).getTypeOperand().getUnspecifiedType().getName() + ")."
