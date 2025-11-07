/**
 * @name `memcpy` size argument probably wrong
 * @description The memcpy size argument is a sizeof(type_t) parameter,
                and dst and src are pointers to types, but the sizes
                of the types referred to by the arguments differ.
                Consider using an assignment expression instead.
 * @kind problem
 * @id firedancer-io/trivial-memcpy-wrong
 * @problem.severity error
 * @precision medium
 * @tags correctness
 */

import cpp

class MemcpyFunction extends Function {
  MemcpyFunction() {
    this.hasGlobalOrStdName("memcpy")
    or
    this.hasGlobalName(["fd_memcpy", "__builtin_memcpy"])
  }
}

class NotVoidChar extends Type {
  NotVoidChar() {
    not this instanceof CharType and
    not this instanceof VoidType
  }
}

from FunctionCall call, MemcpyFunction memcpy, NotVoidChar t1, NotVoidChar t2
where
  not call.isInMacroExpansion() and
  call.getTarget() = memcpy and
  call.getArgument(2) instanceof SizeofTypeOperator and
  call.getArgument(0).getUnspecifiedType().(PointerType).getBaseType() = t1 and
  call.getArgument(1).getUnspecifiedType().(PointerType).getBaseType() = t2 and
  (
    call.getArgument(0).getUnspecifiedType().(PointerType).getBaseType().getSize() != call.getArgument(1).getUnspecifiedType().(DerivedType).getBaseType().getSize() or
    call.getArgument(0).getUnspecifiedType().(PointerType).getBaseType().getSize() != call.getArgument(2).(SizeofTypeOperator).getTypeOperand().getUnspecifiedType().getSize()
  )
select call, "Call to " + memcpy.getName() + " probably has wrong size argument (" +
  "sizeof(dst)=" + call.getArgument(0).getUnspecifiedType().(PointerType).getBaseType().getSize() +
  ", sizeof(src)=" + call.getArgument(1).getUnspecifiedType().(PointerType).getBaseType().getSize() +
  ", sz=" + call.getArgument(2).(SizeofTypeOperator).getTypeOperand().getUnspecifiedType().getSize()
  + ")."
