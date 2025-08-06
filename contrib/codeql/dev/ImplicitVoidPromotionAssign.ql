/**
 * @name Implicit Void Ptr to Typed Ptr promotion in Assignment
 * @description Implicit conversion from void* to a typed pointer in assignment expression
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id firedancer-io/implicit-void-promotion-assign
 */

import cpp

class VoidPointer extends PointerType {
  VoidPointer() {
    this.getBaseType().getUnspecifiedType() instanceof VoidType
  }
}

class NotVoidPointer extends PointerType {
  NotVoidPointer() {
    not this.getBaseType().getUnspecifiedType() instanceof VoidType
  }
}

predicate implicitVoidPromotion(Type lvalue, Type rvalue, VoidPointer pt1, NotVoidPointer pt2) {
  lvalue.getUnderlyingType() = pt2 and
  rvalue.getUnderlyingType() = pt1
}

predicate allowedSourceFile(File file) {
  file.getBaseName() != "fd_types.c"
}

from AssignExpr assign, PointerType pt1, PointerType pt2
where
  implicitVoidPromotion(assign.getLValue().getType(), assign.getRValue().getType(), pt1, pt2) and
  allowedSourceFile(assign.getLocation().getFile()) and
  not assign.getRValue().isInMacroExpansion()
select assign, "Implicit conversion from void * to " + pt2.getName()
