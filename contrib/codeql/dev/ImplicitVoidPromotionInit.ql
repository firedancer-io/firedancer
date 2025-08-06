/**
 * @name Implicit Void Ptr to Typed Ptr promotion in Initializer
 * @description Implicit conversion from void* to a typed pointer in variable initialization
 * @kind problem
 * @problem.severity recommendation
 * @precision low
 * @id firedancer-io/implicit-void-promotion-init
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

predicate voidPromotion(Type lvalue, Type rvalue, VoidPointer pt1, NotVoidPointer pt2) {
  lvalue.getUnderlyingType() = pt2 and
  rvalue.getUnderlyingType() = pt1
}

from Variable var, PointerType pt1, PointerType pt2
where
  voidPromotion(var.getType(), var.getInitializer().getExpr().getType(), pt1, pt2) and
  not var.getInitializer().getExpr().hasExplicitConversion() and
  not var.getInitializer().getExpr().isInMacroExpansion()
select var, "Implicit conversion from void * to " + pt2.getName()
