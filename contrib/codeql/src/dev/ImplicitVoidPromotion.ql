/**
 * @name Implicit Void Ptr to Typed Ptr promotion
 * @description Implicit conversion from void* to a typed pointer
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id firedancer-io/implicit-void-promotion
 */

import cpp

class VoidPointer extends PointerType {
  VoidPointer() { this.getBaseType().getUnspecifiedType() instanceof VoidType }
}

predicate implicitVoidPromotion(Type lvalue, Type rvalue) {
  not lvalue.getUnderlyingType() instanceof VoidPointer and
  rvalue.getUnderlyingType() instanceof VoidPointer
}

predicate allowedSourceFile(File file) { file.getBaseName() != "fd_types.c" }

class BroadAssign extends Locatable {
  BroadAssign() { this instanceof Variable or this instanceof AssignExpr }

  Expr getRExpr() {
    result = this.(Variable).getInitializer().getExpr() or
    result = this.(AssignExpr).getRValue()
  }

  Type getLType() {
    result = this.(Variable).getType() or
    result = this.(AssignExpr).getLValue().getType()
  }

  Type getRType() { result = this.getRExpr().getType() }
}

from BroadAssign assign
where
  implicitVoidPromotion(assign.getLType(), assign.getRType()) and
  allowedSourceFile(assign.getLocation().getFile()) and
  not assign.getRExpr().isInMacroExpansion() and
  not assign.getRExpr().hasExplicitConversion() and
  not assign.getRExpr().(FunctionCall).getTarget().getName().matches("fd_type_pun%")
select assign, "Implicit conversion from void * to " + assign.getLType()
