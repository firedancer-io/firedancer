/**
 * As defence in depth for memory corruptions, we should always check and reset the magic field
 * in a _destroy function. This query finds all functions that *have* a magic field and *do not have*
 * a check for the magic field or a reset of the magic field.
 * @id asymmetric-research/no-magic-delete
 * @kind problem
 * @severity warning
 */

import cpp

class MagicAccess extends FieldAccess {
  MagicAccess() { this.getTarget().getName() = "magic" }
}

class MagicCmp extends ComparisonOperation {
  MagicCmp() { exists(MagicAccess ma |  this.getAnOperand().getAChild*() = ma) }
}

class MagicNulling extends Assignment {
  MagicNulling() { exists(MagicAccess ma | ma.getEnclosingStmt().getAChild*() = this) }
}


class CheckFunction extends Function {
  Field magicField;
  Type parentType;

  CheckFunction() {
    exists(int n | this.getParameter(n)
                       .getType() = parentType)
    and
    parentType.stripType()
               .(Struct)
               .getAField() = magicField and
    magicField.getName() = "magic"
    and this.getName().regexpCapture("(.*)_(delete|join)", 1) = parentType.getName().regexpCapture("(.*)_t \\*", 1)
  }

  predicate hasMagicCmp() {
    exists(MagicCmp cmp | cmp.getBasicBlock().getEnclosingFunction() = this)
  }

  predicate setsMagicNull() {
    exists(MagicNulling n | n.getBasicBlock().getEnclosingFunction() = this)
  }

  string getParentType() {
    result = parentType.getName()
  }

  predicate valid() {
    this.hasMagicCmp() and
    (this.setsMagicNull() or not this.getName().matches("%_delete"))
  }
}

from CheckFunction f
where not f.valid()
select f, "should check or null magic of " + f.getParentType()
