/**
 * @name No duplicate magic constant
 * @description One advantage of the magic constant is to avoid type confusions. To be as effective as possible, no two types should have the same magic constant.
 * @id asymmetric-research/no-duplicate-magic
 * @kind problem
 * @severity warning
 */

import cpp

class MagicConstant extends Macro {
  MagicConstant() {
    this.getName().matches("%MAGIC%")
    and this.getFile().getRelativePath().matches("src/%")
  }

  Expr getFullyConverted() {
    result = this.getAnInvocation().getExpr().getFullyConverted()
  }
}

from MagicConstant a, MagicConstant b
where
(a.getBody() = b.getBody() or a.getFullyConverted() = b.getFullyConverted())
and a.getName() > b.getName()
select a, "Has the same magic constant as " + b