/**
 * @name Suspicious comparison between index-based expressions and max-sized expressions
 * @description Comparisons between index-based expressions and max-sized expressions can lead to off-by-one errors.
 * For example, `idx <= MAX_LENGTH` is suspicious because `idx` can be equal to `MAX_LENGTH`, which is often out of bounds.
 * Indexes are assumed to be zero-based, while max sizes are usually one-based.
 * @tags security
 * @kind problem
 * @id asymmetric-research/suspicious-index-max-comparison
 * @severity warning
 * @precision medium
 */

import cpp

/**
 * A base class for expressions that can be identified by their name.
 * This includes variable accesses, function calls, and macro invocations.
 */
class NamedExpr extends Expr {
  NamedExpr() {
    this instanceof VariableAccess or
    this instanceof Call or
    exists(MacroInvocation mi | mi.getExpr() = this)
  }

  string getName() {
    result = this.(VariableAccess).getTarget().getName()
    or
    result = this.(Call).getTarget().getName()
    or
    exists(MacroInvocation mi |
      mi.getMacro().getName() = result and
      mi.getExpr() = this
    )
  }
}

private string getIndexPattern() {
  result = "%IDX%" or
  result = "%idx%" or
  result = "%index%" or
  // Matches common variable names like i, j, k, l, m, n
  result = "abcdefghijklmnopqrstuvwxyz".charAt(_)
}

class IdxBasedExpr extends NamedExpr {
  IdxBasedExpr() { this.getName().matches(getIndexPattern()) }
}

private string getMaxPattern() {
  result = "%MAX%" or
  result = "%max%" or
  result = "%SIZE%" or
  result = "%size%" or
  result = "%LENGTH%" or
  result = "%length%"
}

class MaxBasedExpr extends NamedExpr {
  MaxBasedExpr() {
    this.getName().matches(getMaxPattern()) and not this.getName().matches("max_idx%")
  }
}

predicate wrongComparison(RelationalOperation ro, IdxBasedExpr ibe, MaxBasedExpr mbe) {
  // int foo[MAX_SIZE];
  // foo_idx <= MAX_SIZE  // suspicious, should be < instead of <=
  ro.getOperator() = "<=" and
  ro.getLeftOperand() = ibe and
  ro.getRightOperand() = mbe
  or
  // foo_idx > MAX_SIZE  // suspicious, should be >= instead of >
  ro.getOperator() = ">" and
  ro.getLeftOperand() = ibe and
  ro.getRightOperand() = mbe
  or
  // MAX_SIZE >= foo_idx  // suspicious, should be > instead of >=
  ro.getOperator() = ">=" and
  ro.getLeftOperand() = mbe and
  ro.getRightOperand() = ibe
  or
  // MAX_SIZE < foo_idx  // suspicious, should be <= instead of <
  ro.getOperator() = "<" and
  ro.getLeftOperand() = mbe and
  ro.getRightOperand() = ibe
}

from IdxBasedExpr ibe, MaxBasedExpr mbe, RelationalOperation ro
where wrongComparison(ro, ibe, mbe)
select ro,
  "The comparison between this $@ and $@ can be wrong if the index is assumed to be in the range [0, "
    + mbe + ").", ibe, "index-based expression", mbe, "max-sized expression"
