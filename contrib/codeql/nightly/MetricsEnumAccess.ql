/**
 * @name Metrics Enum Access Issues
 * @id asymmetric-research/metrics-enum-access
 * @description Finds issues with FD_METRICS_ENUM_%_CNT and FD_METRICS_ENUM_%_IDX macros used for array accesses.
 * @kind problem
 * @severity warning
 * @precision high
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

bindingset[s]
int getValue(string s) { result = s.regexpCapture(".*?([0-9]+).*", 1).toInt() }

/**
 * Gets the 0-based dimension of the array access expression.
 * E.g., for `a[i]`, returns 0; for `a[i][j]`, returns 1.
 */
int getDimension(ArrayExpr e) {
  if e.getArrayBase() instanceof ArrayExpr
  then result = 1 + getDimension(e.getArrayBase().(ArrayExpr))
  else result = 0
}

/**
 * Gets the 1-based number of dimensions of the array type.
 * E.g., for `int a[3][4]`, returns 2.
 */
private int getNumArrayDimensions(ArrayType at) {
  if at.getBaseType() instanceof ArrayType
  then result = 1 + getNumArrayDimensions(at.getBaseType().(ArrayType))
  else result = 1
}

pragma[inline]
Literal nextLiteral(Element l) {
  min(Literal li |
    afterElement(l.getLocation(), li)
  |
    li order by li.getLocation().getStartLine(), li.getLocation().getStartColumn()
  ) = result
}

Literal nthLiteralAfterVariable(ArrayVariable v, int n) {
  (
    n = 0 and result = nextLiteral(v)
    or
    n > 0 and result = nextLiteral(nthLiteralAfterVariable(v, n - 1))
  ) and
  n < getNumArrayDimensions(v.getType())
}

/** Holds if `e` starts strictly after `f` textually. */
pragma[inline]
predicate afterElement(Location f, Element e) {
  e.getLocation().getFile() = f.getFile() and
  e.getLocation().getStartLine() >= f.getStartLine() and
  e.getLocation().getStartColumn() > f.getStartColumn()
}

/**
 * Matches macros of the form `FD_METRICS_TYPE_<TYPE>` where `<TYPE>` is a
 * string representing the metric type, e.g., `GAUGE`, `COUNTER`, etc.
 */
class FdMetricsTypeMacro extends Macro {
  FdMetricsTypeMacro() { this.getName().matches("FD_METRICS_TYPE_%") }

  string getType() { result = this.getName().regexpCapture("FD_METRICS_TYPE_(.*)", 1) }
}

/**
 * Matches macros of the form `FD_METRICS_<???>_CNT`.
 */
abstract class FdMetricsCountMacro extends Macro {
  /** Returns the enum name, iff this macro is associated with an enum. */
  abstract string getAnEnumName();
}

/**
 * Matches macros of the form `FD_METRICS_<TYPE>_<???>_CNT` where `<TYPE>` is from `FdMetricsTypeMacro` and does not include enums.
 * E.g., `FD_METRICS_COUNTER_<NAME>_CNT`, `FD_METRICS_GAUGE_<NAME>_CNT`, etc.
 */
class FdMetricsTypeCountMacro extends FdMetricsCountMacro {
  string type;
  string groupMeasurement;

  FdMetricsTypeCountMacro() {
    type =
      this.getName()
          .regexpCapture("FD_METRICS_(" + any(FdMetricsTypeMacro m).getType() + ").*_CNT", 1) and
    groupMeasurement = this.getName().regexpCapture("FD_METRICS_" + type + "_(.*)_CNT", 1)
  }

  override string getAnEnumName() {
    exists(FdDeclareMetricEnumInvocation inv |
      inv.getEnumName() = result and
      inv.getType() = type and
      inv.getGroupMeasurement() = groupMeasurement
    )
  }
}

/**
 * Matches macros of the form `FD_METRICS_ENUM_<ENUM_NAME>_CNT`.
 */
class FdMetricsEnumCountMacro extends FdMetricsCountMacro {
  FdMetricsEnumCountMacro() { this.getName().matches("FD_METRICS_ENUM_%_CNT") }

  override string getAnEnumName() {
    result = this.getName().regexpCapture("FD_METRICS_ENUM_(.*?)_CNT$", 1)
  }
}

/**
 * Matches macros of the form `FD_METRICS_ENUM_<ENUM_NAME>_IDX`
 */
class FdMetricsEnumIndexMacro extends Macro {
  FdMetricsEnumIndexMacro() { this.getName().matches("FD_METRICS_ENUM_%_IDX") }

  string getEnumName() { result = this.getName().regexpCapture("FD_METRICS_ENUM_(.*?)_V_.*$", 1) }

  FdMetricsEnumCountMacro asCnt() { result.getAnEnumName() = this.getEnumName() }
}

class FdDeclareMetricEnumMacro extends Macro {
  FdDeclareMetricEnumMacro() { this.hasName("DECLARE_METRIC_ENUM") }
}

/**
 * Matches invocations of the `DECLARE_METRIC_ENUM` macro.
 */
class FdDeclareMetricEnumInvocation extends MacroInvocation {
  FdDeclareMetricEnumInvocation() { this.getMacro() instanceof FdDeclareMetricEnumMacro }

  string getGroupMeasurement() { result = this.getUnexpandedArgument(0) }

  string getType() { result = this.getUnexpandedArgument(1) }

  string getEnumName() { result = this.getUnexpandedArgument(2) }
}

/**
 * Matches variable declarations of array type.
 */
class ArrayVariable extends Variable {
  ArrayVariable() { this.getType() instanceof ArrayType }
}

/**
 * Matches variable declarations of array type used in metrics.
 */
class MetricsArray extends ArrayVariable {
  FdMetricsCountMacro macro;

  MetricsArray() {
    // there is no direct way to get the macro used in the array size expression,
    // so we look for the dimension-th literal after the field declaration...
    // and check if that literal is the argument to a macro invocation of the right kind
    // this would break if one dimension is defined using something other than a literal,
    // for example, `2 * 2` ...
    nthLiteralAfterVariable(this, _) = macro.getAnInvocation().getExpr()
  }

  ArrayExpr getAUsage(int dimension) {
    this.getAnAccess() = result.getArrayBase*() and dimension = getDimension(result)
  }

  FdMetricsCountMacro getMacro(int dimension) {
    nthLiteralAfterVariable(this, dimension) = result.getAnInvocation().getExpr()
  }
}

/**
 * Matches array expressions that use `FD_METRICS_ENUM_<METRIC>_IDX` macros as their index or
 * where the index is bounded by a `FD_METRICS_<???>_CNT` macro.
 */
class MetricsEnumAccess extends ArrayExpr {
  FdMetricsCountMacro macro;

  MetricsEnumAccess() {
    (
      exists(FdMetricsEnumIndexMacro idxMacro |
        this.getArrayOffset() = idxMacro.getAnInvocation().getExpr() and
        macro = idxMacro.asCnt()
      )
      or
      exists(LTExpr ltExpr | ltExpr.getRightOperand() = macro.getAnInvocation().getExpr() |
        DataFlow::localExprFlow(ltExpr.getLeftOperand(), this.getArrayOffset())
      )
    )
  }

  FdMetricsCountMacro getMacro() { result = macro }
}

/**
 * Holds if the CNT value associated with the index in `a` does not match the array size
 * of the array being accessed.
 */
predicate isMismatchedCount(MetricsEnumAccess a) {
  getValue(a.getMacro().getBody()) != a.getArrayBase().getType().(ArrayType).getArraySize()
}

/**
 * Holds if the index used in `a` (which is either an IDX macro or a value bounded by a CNT macro)
 * is out of bounds for the array being accessed.
 */
predicate isArrayAccessOob(ArrayExpr access) {
  exists(MetricsArray e, int dimension, int enumArraySize, int arrayIndex |
    dimension = getDimension(access) and
    getValue(access.getArrayOffset().getValue()) = arrayIndex and
    getValue(e.getMacro(dimension).getBody()) = enumArraySize and
    e.getAUsage(dimension) = access and
    enumArraySize <= arrayIndex
  )
}

/**
 * Holds if the index used in `a` (which is either an IDX macro or a value bounded by a CNT macro)
 * does not match any metric array definition's associated enum name (if any).
 * E.g., if `a` uses `FD_METRICS_ENUM_FOO_IDX`, but the array size is defined using
 * the literal `9` (instead of `FD_METRICS_ENUM_FOO_CNT`), then this predicate holds.
 */
predicate isMismatchedEnumName(MetricsEnumAccess a) {
  exists(int dimension | dimension = getDimension(a) |
    not exists(MetricsArray e |
      e.getAUsage(dimension) = a and
      e.getMacro(dimension).getAnEnumName() = a.getMacro().getAnEnumName()
    )
  )
}

from ArrayExpr access, string des
where
  isArrayAccessOob(access) and
  des =
    "The IDX value (" + access.getArrayOffset().getValue() + ") is greater than the arrays size (" +
      access.getArrayBase().getType().(ArrayType).getArraySize() + ")."
  or
  isMismatchedCount(access) and
  des =
    "The CNT value (" + access.(MetricsEnumAccess).getMacro().getBody() +
      ") associated with the IDX macro and the array size (" +
      access.getArrayBase().getType().(ArrayType).getArraySize() +
      ") do not match and could result in under/over reads/writes."
  or
  isMismatchedEnumName(access) and
  des =
    "The enum name in the IDX macro does not match the one associated with the CNT macro (if any) in the array definition."
select access, des
