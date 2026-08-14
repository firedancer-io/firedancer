/**
 * @name Mmap retval cmp
 * @description A call to mmap is not checked for failure.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/mmap-retval-cmp
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import filter

class MmapCall extends FunctionCall {
  MmapCall() { this.getTarget().hasGlobalName("mmap") }
}

private predicate isMapFailed(Expr e) {
  exists(UnaryMinusExpr minus |
    e.getAChild*() = minus and
    minus.getOperand().getValue().toInt() = 1
  )
}

private predicate sameValue(Expr a, Expr b) {
  globalValueNumber(a.getFullyConverted()) = globalValueNumber(b.getFullyConverted())
}

private predicate isMapFailedComparison(EqualityOperation cmp, Expr value) {
  /* -1 == MAP_FAILED */
  cmp.getLeftOperand() = value and isMapFailed(cmp.getRightOperand())
  or
  cmp.getRightOperand() = value and isMapFailed(cmp.getLeftOperand())
}

private predicate isMapFailedCheck(DataFlow::Node node) {
  exists(EqualityOperation cmp | isMapFailedComparison(cmp, node.asExpr()))
}

private predicate usesMapFixed(MmapCall call) {
  exists(MacroInvocation macro |
    macro.getMacro().getName() = "MAP_FIXED" and
    call.getArgument(3).getAChild*() = macro.getExpr()
  )
}

private predicate isFixedAddressCheck(MmapCall call, DataFlow::Node node) {
  usesMapFixed(call) and
  exists(EqualityOperation cmp |
    cmp.getLeftOperand() = node.asExpr() and
    sameValue(cmp.getRightOperand(), call.getArgument(0))
    or
    cmp.getRightOperand() = node.asExpr() and
    sameValue(cmp.getLeftOperand(), call.getArgument(0))
  )
}

private predicate isLocallyChecked(MmapCall call) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    source.asExpr() = call and
    DataFlow::localFlow(source, sink) and
    (isMapFailedCheck(sink) or isFixedAddressCheck(call, sink))
  )
}

private predicate isStoredFieldChecked(MmapCall call) {
  exists(Assignment assign, FieldAccess stored, FieldAccess checked, EqualityOperation cmp |
    assign.getRValue().getAChild*() = call and
    assign.getLValue() = stored and
    isMapFailedComparison(cmp, checked) and
    stored.getTarget() = checked.getTarget() and
    sameValue(stored.getQualifier(), checked.getQualifier()) and
    dominates(assign, cmp)
  )
}

predicate isChecked(MmapCall call) { isLocallyChecked(call) or isStoredFieldChecked(call) }

from MmapCall call
where
  included(call.getLocation()) and
  not isChecked(call)
select call, "This call to mmap is not checked for failure."
