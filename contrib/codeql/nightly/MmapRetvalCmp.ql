/**
 * @name Mmap retval cmp
 * @description A call to mmap is not checked for failure.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/mmap-retval-cmp
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

import Flow::PathGraph


module Config implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(Variable v |
        v.getAnAssignedValue() = source.asExpr()
        and source.asExpr().(FunctionCall).getTarget().getName() = "mmap"
    )
  }

  /* -1 == MAP_FAILED */

  predicate isSink(DataFlow::Node sink) {
    exists(ComparisonOperation cmp |
        cmp.getLeftOperand() = sink.asExpr() and cmp.getRightOperand().getValue().toInt() = -1
        or
        cmp.getRightOperand() = sink.asExpr() and cmp.getLeftOperand().getValue().toInt() = -1
    )
  }
}

module Flow = DataFlow::Global<Config>;

from
  Flow::PathNode source, Flow::PathNode sink
where
  not Flow::flowPath(source, sink)
select source.getNode(), source, sink, "A call to mmap is not checked for failure."