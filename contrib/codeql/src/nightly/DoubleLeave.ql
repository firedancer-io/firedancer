/**
 * @name Double leave
 * @description Double leave: An object should be joined before being operated on in any way
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/double-leave
 * @tags correctness
 *       maintainability
 */

import cpp

import GenericDoubleFree
import semmle.code.cpp.dataflow.new.DataFlow
import Flow::PathGraph
import filter

bindingset[x]
string matchLeave(string x) {
      result = x.regexpCapture("(.*)_leave", 1)
}

bindingset[x]
string matchJoin(string x) {
      result = x.regexpCapture("(.*)_join", 1)
}


module Flow = DataFlow::GlobalWithState<DoubleFreeConfig<matchLeave/1, matchJoin/1>>;

from
  Flow::PathNode source, Flow::PathNode sink
where
  Flow::flowPath(source, sink)
  and source.getLocation().getStartLine() != sink.getLocation().getStartLine()
  and included(source.getLocation()) and included(sink.getLocation())
select sink.getNode(), source, sink, "double leave"