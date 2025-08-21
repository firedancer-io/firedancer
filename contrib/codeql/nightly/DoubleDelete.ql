/**
 * @name Double delete
 * @description Double delete: not all _delete functions are idempotent currently.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/double-delete
 * @tags correctness
 *       maintainability
 */

import cpp

import GenericDoubleFree
import semmle.code.cpp.dataflow.new.DataFlow
import Flow::PathGraph
import filter

bindingset[x]
string matchDelete(string x) {
      result = x.regexpCapture("(.*)_delete", 1)
      and not x = "fd_aio_delete" /* nbridge wants this to behave idempotently */
}

bindingset[x]
string matchNew(string x) {
      result = x.regexpCapture("(.*)_new", 1)
}


module Flow = DataFlow::GlobalWithState<DoubleFreeConfig<matchDelete/1, matchNew/1>>;

from
  Flow::PathNode source, Flow::PathNode sink
where
  Flow::flowPath(source, sink)
  and source.getLocation().getStartLine() != sink.getLocation().getStartLine()
  and not source.getLocation().getFile().getBaseName().matches("test%")
  and included(source.getLocation()) and included(sink.getLocation())
select sink.getNode(), source, sink, "double delete"