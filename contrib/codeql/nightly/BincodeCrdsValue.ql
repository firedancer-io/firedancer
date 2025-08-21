/**
 * @name Bincode gossip value encoding
 * @description Whenever writing in msg->data and msg of type fd_value_elem, we want the buf
 *              to be only initialized by fd_crds_value_encode. Using other similar methods
 *              like fd_crds_data_encode is not allowed, and has led to a bug in the past:
 *              https://github.com/firedancer-io/firedancer/pull/3568
 * @precision high
 * @id asymmetric-research/bincode-crds-value
 * @kind path-problem
 * @tags security
 * @problem.severity warning
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import Flow::PathGraph
import filter

class CtxData extends FieldAccess {
  CtxData() {
    this.getTarget().getDeclaringType().getName() = "fd_bincode_encode_ctx" and
    this.getTarget().getName() = "data" and
    this.getAPredecessor()
        .getASuccessor*()
        .getEnclosingElement()
        .(FunctionCall)
        .getTarget()
        .getName() = "fd_crds_value_encode"
  }
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Any pointer that is assigned (or initialized, distinct in CodeQL)
    exists(AssignExpr ae | ae.getAChild() = source.asIndirectExpr()) or
    exists(Initializer ae | source.asIndirectVariable() = ae.getDeclaration())
  }

  /**
   * Fine, if initialized like this:
   * ```
   * ctx.data = buf;
   * ctx.dataend = buf + PACKET_DATA_SIZE;
   * if ( fd_crds_value_encode( &crd, &ctx ) ) {
   * ```
   */
  predicate isBarrier(DataFlow::Node node) {
    exists(CtxData cd | cd.getEnclosingStmt() = node.asIndirectExpr().getEnclosingStmt())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FieldAccess fa |
      fa.getTarget().getName() = "data" and
      fa.getTarget().getDeclaringType().getName() = "fd_value_elem" and
      fa = sink.asIndirectExpr()
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node fromNode, DataFlow::Node afterNode) {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "fd_memcpy" and
      fc.getArgument(1) = fromNode.asIndirectArgument(1) and
      fc.getArgument(0) = afterNode.asIndirectArgument(1)
    )
  }
}

module Flow = DataFlow::Global<Config>;

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink) and
included(source.getLocation()) and included(sink.getLocation())
select sink.getNode(), source, sink, "Only use fd_crds_value_encode to initialize fd_value_elem->data"
