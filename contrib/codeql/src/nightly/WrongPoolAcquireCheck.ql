/**
 * @name Checking for null after pool ele_acquire is dubious.
 * @description Pool ele_acquire functions never return null even when
 * the pool is exhausted. Therefore, checking their return value for null
 * indicates a misunderstanding and is likely a bug.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/fd-pool-ele-acquire-wrong-null-check
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import fdpool
import semmle.code.cpp.ir.IR
import semmle.code.cpp.controlflow.IRGuards

module AcquireToNullCheck implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(PoolAcquire pa | pa.isEleAcquire() | source.asExpr() = pa)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(IRGuardCondition g |
      g.comparesEq(sink.asInstruction().getAUse(),
        any(ConstantValueInstruction const | const.getValue() = "0").getAUse(), 0, false, _)
    )
  }
}

module Flow = DataFlow::Global<AcquireToNullCheck>;

import Flow::PathGraph

from Flow::PathNode sourceNode, Flow::PathNode sinkNode
where
  // only intra-procedural flow to reduce FPs
  sourceNode.getNode().getEnclosingCallable() = sinkNode.getNode().getEnclosingCallable() and
  Flow::flowPath(sourceNode, sinkNode)
select sinkNode, sourceNode, sinkNode,
  "Result of $@ cannot be null; checking it indicates a misunderstanding.", sourceNode,
  "pool ele_acquire"
