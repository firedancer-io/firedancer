/**
 * @name Account meta deref before modify
 * @description Dereferencing a borrowed account's metadata before modifying it is not allowed.
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/account-meta-deref-before-modify
 */


import cpp
import semmle.code.cpp.dataflow.new.DataFlow

import Flow::PathGraph

/**
 * It is hard to track the flow if indexing is used for barrier checks.
 * This class tries to find such barriers and works well on the current codebase.
 * Using calculations or constants for indexing could lead to false positives.
 */
class WritableCheck extends FunctionCall {
  WritableCheck() {
    this.getTarget().hasName("fd_txn_account_is_writable_idx")
  }

  VariableAccess getAcc() {
    exists(Variable v, ArrayExpr ae, VariableAccess ve |
      this.getArgument(1).getAChild*() = v.getAnAccess() and
      ve = v.getAnAccess() and
      (
        ae.getArrayOffset().getAChild*() = ve or
        exists(FunctionCall fc |
               fc.getTarget().getName() = "fd_instr_borrowed_account_view_idx" and
               fc.getArgument(1).getAChild*() = ve)
      ) and
      result = ve
    )
  }
}

module Config implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(Call call |
      call.getTarget().hasName("fd_borrowed_account_init") and
      source.asIndirectArgument() = call.getArgument(0)
    )
  }

  predicate isBarrier(DataFlow::Node barrier) {
    exists(Call call |
      (call.getTarget().hasName("fd_acc_mgr_modify") and
       barrier.asIndirectArgument() = call.getArgument(5)) or
      (call.getTarget().hasName("fd_borrowed_account_make_modifiable") and
       barrier.asIndirectArgument() = call.getArgument(0))
    )
    // The fee payer acc is special and is checked elsewhere
    or barrier.toString().matches("%fee_payer%")
    or exists(WritableCheck wc | wc.getAcc() = barrier.asIndirectExpr().getAChild*())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(
      FieldAccess fa |
      fa.getAChild() = sink.asIndirectExpr(1) and
      fa.getTarget().getName() = "meta" and
      exists(FieldAccess ma | ma.getAChild().toString() = "meta" and ma.getEnclosingStmt() = fa.getEnclosingStmt())
    )
  }
}

module Flow = DataFlow::Global<Config>;

from
  Flow::PathNode source, Flow::PathNode sink
where
  Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "A borrowed account is dereferenced before being modified."