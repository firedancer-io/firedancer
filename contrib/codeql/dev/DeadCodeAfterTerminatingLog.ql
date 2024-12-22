/**
 * @name Dead code after terminating log
 * @description Code after a FD_LOG_ERR (and family)
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id asymmetric-research/dead-code-after-terminating-log
 */

import cpp

import semmle.code.cpp.controlflow.ControlFlowGraph
import semmle.code.cpp.controlflow.internal.ConstantExprs
import filter

class TerminatingLog extends FunctionCall {
    TerminatingLog() {
        this.getTarget().getName() = "fd_log_private_2"
    }
}

class UnreachableBlock extends BasicBlock {
    UnreachableBlock() {
        this.isUnreachable()
    }
}

predicate isProperBlock (BasicBlock bb) {
    exists(Stmt s | s.getBasicBlock() = bb and
                   not s instanceof EmptyStmt) and
    not (bb.getStart().getLocation().getStartLine() = bb.getEnd().getLocation().getEndLine() and
         bb.getEnd().getLocation().getEndColumn() - bb.getStart().getLocation().getStartColumn() <= 2)
}

predicate isAbove(FunctionCall inc, BasicBlock bb) {
    bb.getStart().getLocation().getStartLine() > inc.getLocation().getStartColumn() or
    bb.getStart().getLocation().getStartLine() = inc.getLocation().getStartLine() and
    bb.getStart().getLocation().getStartColumn() > inc.getLocation().getStartColumn()
}


from UnreachableBlock bb, TerminatingLog inc, Function f
where
    bb.getEnclosingFunction() = inc.getEnclosingFunction() and
    f = inc.getEnclosingFunction() and
    f.getBasicBlock() != bb and
    isAbove(inc, bb) and
    isProperBlock(bb) and
    inc.getBasicBlock().isReachable() and
    not exists( TerminatingLog incP | bb.contains(incP) )
select bb, "Dead code of length " + bb.length() + " after terminating log."
