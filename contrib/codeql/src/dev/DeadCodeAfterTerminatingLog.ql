/**
 * @name Dead code after terminating log
 * @description Finds code made unreachable by FD_LOG_ERR and the other
 *              terminating log macros.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/dead-code-after-terminating-log
 */

import cpp
import semmle.code.cpp.controlflow.ControlFlowGraph
import filter

private class TerminatingLog extends FunctionCall {
  TerminatingLog() { this.getTarget().hasGlobalName("fd_log_private_2") }
}

private class UnreachableBlock extends BasicBlock {
  UnreachableBlock() { this.isUnreachable() }
}

/**
 * Holds if `dead` is a first source-bearing block reachable after restoring an
 * edge that was present in the raw CFG after `log`, but removed from the
 * adapted CFG because `log` does not return. Requiring `dead` to remain
 * globally unreachable excludes code reached through another branch or goto.
 */
private predicate madeUnreachableBy(TerminatingLog log, UnreachableBlock dead) {
  log.getBasicBlock().isReachable() and
  exists(ControlFlowNode rawSuccessor |
    successors_extended(log, rawSuccessor) and
    not log.getASuccessor() = rawSuccessor and
    rawSuccessor.getBasicBlock().getASuccessor*() = dead and
    not exists(UnreachableBlock intermediate |
      rawSuccessor.getBasicBlock().getASuccessor*() = intermediate and
      intermediate.getASuccessor+() = dead and
      exists(firstSourceStatement(intermediate))
    )
  )
}

/** Gets the first source-written, non-empty statement in `block`. */
private Stmt firstSourceStatement(UnreachableBlock block) {
  exists(int position |
    result = block.getNode(position) and
    not result instanceof EmptyStmt and
    not result.isCompilerGenerated() and
    not result.isInMacroExpansion() and
    not exists(int earlierPosition, Stmt earlier |
      earlier = block.getNode(earlierPosition) and
      earlierPosition < position and
      not earlier instanceof EmptyStmt and
      not earlier.isCompilerGenerated() and
      not earlier.isInMacroExpansion()
    )
  )
}

from TerminatingLog log, UnreachableBlock dead, Stmt firstDead
where
  madeUnreachableBy(log, dead) and
  firstDead = firstSourceStatement(dead) and
  included(firstDead.getLocation())
select firstDead, "Code is unreachable because $@ does not return.", log, "this terminating log"
