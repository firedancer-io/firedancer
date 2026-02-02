/**
 * @name Suspicious check on address-of expression
 * @description Taking the address of a valid object always produces a non-NULL
 *              pointer, so checking the result against NULL is either redundant
 *              or indicates a bug where a different check was intended.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/suspicious-address-of-null-check
 * @tags reliability
 *       correctness
 *       readability
 */

import cpp
import semmle.code.cpp.ir.dataflow.MustFlow
import semmle.code.cpp.controlflow.Guards

/**
 * Models flows from address-of expressions to NULL/non-NULL checks that
 * always hold.
 */
private class MustFlowConfig extends MustFlowConfiguration {
  MustFlowConfig() { this = "SuspiciousAddressOfNullCheckMustFlow" }

  override predicate isSource(Instruction source) {
    source.getUnconvertedResultExpression() instanceof ValidAddressOfExpr
  }

  override predicate isSink(Operand sink) { isNullOrNonNullCheck(sink) }

  override predicate allowInterproceduralFlow() { none() }

  override predicate isBarrier(Instruction instr) {
    // Temporary workaround for bug in the library where interprocedural flow
    // in recursive functions is not handled correctly.
    // Tracking issue: https://github.com/github/codeql/issues/21240
    instr instanceof InitializeParameterInstruction
  }
}

/**
 * Technically, we'd ignore cases where we do something like &foo->first_field (where foo is a pointer)
 * this is because if foo is NULL, the expression could actually evaluate to NULL.
 * However, it doesn't seem likely that anyone would write code like that intentionally
 * and it's also undefined behavior to dereference a NULL pointer anyway.
 */
class ValidAddressOfExpr extends AddressOfExpr { }

predicate isNullOrNonNullCheck(Operand operand) {
  any(IRGuardCondition gc).comparesEq(operand, 0, _, _)
}

from MustFlowPathNode source, MustFlowPathNode sink, MustFlowConfig cfg
where
  cfg.hasFlowPath(source, sink) and
  not source.getInstruction().getUnconvertedResultExpression().isInMacroExpansion() and
  source.getInstruction().getEnclosingFunction() = sink.getInstruction().getEnclosingFunction()
select sink, "Taking the address of $@ always produces a non-NULL pointer, but it is checked $@.",
  source.getInstruction().getUnconvertedResultExpression().(ValidAddressOfExpr).getOperand(),
  "this operand", sink, "here"
