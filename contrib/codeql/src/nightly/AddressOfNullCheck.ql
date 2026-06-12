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
module MustFlowConfig implements MustFlow::ConfigSig {
  predicate isSource(Instruction source) {
    source.getUnconvertedResultExpression() instanceof ValidAddressOfExpr
  }

  predicate isSink(Operand sink) { isNullOrNonNullCheck(sink) }

  predicate allowInterproceduralFlow() { none() }
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

module Flow = MustFlow::Global<MustFlowConfig>;

from Flow::PathNode source, Flow::PathNode sink
where
  Flow::flowPath(source, sink) and
  not source.getInstruction().getUnconvertedResultExpression().isInMacroExpansion() and
  source.getInstruction().getEnclosingFunction() = sink.getInstruction().getEnclosingFunction()
select sink, "Taking the address of $@ always produces a non-NULL pointer, but it is checked $@.",
  source.getInstruction().getUnconvertedResultExpression().(ValidAddressOfExpr).getOperand(),
  "this operand", sink, "here"
