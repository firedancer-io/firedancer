/**
 * Identifies functions that return a defined integer constant and compare it to a literal value at invocation.
 * @id asymmetric-research/macro-cmp-literal
 * @kind problem
 * @problem.severity warning
 * @tags maintainability
 *       readability
 */

import cpp
import filter
import rettypes

predicate callOriginated(Element e, FunctionCall call) {
    exists(Variable v | e = v and v.getAnAssignment().findRootCause() = call) or e = call
}

// TODO: use dataflow instead of findRootCause()
from
    Function func, FunctionCall call
where
    exists(MacroReturn ret | 
            exists(ComparisonOperation cmp | cmp.getAnOperand().findRootCause() instanceof Literal and
                callOriginated(cmp.getAnOperand().findRootCause(), call) and
                cmp.getOperator() = "==") and
            ret.getEnclosingFunction() = func and
            call.getTarget() = func) or
    exists(LiteralReturn ret |
        exists(ComparisonOperation cmp | cmp.getAnOperand().findRootCause() instanceof ConstantMacro and
                                         callOriginated(cmp.getAnOperand().findRootCause(), call) and
                                         cmp.getOperator() = "==") and
        ret.getEnclosingFunction() = func and
        call.getTarget() = func
        )
/* don't print the invocation location, to avoid multiple results for the same finding
   problem mostly occurs at the return statement of the function. */
select
    func, func + " returns a constant value and compares it to a literal at invocation"

