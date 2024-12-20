/**
 * @name Error discard
 * @description A function that returns an error code is called, but the return value is discarded.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id asymmetric-research/error-discard
 */

import cpp
import rettypes


class ErrFunction extends Function {
    ErrFunction() {
        exists(ConstantReturn ret | ret.getEnclosingFunction() = this)
    }
}


from FunctionCall errCall, Stmt callStmt
where
    errCall.getTarget() instanceof ErrFunction and
    errCall.getEnclosingStmt() = callStmt and
    not callStmt instanceof ReturnStmt and
    not callStmt.getAChild() instanceof Assignment and
    not callStmt instanceof DeclStmt and
    not callStmt instanceof Loop and
    not errCall.isInMacroExpansion() and
    not callStmt instanceof ConditionalStmt and
    not exists (Call c | c.getAChild() = errCall) and
    not errCall.getLocation().getFile().getBaseName().regexpMatch("(test|fuzz)_.*")
select errCall, errCall.getLocation()
