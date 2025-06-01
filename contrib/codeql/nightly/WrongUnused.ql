/**
 * @name Used parameter marked as unused
 * @description A parameter is marked as unused, but is actually used.
 * @id asymmetric-research/used-unused-param
 * @kind problem
 * @precision high
 * @problem.severity none
 */

import cpp
import filter

predicate isVoidCast(VariableAccess va) {
    va.getFullyConverted().(Cast).getType().getName() = "void" and
    not va.isInMacroExpansion()
}

abstract class MarkedUnusedParam extends Parameter {
    predicate isOffending() {
        exists(VariableAccess va |
            va = this.getAnAccess() and
            not isVoidCast(va)
            and not va.isInMacroExpansion()
        )
    }
}

class AnnotatedUnusedParam extends MarkedUnusedParam {
    AnnotatedUnusedParam() {
        this.getAnAttribute().getName() = "unused"
    }
}

class VoidCastUnusedParam extends MarkedUnusedParam {
    VoidCastUnusedParam() {
        exists(VariableAccess va |
            va = this.getAnAccess() and
            isVoidCast(va) and
            not exists(Expr expr |
                expr.getASuccessor*() = va
                and expr.getFullyConverted().(Cast).getType().getName() != "void"
            ) and
            not va.isInMacroExpansion()
        )
    }
}


from MarkedUnusedParam p
where p.isOffending() and
not p.isInMacroExpansion() and
included(p.getLocation()) and
not p.getLocation().getFile().getBaseName() = "fd_rpc_service.c" /* lots of unimplmented stubs */
select p.getLocation(), "Parameter is marked as unused, but is actually used"
