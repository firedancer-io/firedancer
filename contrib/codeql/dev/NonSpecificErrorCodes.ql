/**
 * Identifies functions that return a defined constant on one path and a literal number on another path.
 * It is not very precise and more of a hint during development.
 * One failure case is when a function either returns error constant or a size (e.g. of bytes read).
 * @id asymmetric-research/mixed-return-values
 * @precision low
 * @kind problem
 * @severity warning
 */
import cpp
import rettypes

from
    LiteralReturn ret1, MacroReturn ret2, Function func
where
    ret1.getEnclosingFunction() = func and
    ret2.getEnclosingFunction() = func
select func, "Mixed return values" /* ret1.getExpr(), ret2.getExpr() */
