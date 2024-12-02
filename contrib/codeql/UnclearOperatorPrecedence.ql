/**
 * Lists all binary bitwise operations that are not parenthesised and have a comparison operation as the other operand.
 * @id asymmetric-research/comparison-bitwise-precedence
 * @kind problem
 * @severity warning
 * @precision high
 */

import cpp

from BinaryBitwiseOperation bit, ComparisonOperation rel, Expr other
where
    bit.hasOperands(rel, other) and
    not rel.isParenthesised()
select rel, "Operator precedence and paranthese hint at a likely issue"

