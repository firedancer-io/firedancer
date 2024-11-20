/**
 * @name Bad check for overflow of integer addition
 * @description Checking for overflow of integer addition by comparing
 *              against one of the arguments of the addition does not work
 *              when the result of the addition is automatically promoted
 *              to a larger type.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision very-high
 * @id cpp/bad-addition-overflow-check
 * @tags reliability
 *       correctness
 *       security
 *       external/cwe/cwe-190
 *       external/cwe/cwe-192
 */

import cpp
import BadAdditionOverflowCheck
import filter

from RelationalOperation cmp, AddExpr a
where badAdditionOverflowCheck(cmp, a)
and included(cmp.getLocation())
select cmp, cmp.getFile().getRelativePath()
