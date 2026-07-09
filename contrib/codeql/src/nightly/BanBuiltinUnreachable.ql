/**
 * @name Ban usage of `__builtin_unreachable`
 * @description Do not use `__builtin_unreachable`. Use `FD_LOG_CRIT` or another appropriate error path instead.
 * @kind problem
 * @id asymmetric-research/ban-builtin-unreachable
 * @tags maintainability
 * @precision high
 * @severity warning
 */

import cpp
import filter

from FunctionCall fc
where fc.getTarget().getName() = "__builtin_unreachable"
  and included(fc.getLocation())
select fc,
  "Usage of `__builtin_unreachable` is not allowed. Use `FD_LOG_CRIT` or another appropriate error path instead."
