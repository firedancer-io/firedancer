/**
 * @name Metrics Enum Access Issues
 * @id asymmetric-research/metrics-enum-access
 * @description Finds issues with FD_METRICS_ENUM_%_CNT and FD_METRICS_ENUM_%_IDX macros used for array accesses.
 * @kind problem
 * @severity warning
 * @precision high
 */

import cpp
import fd_metrics

from ArrayExpr access, string des
where
  isArrayAccessOob(access) and
  des =
    "The IDX value (" + access.getArrayOffset().getValue() + ") is greater than the arrays size (" +
      access.getArrayBase().getType().(ArrayType).getArraySize() + ")."
  or
  isMismatchedCount(access) and
  des =
    "The CNT value (" + access.(MetricsEnumAccess).getMacro().getBody() +
      ") associated with the IDX macro and the array size (" +
      access.getArrayBase().getType().(ArrayType).getArraySize() +
      ") do not match and could result in under/over reads/writes."
  or
  isMismatchedEnumName(access) and
  des =
    "The enum name in the IDX macro does not match the one associated with the CNT macro in the array definition."
select access, des
