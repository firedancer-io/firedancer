/**
* @name memory bounded custom printf check
* @description Check that custom constructed runtime logging format strings do not exceed their fixed size target buffers
* @kind problem
* @problem.severity warning
* @precision medium
* @id asymmetric-research/bounded-format-string
*/


import cpp

from FunctionCall fc, int bound, BufferWriteEstimationReason reason

where (
    fc.getTarget().getName() = "fd_log_collector_printf_dangerous_max_127" and
    bound = fc.(FormattingFunctionCall).getFormat().(FormatLiteral).getMaxConvertedLengthLimitedWithReason(reason) and
    bound - 1  > 127
)
or
(
    fc.getTarget().getName() = "fd_log_collector_printf_dangerous_128_to_2k" and
    bound = fc.(FormattingFunctionCall).getFormat().(FormatLiteral).getMaxConvertedLengthLimitedWithReason(reason) and
    bound - 1  < 127 and
    bound - 1  > 2000
)
or
(
    fc.getTarget().getName() = "fd_log_collector_printf_inefficient_max_512" and
    bound = fc.(FormattingFunctionCall).getFormat().(FormatLiteral).getMaxConvertedLengthLimitedWithReason(reason) and
    bound - 1  < 512
)
select fc, "After formatting this may have a size up to " + bound.toString() + " bytes, estimated by " + reason.toString()
