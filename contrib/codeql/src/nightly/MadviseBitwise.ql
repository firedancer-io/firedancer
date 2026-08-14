/**
 * @name The `advice` argument of madvise doesn't accept bitwise arguments.
 * @description `madvise` accepts only one `MADV_...` value in the `advice` argument. If you want to pass multiple advises, you need to call `madvise` multiple times.
 * @kind problem
 * @problem.severity warning
 * @id asymmetric-research/madvise-wrong-bitwise
 * @tags reliability
 *       correctness
 */

import cpp
import filter

private class MadviseCall extends FunctionCall {
  MadviseCall() { this.getTarget().hasGlobalName("madvise") }

  Expr getAdviceArgument() { result = this.getArgument(2) }
}

from MadviseCall mc
where
  mc.getAdviceArgument() instanceof BinaryBitwiseOperation and
  included(mc.getLocation())
select mc, "The `advice` argument of madvise doesn't accept bitwise arguments."
