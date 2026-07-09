/**
 * @name Ban usage of `explicit_bzero` and `memset_explicit`
 * @description Do not use `explicit_bzero` or `memset_explicit` but instead use `fd_memzero_explicit`.
 * @kind problem
 * @id asymmetric-research/ban-explicit-bzero
 * @tags maintainability
 * @precision high
 * @severity warning
 */

import cpp
import filter

from FunctionCall fc
where fc.getTarget().getName() = ["explicit_bzero", "memset_explicit"]
  and included(fc.getLocation())
select fc,
  "Usage of `" + fc.getTarget().getName() + "` is not allowed. Use `fd_memzero_explicit` instead."
