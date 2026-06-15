/**
 * @name Function allocates stack variable larger than 512KiB
 * @description Flags stack variables larger than 512KiB.
 * @kind problem
 * @id asymmetric-research/large-stack-variable
 * @problem.severity warning
 * @precision high
 * @tags reliability
 */

import cpp

from StackVariable sv
where sv.getType().getSize() > 512 * 1024
select sv, "Stack variable larger than 512KiB."
