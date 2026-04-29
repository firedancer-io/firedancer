/**
 * @name Maybe missing free before pool acquire
 * @description Detects calls to pool acquire functions that are not
 * preceded by a call to the corresponding free function on all paths
 * in that function.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id asymmetric-research/fd-pool-missing-free
 */

import cpp
import fdpool

from PoolAcquire acq
where
  not exists(PoolFree free | dominates(free, acq) and free.getPoolName() = acq.getPoolName()) and
  not acq.getLocation().getFile().getBaseName() = "fd_types.c"
select acq, acq.getPoolName()
