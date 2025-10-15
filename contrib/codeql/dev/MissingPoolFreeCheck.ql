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

class PoolAcquire extends FunctionCall {
  PoolAcquire() {
    (this.getTarget().getName().matches("%_idx_acquire") or this.getTarget().getName().matches("%_ele_acquire")) and
    this.getTarget().getLocation().getFile().getBaseName().matches("fd_pool.c") and
    not this.getLocation().getFile().getAbsolutePath().matches("%/tmpl/%")
  }
  string getPoolName() {
      result = this.getTarget().getName().replaceAll("_idx_acquire", "").replaceAll("_ele_acquire", "")
  }
}


class PoolFree extends FunctionCall {
  PoolFree() {
    (this.getTarget().getName().matches("%_free") or this.getTarget().getName().matches("%_used")) and
    this.getTarget().getLocation().getFile().getBaseName().matches("fd_pool.c") and
    not this.getLocation().getFile().getAbsolutePath().matches("%/tmpl/%")
  }

  string getPoolName() {
    result = this.getTarget().getName().replaceAll("_free", "").replaceAll("_used", "")
  }
}


from PoolAcquire acq
where
not exists(PoolFree free | dominates(free, acq) and free.getPoolName() = acq.getPoolName()) and
not acq.getLocation().getFile().getBaseName() = "fd_types.c"
select acq, acq.getPoolName()
