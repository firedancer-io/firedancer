import cpp

class PoolAcquire extends FunctionCall {
  PoolAcquire() {
    (
      this.getTarget().getName().matches("%_idx_acquire") or
      this.getTarget().getName().matches("%_ele_acquire")
    ) and
    this.getTarget().getLocation().getFile().getBaseName().matches("fd_pool.c") and
    not this.getLocation().getFile().getAbsolutePath().matches("%/tmpl/%")
  }

  string getPoolName() {
    result =
      this.getTarget().getName().replaceAll("_idx_acquire", "").replaceAll("_ele_acquire", "")
  }

  predicate isEleAcquire() { this.getTarget().getName().matches("%_ele_acquire") }
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
