/**
 * @name Missing fd_rwlock Unlock
 * @description Finds functions where a fd_rwlock is returned on some
 * but not all branches. Currently, this query does not model the
 * locked data and has no concept of lock semantics (an fd_rwlock_unread
 * does not unlock a fd_rwlock_write). If we would ever encounter FPs
 * related to this we can later add this more precise modeling.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/missing-rwlock-unlock
 */

import cpp

class LockCall extends FunctionCall {
  LockCall() { this.getTarget().hasName(["fd_rwlock_read", "fd_rwlock_write"]) }
}

class UnlockCall extends FunctionCall {
  UnlockCall() { this.getTarget().hasName(["fd_rwlock_unread", "fd_rwlock_unwrite"]) }
}

ControlFlowNode nextNoUnlock(ControlFlowNode n) {
  not result instanceof UnlockCall and
  result = n.getASuccessor()
}

predicate noUnlock(LockCall l) { exists(ReturnStmt r | r = nextNoUnlock*(l)) }

from LockCall l
where
  l.getASuccessor*() instanceof UnlockCall and
  noUnlock(l)
select l, "Missing unlock"
