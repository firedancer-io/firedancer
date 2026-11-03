/**
 * @name Missing fd_rwlock Unlock
 * @description Finds functions where a fd_rwlock is returned on some
 * but not all branches. Functions that return holding the lock on
 * every path (acquire wrappers that hand the lock to their caller,
 * e.g. ones that drop a read lock to retake it as a write lock) are
 * not flagged. Currently, this query does not model the locked data
 * and has no concept of lock semantics (an fd_rwlock_unread does not
 * unlock a fd_rwlock_write). If we would ever encounter FPs related to
 * this we can later add this more precise modeling.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id asymmetric-research/missing-rwlock-unlock
 */

import cpp
import filter

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

ControlFlowNode nextNoLock(ControlFlowNode n) {
  not result instanceof LockCall and
  result = n.getASuccessor()
}

predicate noUnlock(LockCall l) { exists(ReturnStmt r | r = nextNoUnlock*(l)) }

/**
 * Holds if the function exits without holding the lock on some path,
 * i.e. the exit is reachable from an unlock without being reacquired.
 */
predicate unlockedExit(Function f) {
  exists(UnlockCall u |
    u.getEnclosingFunction() = f and
    f = nextNoLock+(u)
  )
}

from LockCall l
where
  included(l.getLocation()) and
  l.getASuccessor*() instanceof UnlockCall and
  noUnlock(l) and
  unlockedExit(l.getEnclosingFunction())
select l, "Missing unlock"
