/**
 * @name Checks for large memset operations
 * @description This query checks for calls to `memset` where the size argument is unusually large.
 * @precision high
 * @kind problem
 * @id asymmetric-research/large-memset
 * @problem.severity warning
 */

import cpp

private class MemsetCall extends Call {
  MemsetCall() {
    this.getTarget().hasGlobalName("fd_memset")
    or
    this.getTarget().hasGlobalOrStdOrBslName("memset")
  }
}

int getMaxMemsetSize() { result = 10 * 1024 * 1024 } // 10MB, adjust as needed

bindingset[size]
string asString(int size) {
  if size >= 1024 * 1024
  then result = (size / (1024 * 1024)) + " MB"
  else
    if size >= 1024
    then result = (size / 1024) + " KB"
    else result = size + " bytes"
}

from MemsetCall call, int size, int maxSize
where
  size = call.getArgument(2).getValue().toInt() and
  maxSize = getMaxMemsetSize() and
  size > maxSize
select call,
  "This call to memset has a $@ (" + asString(size) + ") that is larger than " + asString(maxSize) +
    ".", call.getArgument(2), "size argument"
