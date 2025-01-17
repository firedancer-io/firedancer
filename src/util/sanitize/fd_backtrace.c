#include "fd_backtrace.h"

#include <execinfo.h>

void
fd_backtrace_print( int fd ) {
  void * bt[1024];
  int bt_size;
  bt_size = backtrace(bt, 1024);
  backtrace_symbols_fd(bt, bt_size, fd);
}
