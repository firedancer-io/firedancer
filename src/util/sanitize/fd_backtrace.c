#include "fd_backtrace.h"
#include "../fd_util_base.h"

#if FD_HAS_BACKTRACE
#include "../log/fd_backtrace.h"
#endif

void
fd_backtrace_print( int fd ) {
#if FD_HAS_BACKTRACE
  fd_backtrace_log( fd );
#else
  (void)fd;
#endif
}
