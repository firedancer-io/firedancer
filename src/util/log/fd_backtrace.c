#include "fd_backtrace.h"
#include "../fd_util_base.h"
#include "../log/fd_log.h"

#include <unistd.h>

void
fd_backtrace_log( void ** addrs,
                  ulong   addrs_cnt ) {
  for( ulong i=0UL; i<addrs_cnt; i++ ) {
    void * addr = addrs[ i ];
    fd_log_private_fprintf_0( STDERR_FILENO, "%p\n", addr );
  }
}
