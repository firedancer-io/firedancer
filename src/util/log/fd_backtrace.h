#ifndef HEADER_fd_src_util_log_fd_backtrace_h
#define HEADER_fd_src_util_log_fd_backtrace_h

#include "../fd_util_base.h"

/* fd_backtrace_log prints a simple backtrace to stderr. */

void
fd_backtrace_log( void ** addrs,
                  ulong   addrs_cnt );

#endif /* HEADER_fd_src_util_log_fd_backtrace_h */
