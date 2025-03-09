#define _GNU_SOURCE
#include "fd_sys_util.h"

#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

void __attribute__((noreturn))
fd_sys_util_exit_group( int code ) {
  syscall( SYS_exit_group, code );
  for(;;);
}

int
fd_sys_util_nanosleep( uint secs,
                       uint nanos ) {
  struct timespec ts = { .tv_sec = secs, .tv_nsec = nanos };
  struct timespec rem;
  while( FD_UNLIKELY( -1==nanosleep( &ts, &rem ) ) ) {
    if( FD_LIKELY( errno==EINTR ) ) ts = rem;
    else return -1;
  }
  return 0;
}
