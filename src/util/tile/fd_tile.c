#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>

#include "fd_tile_private.h"

int
fd_cpuset_getaffinity( ulong         pid,
                       fd_cpuset_t * mask ) {
# if defined(__linux__)
  return sched_getaffinity( (int)pid, fd_cpuset_word_cnt<<3, (cpu_set_t *)fd_type_pun( mask ) );
# else
  (void)pid; (void)mask;
  errno = ENOTSUP;
  return -1;
# endif
}

int
fd_cpuset_setaffinity( ulong               pid,
                       fd_cpuset_t const * mask ) {
# if defined(__linux__)
  return sched_setaffinity( (int)pid, fd_cpuset_word_cnt<<3, (cpu_set_t const *)fd_type_pun_const( mask ) );
# else
  (void)pid; (void)mask;
  errno = ENOTSUP;
  return -1;
# endif
}
