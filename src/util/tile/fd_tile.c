#define _GNU_SOURCE
#include <sched.h>

#include "fd_tile_private.h"

volatile int fd_tile_shutdown_flag = 0;

int
fd_cpuset_getaffinity( ulong         pid,
                       fd_cpuset_t * mask ) {
  return sched_getaffinity( (int)pid, fd_cpuset_word_cnt<<3, (cpu_set_t *)fd_type_pun( mask ) );
}

int
fd_cpuset_setaffinity( ulong               pid,
                       fd_cpuset_t const * mask ) {
  return sched_setaffinity( (int)pid, fd_cpuset_word_cnt<<3, (cpu_set_t const *)fd_type_pun_const( mask ) );
}
