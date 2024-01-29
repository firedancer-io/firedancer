#define _GNU_SOURCE
#include <sched.h>

#include "fd_cpuset.h"

int
fd_sched_getaffinity( pid_t       pid,
                      fd_cpuset_t mask[ static fd_cpuset_word_cnt ] ) {
  return sched_getaffinity( pid, fd_cpuset_word_cnt<<3, (cpu_set_t *)fd_type_pun( mask ) );
}

int
fd_sched_setaffinity( pid_t             pid,
                      fd_cpuset_t const mask[ static fd_cpuset_word_cnt ] ) {
  return sched_setaffinity( pid, fd_cpuset_word_cnt<<3, (cpu_set_t const *)fd_type_pun_const( mask ) );
}
