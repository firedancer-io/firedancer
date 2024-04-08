#ifndef HEADER_fd_src_wiredancer_wd_f1_mon_h
#define HEADER_fd_src_wiredancer_wd_f1_mon_h

// TODO remove unnecessary ones
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include "../c/wd_f1.h"
#include "../../util/fd_util_base.h"

typedef struct {
    uint64_t recv_cnt [2];
    uint64_t send_cnt;
    uint64_t cnt_replay;
    uint64_t cnt_parser;
    uint64_t cnt_x86;
    uint64_t cnt__wd;
    uint64_t rate_replay;
    uint64_t rate_parser;
    uint64_t rate_x86;
    uint64_t rate__wd;
    uint64_t sig_pass;
    uint64_t sig_fail;
    uint64_t cnt_checked;
    uint32_t running;
    uint32_t running_recv;
    uint32_t slot;
    wd_wksp_t wd;
} wd_mon_state_t;

void* mon_thread(void* arg);

/* TSC simple "calibration" method */

static inline double get_tsc_ticks_ns()
{
  struct timespec ts_start, ts_end;
  volatile long rdtsc_start = 0LL;
  volatile long rdtsc_end   = 0LL;
  volatile long i = 0;

  clock_gettime(CLOCK_MONOTONIC, &ts_start);
  rdtsc_start = fd_tickcount();
  /* Compute intensive - arbitrary count */
  for (i = 0; i < 100000000LL; i++);
  rdtsc_end = fd_tickcount();
  clock_gettime(CLOCK_MONOTONIC, &ts_end);

  static struct timespec ts_diff;
  do { /* compute the differences */
    ts_diff.tv_sec  = ts_end.tv_sec  - ts_start.tv_sec ;
    ts_diff.tv_nsec = ts_end.tv_nsec - ts_start.tv_nsec;
    if (ts_diff.tv_nsec < 0) { ts_diff.tv_sec--; ts_diff.tv_nsec += 1000000000LL; /* ns per second */}
  } while(0);
  uint64_t ns = (uint64_t)(ts_diff.tv_sec * 1000000000LL + ts_diff.tv_nsec);
  return (double)(rdtsc_end - rdtsc_start)/(double)ns;
}

#endif
