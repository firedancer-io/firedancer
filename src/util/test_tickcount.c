#define _GNU_SOURCE
#include "fd_util.h"
#include <sched.h>
#include <time.h>

static long
monotonic_ns( void ) {
  struct timespec ts;
  FD_TEST( !clock_gettime( CLOCK_MONOTONIC_RAW, &ts ) );
  return (long)ts.tv_sec*1000000000L + (long)ts.tv_nsec;
}

int
main( int argc, char ** argv ) {
  /* fd_boot may pin this thread.  Remember the original allowed set so
     migration tests cover all accessible CPUs, not just the boot CPU. */
  cpu_set_t allowed;
  FD_TEST( !sched_getaffinity( 0, sizeof(allowed), &allowed ) );
  fd_boot( &argc, &argv );

  double rate0 = 0.;
  long prev = fd_tickcount();
  for( ulong cpu=0UL; cpu<CPU_SETSIZE; cpu++ ) {
    if( !CPU_ISSET( cpu, &allowed ) ) continue;
    cpu_set_t one;
    CPU_ZERO( &one );
    CPU_SET( cpu, &one );
    FD_TEST( !sched_setaffinity( 0, sizeof(one), &one ) );
    long tick = fd_tickcount();
    FD_TEST( tick>=prev );
    prev = tick;
    for( ulong i=0UL; i<1000000UL; i++ ) {
      tick = fd_tickcount();
      FD_TEST( tick>=prev );
      prev = tick;
    }

    long ns0 = monotonic_ns();
    long t0  = fd_tickcount();
    fd_log_sleep( 100000000L );
    long t1  = fd_tickcount();
    long ns1 = monotonic_ns();
    FD_TEST( t1>t0 && ns1>ns0 );
    double rate = (double)(t1-t0)/(double)(ns1-ns0);
    if( rate0==0. ) rate0 = rate;
    /* Generous tolerance for scheduler jitter in this portability test. */
    FD_TEST( rate>0.95*rate0 && rate<1.05*rate0 );
    FD_LOG_NOTICE(( "CPU %lu: %.6f ticks/ns", cpu, rate ));
    prev = t1;
  }

  /* Reverse direction too: a per-core offset increasing with CPU index
     could pass only the forward migration check. */
  for( ulong i=CPU_SETSIZE; i; i-- ) {
    ulong cpu = i-1UL;
    if( !CPU_ISSET( cpu, &allowed ) ) continue;
    cpu_set_t one;
    CPU_ZERO( &one );
    CPU_SET( cpu, &one );
    FD_TEST( !sched_setaffinity( 0, sizeof(one), &one ) );
    long tick = fd_tickcount();
    FD_TEST( tick>=prev );
    prev = tick;
  }

  /* Time many reads with an independent clock; do not impose a noisy
     host-dependent performance threshold on this correctness test. */
  ulong const count = 1000000UL;
  long start = monotonic_ns();
  for( ulong i=0UL; i<count; i++ ) (void)fd_tickcount();
  long tick_ns = monotonic_ns()-start;
  start = monotonic_ns();
  for( ulong i=0UL; i<count; i++ ) (void)fd_log_wallclock();
  long wall_ns = monotonic_ns()-start;
  FD_LOG_NOTICE(( "tick read %.2f ns; wallclock read %.2f ns",
                  (double)tick_ns/(double)count, (double)wall_ns/(double)count ));
  FD_TEST( !sched_setaffinity( 0, sizeof(allowed), &allowed ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
